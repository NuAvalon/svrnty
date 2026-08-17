// src/lib/contacts/dedup.ts
// Contact dedup for the living address book (Queue B lane 0.13 — Archie).
// Operates on the LIVE model: TrustEdge + contact_info (NOT the dead legacy Contact type).
// E.164 phone + conservative email normalization → dedup keys → living-wins survivor selection.
// Wires into src/lib/sync/merge.ts. Merge itself stays confirm-gated (NEVER silent — invariant B2).
// Spec: shared/outbox/archie/svrnty_queueB_0.13_dedup_and_0.1_0.2_format_v1.md Part B

import type { TrustEdge } from '@/lib/trust/types';

export interface NormalizedChannel {
  type: string;
  key: string;
  unnormalizable: boolean;
}

/** Subset of a TrustEdge that dedup reads — lets callers pass partials (imported grays). */
export type ChannelSource = Pick<TrustEdge, 'peer_email' | 'contact_info'>;

/** Deterministic + idempotent channel normalization. Conservative — never over-merges. */
export function normalizeChannel(type: string, rawValue: string | undefined): NormalizedChannel {
  const value = String(rawValue ?? '').trim();
  switch (type) {
    case 'phone': {
      const e164 = toE164(value);
      return e164 ? { type, key: e164, unnormalizable: false } : { type, key: value, unnormalizable: true };
    }
    case 'email': {
      const m = value.toLowerCase(); // lowercase + trim ONLY — no +tag/dot folding (over-merge risk, Open Q1)
      return { type, key: m, unnormalizable: !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(m) };
    }
    case 'signal':
    case 'telegram':
      return { type, key: value.toLowerCase().replace(/^@/, ''), unnormalizable: value === '' };
    case 'matrix':
      return { type, key: value.toLowerCase(), unnormalizable: !/^@[^:\s]+:[^:\s]+$/.test(value) };
    default:
      return { type, key: value, unnormalizable: true }; // unknown/custom → never a dedup key
  }
}

// Conservative E.164: only accept a value already carrying a country code (leading '+').
// Region inference for bare national numbers → libphonenumber (production upgrade); here → unnormalizable.
function toE164(v: string): string | null {
  if (!v.startsWith('+')) return null;
  const digits = v.replace(/[^\d]/g, '');
  if (digits.length < 8 || digits.length > 15) return null; // E.164 max 15 digits
  return '+' + digits;
}

/** Every normalized channel a TrustEdge carries: peer_email + contact_info.{phones[],emails[],handles{}}. */
export function edgeChannels(edge: ChannelSource): NormalizedChannel[] {
  const out: NormalizedChannel[] = [];
  if (edge.peer_email) out.push(normalizeChannel('email', edge.peer_email));
  const ci = edge.contact_info;
  if (ci) {
    for (const p of ci.phones ?? []) out.push(normalizeChannel('phone', p));
    for (const e of ci.emails ?? []) out.push(normalizeChannel('email', e));
    for (const [platform, handle] of Object.entries(ci.handles ?? {})) out.push(normalizeChannel(platform, handle));
  }
  return out;
}

/** Dedup key for a normalized channel — null for anything that must NOT form a match (garbage/unknown). */
export function dedupKey(nc: NormalizedChannel): string | null {
  return nc.unnormalizable ? null : `${nc.type}:${nc.key}`;
}

/** Match candidates iff two edges share ≥1 dedup key across any normalized channel. */
export function sharesChannel(a: ChannelSource, b: ChannelSource): boolean {
  const ka = new Set(edgeChannels(a).map(dedupKey).filter((k): k is string => k !== null));
  return edgeChannels(b).some((nc) => {
    const k = dedupKey(nc);
    return k !== null && ka.has(k);
  });
}

/**
 * Living-wins survivor selection (spec B3). Pure, deterministic, order-independent.
 *  living(trusted) > living(known) > gray(imported, no fingerprint).
 * Tie-break: more normalized channels → lexicographic fingerprint → id.
 * This picks the SURVIVOR only; the actual field-union merge is confirm-gated at the call
 * site in sync/merge.ts (invariant B2: NEVER silent merge; B3: merge is lossless).
 */
export function livingWinsSurvivor(a: TrustEdge, b: TrustEdge): TrustEdge {
  const ra = rank(a), rb = rank(b);
  if (ra !== rb) return ra > rb ? a : b;
  const ca = countChannels(a), cb = countChannels(b);
  if (ca !== cb) return ca > cb ? a : b;
  const fa = a.peer_fingerprint || '', fb = b.peer_fingerprint || '';
  if (fa !== fb) return fa < fb ? a : b;
  return a.id <= b.id ? a : b;
}

function rank(e: TrustEdge): number {
  const hasIdentity = !!e.peer_fingerprint && e.peer_fingerprint.length > 0;
  if (!hasIdentity) return 0; // gray import (no linked svrnty identity yet)
  return e.trusted ? 2 : 1;   // trusted living > known living
}

function countChannels(e: TrustEdge): number {
  return edgeChannels(e).filter((c) => !c.unnormalizable).length;
}

// ─── Cluster detection (9.1 engine — Archie #115797 rulings + Fable §9.1) ─────────────
// The step between normalize (above) and the field-union merge (confirm-gated in sync/merge.ts):
// group the address book into dup-clusters so the merge has something to operate on.

/**
 * A group of edges that resolve to the same person, with the survivor pre-selected.
 *  - `exact`: members share ≥1 NORMALIZED channel (phone/email/handle). High-confidence dup →
 *    auto-applied-but-SHOWN (Archie #115797: satisfies B2's "never HIDDEN loss" without a
 *    per-merge confirm). `fuzzy` (name-similarity, no shared channel) is a later pass and is
 *    proposed-awaiting-confirm — not produced here.
 * Carries ALL `members` so the downstream field-union merge stays lossless (B3), and `sharedKeys`
 * so the UI can show WHY the cluster formed (per-field provenance / the "shown" in auto-but-shown).
 */
export interface DedupCluster {
  members: TrustEdge[];   // ≥2 edges, transitively channel-linked
  survivor: TrustEdge;    // livingWinsSurvivor folded across all members (spec B3)
  matchType: 'exact';
  sharedKeys: string[];   // dedup keys present on ≥2 members = the reason they clustered (sorted)
}

/**
 * Cluster edges into exact-match dup groups by TRANSITIVE shared channel (connected components:
 * A~B and B~C ⇒ {A,B,C}, even when A and C share no channel directly). Pure, deterministic, and
 * order-independent; returns ONLY multi-member clusters (singletons are not merges), ordered by
 * survivor id. Unnormalizable channels never bind a cluster (dedupKey → null), so a shared "" /
 * garbage value can't collapse two strangers.
 *
 * Complexity: O(total channels) via a key→edges bucket + union-find, not O(n²) pairwise
 * `sharesChannel`. Does NOT mutate or merge fields — that is confirm-gated in sync/merge.ts (B2).
 */
export function clusterByExactChannel(edges: TrustEdge[]): DedupCluster[] {
  const n = edges.length;
  const parent = Array.from({ length: n }, (_, i) => i);
  const find = (x: number): number => {
    let r = x;
    while (parent[r] !== r) r = parent[r];
    while (parent[x] !== r) { const nx = parent[x]; parent[x] = r; x = nx; } // path compression
    return r;
  };
  // Root = smallest index in the component → deterministic, order-independent.
  const union = (a: number, b: number): void => {
    const ra = find(a), rb = find(b);
    if (ra !== rb) parent[Math.max(ra, rb)] = Math.min(ra, rb);
  };

  // Bucket by dedup key; union every edge that shares a key with an earlier one.
  const keysOf: string[][] = new Array(n);
  const firstForKey = new Map<string, number>();
  for (let i = 0; i < n; i++) {
    const keys = edgeChannels(edges[i]).map(dedupKey).filter((k): k is string => k !== null);
    keysOf[i] = keys;
    for (const k of keys) {
      const first = firstForKey.get(k);
      if (first === undefined) firstForKey.set(k, i);
      else union(first, i);
    }
  }

  // Group indices by component root.
  const groups = new Map<number, number[]>();
  for (let i = 0; i < n; i++) {
    const r = find(i);
    const g = groups.get(r);
    if (g) g.push(i); else groups.set(r, [i]);
  }

  const clusters: DedupCluster[] = [];
  for (const idxs of groups.values()) {
    if (idxs.length < 2) continue; // singleton = no merge
    const members = idxs.map((i) => edges[i]);
    const survivor = members.reduce((acc, e) => livingWinsSurvivor(acc, e));
    const keyMembers = new Map<string, number>();
    for (const i of idxs) for (const k of new Set(keysOf[i])) keyMembers.set(k, (keyMembers.get(k) ?? 0) + 1);
    const sharedKeys = [...keyMembers.entries()].filter(([, c]) => c >= 2).map(([k]) => k).sort();
    clusters.push({ members, survivor, matchType: 'exact', sharedKeys });
  }
  clusters.sort((a, b) => (a.survivor.id < b.survivor.id ? -1 : a.survivor.id > b.survivor.id ? 1 : 0));
  return clusters;
}

// ─── Field-union merge primitive (9.1 — moved here from import-dedup.ts in the re-route) ──────
// livingWinsMerge is the shared field-union: BOTH the import path (Apollo, pairwise) and the cluster
// path (multi-member, via foldLivingWins) fold IDENTICALLY (Hypatia build-once #115891). Living/attested
// scalars are never overwritten; multi-value fields (phones/emails/urls/tags/channels) are UNIONed
// (lossless, B3). Now a dedup PRIMITIVE living with livingWinsSurvivor/foldLivingWins — import-dedup
// imports it one-directionally, resolving the former dedup↔import-dedup circular import.

/**
 * Field-union merge with LIVING precedence. `living` (the existing, attested/fingerprint-bound edge)
 * is the base: its non-empty SCALAR fields are never overwritten by `incoming`. Multi-value fields are
 * UNIONed (living first, order-preserving, de-duplicated); handles win per-platform for the living side.
 * `incoming` may be a Partial<TrustEdge> (a gray import that isn't a full edge).
 */
export function livingWinsMerge(living: TrustEdge, incoming: Partial<TrustEdge>): TrustEdge {
  const merged: TrustEdge = { ...living };
  if (!merged.peer_name && incoming.peer_name) merged.peer_name = incoming.peer_name;
  if (!merged.peer_email && incoming.peer_email) merged.peer_email = incoming.peer_email;
  if (!merged.notes && incoming.notes) merged.notes = incoming.notes;
  merged.tags = unionArr(merged.tags, incoming.tags);
  merged.connection_channels = unionArr(merged.connection_channels, incoming.connection_channels);
  merged.contact_info = {
    ...merged.contact_info,
    phones: unionArr(merged.contact_info?.phones, incoming.contact_info?.phones),
    emails: unionArr(merged.contact_info?.emails, incoming.contact_info?.emails),
    urls: unionArr(merged.contact_info?.urls, incoming.contact_info?.urls),
    handles: { ...(incoming.contact_info?.handles ?? {}), ...(merged.contact_info?.handles ?? {}) },
  };
  return merged;
}

/** Order-preserving de-duplicated union of two string lists (skips empties). Living (a) first. */
function unionArr(a: string[] | undefined, b: string[] | undefined): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const v of [...(a ?? []), ...(b ?? [])]) {
    if (v && !seen.has(v)) { seen.add(v); out.push(v); }
  }
  return out;
}

/**
 * Fold same-person edges into ONE merged edge. Composition ORDER matters (Archie #115913):
 * rank-SELECT the base FIRST, THEN union the others into it — NOT a naive reduce(livingWinsMerge),
 * which would let reduce-order pick the scalar base instead of the rank-winner (the subtle bug).
 *   (1) livingWinsSurvivor selects the base by rank (trusted>known>gray, then channels/fp/id).
 *   (2) livingWinsMerge unions every other member's multi-value fields into the base; the base's
 *       non-empty SCALARS are never overwritten (attested/living data wins).
 * → rank-winner's scalars win + ALL members' phones/emails/urls/tags/handles UNIONed (lossless, B3).
 * Pure + order-independent (livingWinsSurvivor is a total order). One member → returned as-is.
 */
export function foldLivingWins(members: TrustEdge[]): TrustEdge {
  if (members.length === 0) throw new Error('foldLivingWins: empty member set');
  const base = members.reduce(livingWinsSurvivor);
  return members.filter((m) => m !== base).reduce<TrustEdge>((acc, m) => livingWinsMerge(acc, m), base);
}

/** Merge a DedupCluster into its single surviving edge — the field-union its detection deferred (B3). */
export function mergeCluster(cluster: DedupCluster): TrustEdge {
  return foldLivingWins(cluster.members);
}
