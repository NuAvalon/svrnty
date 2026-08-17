// src/lib/contacts/import-dedup.ts
// Top-level dedup ENGINE for the IMPORT flow (Queue B 0.12 / Fable §9.1).
// Wraps Archie's primitives (dedup.ts). This is import-time dedup — NOT sync/merge
// (that's cross-device vault sync).
//
// livingWinsMerge below is the SHARED "living-data-wins" mechanism (Hypatia #115891):
// the same rule powers import dedup ("imports never overwrite attested data") AND the
// live-update beat ("Bob's edit updates Alice's entry" — attested/living wins over stale).
// Build it once, call it from both.
//
// v1 scope (demo-safe, conservative):
//   - EXACT-KEY dedup only: match iff two contacts share ≥1 normalized channel (phone E.164 /
//     folded email). Fuzzy name-matching → review is DEFERRED (over-merge is the cardinal sin).
//   - Field-union with LIVING precedence. Per-field provenance is a follow-up.
//   - Ambiguous (>1 existing match) → review card-stack, NEVER a silent merge.

import type { TrustEdge } from '@/lib/trust/types';
import { sharesChannel, type ChannelSource } from './dedup';

export interface AutoMerge {
  /** The field-union result (living wins). Applied to storage on user confirm. */
  survivor: TrustEdge;
  /** The existing living edge this incoming matched. */
  existing: TrustEdge;
  /** The imported (usually gray) contact that merged in. */
  incoming: Partial<TrustEdge>;
}

export interface DedupPlan {
  /** Single exact-key match → auto-merged (field-union, living wins). */
  autoMerge: AutoMerge[];
  /** Ambiguous: incoming matched >1 existing edge → user disambiguates in a review card-stack. */
  review: { incoming: Partial<TrustEdge>; candidates: TrustEdge[] }[];
  /** No channel match → a new (gray) contact. */
  fresh: Partial<TrustEdge>[];
}

/** A Partial import row read as a channel source (peer_email may be absent on a gray card). */
const asSource = (e: Partial<TrustEdge>): ChannelSource => ({
  peer_email: e.peer_email ?? '',
  contact_info: e.contact_info,
});

/**
 * Classify each imported contact against the existing living book.
 * Idempotent: re-importing the same card re-matches its own channel → auto-merge, never a new fresh row.
 */
export function dedupeContacts(incoming: Partial<TrustEdge>[], existing: TrustEdge[]): DedupPlan {
  const plan: DedupPlan = { autoMerge: [], review: [], fresh: [] };
  for (const inc of incoming) {
    const src = asSource(inc);
    const matches = existing.filter((e) => sharesChannel(src, e));
    if (matches.length === 1) {
      plan.autoMerge.push({ survivor: livingWinsMerge(matches[0], inc), existing: matches[0], incoming: inc });
    } else if (matches.length > 1) {
      plan.review.push({ incoming: inc, candidates: matches });
    } else {
      plan.fresh.push(inc);
    }
  }
  return plan;
}

/**
 * Field-union merge with LIVING precedence — the shared living-data-wins mechanism.
 * `living` (the existing, fingerprint-bound/attested edge) is the base: its non-empty SCALAR fields
 * are NEVER overwritten by the import. Multi-value fields (phones/emails/urls/tags/channels) are
 * UNIONed (living values kept + ordered first, incoming fills gaps). Handles: living wins per platform.
 *
 * Same fn serves the live-update beat: call livingWinsMerge(currentEdge, incomingUpdate) — attested
 * current data wins, the update fills/extends. (Rank-flip for a more-attested import of a gray edge is
 * a deferred follow-up; for a gray vCard import the existing edge is living by definition.)
 */
export function livingWinsMerge(living: TrustEdge, incoming: Partial<TrustEdge>): TrustEdge {
  const merged: TrustEdge = { ...living };
  // Scalars: keep living's non-empty value; fill from incoming only if living's is empty.
  if (!merged.peer_name && incoming.peer_name) merged.peer_name = incoming.peer_name;
  if (!merged.peer_email && incoming.peer_email) merged.peer_email = incoming.peer_email;
  if (!merged.notes && incoming.notes) merged.notes = incoming.notes;
  // Multi-value: union (living first, order-preserving, de-duplicated).
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
