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

/** Every normalized channel a TrustEdge carries: peer_email + contact_info.{phone,emails[],handles{}}. */
export function edgeChannels(edge: ChannelSource): NormalizedChannel[] {
  const out: NormalizedChannel[] = [];
  if (edge.peer_email) out.push(normalizeChannel('email', edge.peer_email));
  const ci = edge.contact_info;
  if (ci) {
    if (ci.phone) out.push(normalizeChannel('phone', ci.phone));
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
