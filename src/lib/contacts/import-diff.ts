// src/lib/contacts/import-diff.ts
// Per-field provenance for the 0.12 import merge preview.
// Turns "N merge into existing" into a real DIFF: what channel MATCHED (why the two clustered) and
// what channels the merge would ADD to the target — so a channel injected onto a TRUSTED contact is
// VISIBLE, not hidden behind a count (MEDIUM trust-injection).
//
// Truthfulness is the whole point. `added` is computed as (survivor − target) on RAW channel values,
// off livingWinsMerge's OWN output — because livingWinsMerge unions channels by raw value (unionArr),
// NOT by normalized dedup key. An UNNORMALIZABLE injected channel (a bare national phone "555-1234",
// a custom handle) still lands in the survivor even though normalizeChannel drops it. Diffing the
// actual merge output (not the dedup keys) guarantees the preview matches what is actually written —
// otherwise an unnormalizable injection would be silent in the UI while still polluting the edge.
//
// Pure + read-only. Reused by BOTH the auto-merge rows and the review-candidate rows in
// ImportContactsDialog, and independent of the DedupPlan item shape (it operates on edges), so it does
// not collide with the (A) routing changes in import-dedup.ts.

import type { TrustEdge } from '@/lib/trust/types';
import { edgeChannels, dedupKey, livingWinsMerge } from './dedup';

/** One channel, for display: type ('phone' | 'email' | 'url' | 'signal' | 'telegram' | ...) + its value. */
export interface ChannelChange {
  type: string;
  value: string;
}

export interface MergeProvenance {
  /** Normalized channels present on BOTH target and incoming = why they matched (deduped, sorted). */
  matchedOn: ChannelChange[];
  /** Raw channels the merge would ADD to the target (survivor − target). The injection surface. */
  added: ChannelChange[];
}

/**
 * Every raw reachable channel an edge/partial carries, as {type,value} — mirrors exactly the fields
 * livingWinsMerge unions (peer_email + contact_info.phones/emails/urls/handles). RAW, not normalized:
 * this is the surface that actually gets written, so the diff must read it verbatim.
 */
function rawChannels(e: Partial<TrustEdge>): ChannelChange[] {
  const out: ChannelChange[] = [];
  if (e.peer_email) out.push({ type: 'email', value: e.peer_email });
  const ci = e.contact_info;
  if (ci) {
    for (const p of ci.phones ?? []) if (p) out.push({ type: 'phone', value: p });
    for (const em of ci.emails ?? []) if (em) out.push({ type: 'email', value: em });
    for (const u of ci.urls ?? []) if (u) out.push({ type: 'url', value: u });
    for (const [platform, h] of Object.entries(ci.handles ?? {})) if (h) out.push({ type: platform, value: h });
  }
  return out;
}

const chanId = (c: ChannelChange): string => `${c.type}\u0000${c.value}`;

/**
 * Per-field provenance for merging `incoming` into `target` (living wins).
 *  - matchedOn: the normalized dedup keys shared by both sides (the reason they clustered).
 *  - added: the raw channels newly present in the survivor vs the target — exactly what
 *    livingWinsMerge would write that isn't already there. Deterministic; order follows the survivor.
 * `target` is the existing (living) edge; `incoming` may be a gray Partial.
 */
export function mergeProvenance(target: TrustEdge, incoming: Partial<TrustEdge>): MergeProvenance {
  // matchedOn: normalized channels on BOTH sides (why they clustered). asSource shim mirrors import-dedup.
  const incSource = { peer_email: incoming.peer_email ?? '', contact_info: incoming.contact_info };
  const targetKeys = new Set(
    edgeChannels(target).map(dedupKey).filter((k): k is string => k !== null),
  );
  const matchedSeen = new Set<string>();
  const matchedOn: ChannelChange[] = [];
  for (const nc of edgeChannels(incSource)) {
    const k = dedupKey(nc);
    if (k !== null && targetKeys.has(k) && !matchedSeen.has(k)) {
      matchedSeen.add(k);
      matchedOn.push({ type: nc.type, value: nc.key });
    }
  }
  matchedOn.sort((a, b) => (chanId(a) < chanId(b) ? -1 : chanId(a) > chanId(b) ? 1 : 0));

  // added: raw channels in the survivor the target didn't already have — truthful to livingWinsMerge.
  const survivor = livingWinsMerge(target, incoming);
  const had = new Set(rawChannels(target).map(chanId));
  const addedSeen = new Set<string>();
  const added: ChannelChange[] = [];
  for (const c of rawChannels(survivor)) {
    const id = chanId(c);
    if (!had.has(id) && !addedSeen.has(id)) {
      addedSeen.add(id);
      added.push(c);
    }
  }

  return { matchedOn, added };
}
