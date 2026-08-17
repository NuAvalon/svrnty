// src/lib/contacts/import-dedup.ts
// Top-level dedup ENGINE for the IMPORT flow (Queue B 0.12 / Fable §9.1).
// Wraps the dedup primitives (dedup.ts). Import-time dedup — NOT sync/merge (cross-device vault sync).
//
// The living-wins field-union (livingWinsMerge, now a primitive in dedup.ts) is the SHARED
// "living-data-wins" mechanism (Hypatia #115891): the same rule powers import dedup ("imports never
// overwrite attested data") AND the live-update beat ("Bob's edit updates Alice's entry").
//
// v1 scope (demo-safe, conservative):
//   - EXACT-KEY dedup only: match iff two contacts share ≥1 normalized channel (phone E.164 /
//     folded email). Fuzzy name-matching → review is DEFERRED (over-merge is the cardinal sin).
//   - Ambiguous (>1 existing match) → review card-stack, NEVER a silent merge.

import type { TrustEdge } from '@/lib/trust/types';
import { sharesChannel, livingWinsMerge, type ChannelSource } from './dedup';

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
