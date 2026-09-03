// src/lib/contacts/import-dedup.ts
// Top-level dedup ENGINE for the IMPORT flow (Queue B 0.12).
// Wraps the dedup primitives (dedup.ts). Import-time dedup — NOT sync/merge (cross-device vault sync).
//
// The living-wins field-union (livingWinsMerge, now a primitive in dedup.ts) is the SHARED
// "living-data-wins" mechanism: the same rule powers import dedup ("imports never
// overwrite attested data") AND the live-update beat ("Bob's edit updates Alice's entry").
//
// v1 scope (demo-safe, conservative):
//   - EXACT-KEY dedup only: match iff two contacts share ≥1 normalized channel (phone E.164 /
//     folded email). Fuzzy name-matching → review is DEFERRED (over-merge is the cardinal sin).
//   - Ambiguous (>1 existing match) → review card-stack, NEVER a silent merge.
//   - SECURITY: a single-match auto-merge that
//     would ADD ≥1 net-new reachability channel to a TRUSTED-living target → route to review
//     (channel-INJECTION guard). Net-new is read from the ACTUAL livingWinsMerge survivor via
//     addsRawChannel (RAW values), so a raw-unioned UNNORMALIZABLE channel (bare national phone /
//     custom handle) can't slip past a normalized-key check. livingWinsMerge already protects
//     trust-flags + attested scalars; this closes the reachability-channel-injection vector.

import type { TrustEdge } from '@/lib/trust/types';
import { sharesChannel, livingWinsMerge, addsRawChannel, type ChannelSource } from './dedup';

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
  /**
   * Needs the user before applying: an ambiguous match (>1 existing) OR a guarded merge into
   * a trusted edge. `reason` tells the UI which copy to show — disambiguation ("which contact?") vs a
   * channel-injection security warning ("adds new reachability to a TRUSTED contact — confirm").
   */
  review: { incoming: Partial<TrustEdge>; candidates: TrustEdge[]; reason?: 'ambiguous' | 'trusted-net-new' }[];
  /** No channel match → a new (gray) contact. */
  fresh: Partial<TrustEdge>[];
}

/** A Partial import row read as a channel source (peer_email may be absent on a gray card). */
const asSource = (e: Partial<TrustEdge>): ChannelSource => ({
  peer_email: e.peer_email ?? '',
  contact_info: e.contact_info,
});

/** Trusted-living = rank 2 (dedup.ts rank()): a linked svrnty identity (fingerprint) AND trusted. */
const isTrustedLiving = (e: TrustEdge): boolean => !!e.peer_fingerprint && e.trusted;

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
      const target = matches[0];
      const survivor = livingWinsMerge(target, inc);
      // auto-merging an import into a TRUSTED-living edge UNIONs the import's
      // channels onto it (livingWinsMerge) — a channel-INJECTION vector. If the merge ADDS a reachability
      // channel to a trusted target, route to review; idempotent/no-net-new or non-trusted → auto-merge.
      // addsRawChannel reads the actual survivor's RAW channels, so unnormalizable injections can't slip past.
      if (isTrustedLiving(target) && addsRawChannel(target, survivor)) {
        plan.review.push({ incoming: inc, candidates: [target], reason: 'trusted-net-new' });
      } else {
        plan.autoMerge.push({ survivor, existing: target, incoming: inc });
      }
    } else if (matches.length > 1) {
      plan.review.push({ incoming: inc, candidates: matches, reason: 'ambiguous' });
    } else {
      plan.fresh.push(inc);
    }
  }
  return plan;
}
