// src/lib/contacts/import-apply.ts
// The confirm→apply step of the 0.12 import flow. Consumes a DedupPlan (from dedupeContacts)
// + the user's review choices → concrete storage operations (adds/updates).
// TrustEdge-level; the UI converts each op to a ContactRecord at the addContact/updateContact call.
//
// CONFIRM-GATE (Archie #115904, invariant B2): this applies a CONFIRMED plan. It runs ONLY after
// the user has SEEN the autoMerge set + resolved the review card-stack. A review row with no explicit
// 'merge' choice FALLS BACK to a fresh contact — never a silent merge of an ambiguous row.

import type { TrustEdge } from '@/lib/trust/types';
import type { DedupPlan } from './import-dedup';
import { livingWinsMerge } from './import-dedup';

/** The user's decision for one ambiguous (review) row: merge into a chosen candidate, or keep as new. */
export type ReviewChoice =
  | { action: 'merge'; candidateId: string }
  | { action: 'skip' };

export interface ImportOps {
  /** New (gray) contacts → addContact(). */
  adds: Partial<TrustEdge>[];
  /** Existing edges → updateContact(id, survivor) — the living-wins field-union result. */
  updates: { id: string; survivor: TrustEdge }[];
}

/**
 * Turn a CONFIRMED DedupPlan into storage ops.
 *  - autoMerge → update (existing.id → survivor)
 *  - fresh     → add
 *  - review[i] → choices[i]: 'merge' into the chosen candidate (update), else 'skip'/absent/invalid → add as fresh
 * `choices` is index-aligned with plan.review. Missing/invalid/skip defaults to fresh — the fail-safe
 * that keeps the never-silent-merge invariant: an ambiguous row is never merged without an explicit pick.
 */
export function applyImportPlan(plan: DedupPlan, choices: ReviewChoice[] = []): ImportOps {
  const ops: ImportOps = { adds: [], updates: [] };

  for (const am of plan.autoMerge) {
    ops.updates.push({ id: am.existing.id, survivor: am.survivor });
  }
  for (const f of plan.fresh) {
    ops.adds.push(f);
  }
  plan.review.forEach((row, i) => {
    const choice = choices[i];
    if (choice && choice.action === 'merge') {
      const target = row.candidates.find((c) => c.id === choice.candidateId);
      if (target) {
        ops.updates.push({ id: target.id, survivor: livingWinsMerge(target, row.incoming) });
        return;
      }
      // invalid candidateId → fall through to fresh (never guess which candidate to merge into)
    }
    ops.adds.push(row.incoming); // skip / absent / invalid → keep as a new gray contact
  });

  return ops;
}
