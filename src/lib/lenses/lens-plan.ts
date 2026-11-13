// src/lib/lenses/lens-plan.ts
/**
 * Lenses v1.3 — the Revise-view planning logic (contract R3). PURE: given the owner-card bag, the
 * grants book, and a proposed reassignment, say what it would expose — so the view can confirm
 * EVERY widening PER RECIPIENT before anything is sent. A quick-select, a "select all", or a group
 * selection cannot bypass it: the plan is computed per recipient and the confirm list is a per-
 * recipient structure — there is no batch-confirm shape in this module by construction.
 *
 * WIDENING = the proposed lens exposes a method the recipient has never been sent NOR confirmed to
 * receive — keyed by the owner's METHOD ID, never the wire slot (R3a): two lenses each holding an
 * unlabelled phone with different values are different METHODS, so moving a recipient between
 * them is a widening and asks first. The SENT-SET baseline, not the current face: a method added
 * to the lens but not yet confirmed has never reached them, so moving lenses does not launder it
 * into "already theirs". A method whose VALUE changes inside a kept id is an update, not a
 * widening — the recipient was already given that method (R6: they keep what they have; updates
 * flow). For a recipient with NO record the sent set is empty, so every method a plan would send
 * is a widening.
 */

import type { OwnerCardBag, OwnerLens } from '../../components/identity/owner-card';
import { lensForSend, methodsForSend, type LensSendMethod } from './lens-send';
import { lensSentKeys, recordLensKeys, setRecipientLens, type LensGrantBook } from './lens-grants';

export interface LensReassignPlan {
  fingerprint: string;
  /** The lens id the recipient would move to. */
  toLensId: string | null;
  /** Methods the new face would expose that they were never sent or confirmed — the widening set
   *  (R3/R3a: keyed by owner method id, so a slot-colliding move still asks). */
  added: LensSendMethod[];
  /** Methods they currently receive that the new face would not carry — the narrowing set (R6 copy). */
  removed: LensSendMethod[];
  /** True when added.length > 0 — this change MUST be confirmed per recipient before send. */
  widening: boolean;
}

/** What one recipient's reassignment would change. Pure. */
export function planLensReassign(
  bag: OwnerCardBag,
  book: LensGrantBook,
  recipientFingerprint: string,
  toLensId: string | null,
): LensReassignPlan {
  const grantedLens = lensForSend(bag, book, recipientFingerprint); // null on no record / deleted lens
  const toLens =
    toLensId === null ? null : bag.lenses.find((l) => l.id === toLensId) ?? null;
  const sent = lensSentKeys(book, recipientFingerprint);
  // The flowing set: what the granted lens carries AND they were actually sent. A lens method never
  // sent (pending confirm) is not "theirs", and a sent method dropped from the lens already stopped.
  const flowing = methodsForSend(bag, grantedLens).filter((m) => sent.has(m.id));
  const to = methodsForSend(bag, toLens);
  const toIds = new Set(to.map((m) => m.id));
  const added = to.filter((m) => !sent.has(m.id));
  const removed = flowing.filter((m) => !toIds.has(m.id));
  return {
    fingerprint: recipientFingerprint,
    toLensId,
    added,
    removed,
    widening: added.length > 0,
  };
}

/**
 * The confirms a batch of reassignments requires: the plans that WIDEN, one per recipient — the
 * view must get an explicit per-recipient confirm for each before anything sends. A batch is
 * sendable without confirms only when nothing widens (pure narrowing/same-face moves).
 */
export function plansNeedingConfirm(plans: LensReassignPlan[]): LensReassignPlan[] {
  return plans.filter((p) => p.widening);
}

/**
 * Commit ONE recipient's confirmed plan: record the new lens assignment AND union the confirmed
 * widening keys into their sent set — so the next send may carry exactly what the owner approved
 * (a narrowing commit records nothing new; the already-given keys stay, R6). The caller persists.
 */
export function commitReassignPlan(book: LensGrantBook, plan: LensReassignPlan): LensGrantBook {
  let next = setRecipientLens(book, plan.fingerprint, plan.toLensId);
  if (plan.added.length) next = recordLensKeys(next, plan.fingerprint, plan.added.map((m) => m.id));
  return next;
}

/** Resolve the OwnerLens a plan names (display helper for the view). */
export function lensById(bag: OwnerCardBag, id: string | null): OwnerLens | null {
  return id === null ? null : bag.lenses.find((l) => l.id === id) ?? null;
}
