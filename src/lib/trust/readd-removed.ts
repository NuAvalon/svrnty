// src/lib/trust/readd-removed.ts: taking one person OFF the owner's removed list. PURE over an injected port: no storage of its own. The storage wiring is in the identity store.
//
// Why: the removed list is append-only (every other writer is a union), so a person the owner removed and later let back in would stay on it for good, and every sealed backup would
// say "you once removed this person" about someone the owner now trusts.
//
// The rules:
//  - Nothing calls this yet. Its one caller will be the owner's own, private confirm on a contact's screen, after that contact is unblocked (the record changes first, then the drop). It is
//    NEVER part of adding a contact (a file import, a restore, a gate arrival and the manual add form all add contacts), and the manual add form cannot be the removed person at all: it
//    can only create a contact without a bound key, and a contact without a bound key has no fingerprint, so it never matches an id on this list.
//  - One compare-and-swap, the same as the append: a write that lands in between is never overwritten. An unreadable list is never overwritten: the drop refuses.
//  - Only a canonical id can be on the list, so any other id is a no-op (a legacy contact is never blocked by this).
//  - It changes the removed list and nothing else: no latch, no suppression record, nothing to the wire.
import { parseRemovedList, type SealedRead, type Update } from './suppression-restore';

export type RemovedDrop = { kind: 'write'; list: string[] } | { kind: 'noop' } | { kind: 'refuse'; why: 'unreadable' };

/** What dropping one id does to the stored list. Pure; it can run more than once (a lost compare-and-swap decides again on the newer list). */
export function planRemovedDrop(held: SealedRead<string[]>, durableId: string): RemovedDrop {
  if (parseRemovedList([durableId]) === null) return { kind: 'noop' };
  if (held.state === 'unreadable') return { kind: 'refuse', why: 'unreadable' };
  if (held.state === 'absent' || !held.value.includes(durableId)) return { kind: 'noop' };
  return { kind: 'write', list: held.value.filter((id) => id !== durableId) };
}

/**
 * Whether the owner's private contact screen shows "You removed this person before" for this contact: the contact is in the book (the caller only asks about a contact it holds) and
 * its id is on the removed list. Read only. An absent list is "no"; an UNREADABLE list is also "no" (the screen says nothing it cannot back, and the drop would refuse anyway). The list holds only canonical ids
 * (parseRemovedList), so a contact with no canonical fingerprint can never match.
 */
export function wasRemovedBefore(held: SealedRead<string[]>, durableId: string | null | undefined): boolean {
  if (!durableId || held.state !== 'ok') return false;
  return held.value.includes(durableId.trim().toLowerCase());
}

/** Drop one id atomically (decided on the list the port read, and decided again if another write landed first). */
export function dropRemoved(update: Update<string[]>, durableId: string): Promise<RemovedDrop> {
  return update<RemovedDrop>((held) => {
    const plan = planRemovedDrop(held, durableId);
    return plan.kind === 'write' ? { write: plan.list, result: plan } : { result: plan };
  });
}
