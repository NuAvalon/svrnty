// src/components/relay/relay-holds-repair.ts
// Repair: ONE deliberate owner press lists ONE person at the relay again. Pure orchestration over two injected functions; the signed ADD itself is the existing sync module's, reached only through `reconcileAdd`.
//
//   - It adds ONLY a row the panel SHOWED (`shown`): any other fingerprint is refused before anything is read.
//   - It re-reads the book AT THE PRESS (`consentOf`): a contact blocked, removed or made private since the panel was drawn sends NOTHING and reads "gone". This is the press-time re-check the panel's warning depends on.
//   - It sends ONE add and never retries; "repaired" is returned only when the relay CONFIRMS, anything else is "failed". It never revokes and it never throws.
//   - A press while the same row's add is still in flight is "busy": one add only.
//   - The book must be WHOLE at the press (its integrity flag is ok): a book that is not whole is "damaged" and nothing is sent; a flag that cannot be READ is "unreadable" (we could not check, which is not the same as damaged). The
//     check comes before any consent is read. The panel the screen reloads afterwards shows its own damaged-list line, so "damaged" needs no second copy of it.
//   - A book that cannot be read at the press is "unreadable": nothing is sent. (The panel then shows its could-not-check line.)
// This never runs by itself: there is no timer and no caller but the Repair button. An automatic add from "allowed, not listed" could undo a block made on another device, because this device's book may not have caught up with it.
import { allowedRowShouldExist, type PeerConsent } from '@/lib/sync/allowed-sync';
import type { UnderRow } from './relay-holds-model';

export type RepairOutcome =
  | { kind: 'repaired' }
  | { kind: 'failed' }
  | { kind: 'gone' }
  | { kind: 'unreadable' }
  | { kind: 'damaged' }
  | { kind: 'refused' }
  | { kind: 'busy' };

export interface RepairDeps {
  /** is the contact book WHOLE right now (its integrity flag is ok)? Throws if the flag cannot be read. */
  bookWhole(): Promise<boolean>;
  /** the contact's consent in the book NOW (null/undefined: the contact is not in the book). Throws if the book cannot be read. */
  consentOf(fp: string): Promise<PeerConsent | null | undefined>;
  /** the signed ADD for one contact with the consent just read (true only for a confirmed one). */
  reconcileAdd(fp: string, consent: PeerConsent): Promise<boolean>;
}

const inFlight = new Set<string>();

export async function repairRow(shown: ReadonlyArray<UnderRow>, fp: string, deps: RepairDeps): Promise<RepairOutcome> {
  if (!shown.some((r) => r.fp === fp)) return { kind: 'refused' };
  if (inFlight.has(fp)) return { kind: 'busy' };
  inFlight.add(fp);
  try {
    let whole: boolean;
    try { whole = await deps.bookWhole(); } catch { return { kind: 'unreadable' }; }
    if (!whole) return { kind: 'damaged' };
    let consent: PeerConsent | null | undefined;
    try { consent = await deps.consentOf(fp); } catch { return { kind: 'unreadable' }; }
    if (!consent || !allowedRowShouldExist(consent)) return { kind: 'gone' };
    try { return (await deps.reconcileAdd(fp, consent)) === true ? { kind: 'repaired' } : { kind: 'failed' }; } catch { return { kind: 'failed' }; }
  } finally {
    inFlight.delete(fp);
  }
}
