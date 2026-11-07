// src/lib/trust/psi-epoch-receive.ts
/**
 * What the receive path does with the plaintext of a sealed package, from "is this an epoch note?" to "adopted". Everything that touches the
 * outside world (the book, the pairwise secret, the clock, the store write) is injected, so this is testable with fakes and imports nothing from
 * the store at runtime. The decisions are the ruled table in psi-epoch-delivery, and the layout is psi-epoch-sealed.
 *
 * It never names the epoch field: the held epoch record arrives as an argument of the adoption's decision, and the contact book
 * lookup returns only what this needs (id, fingerprint, blocked).
 */
import type { ContactRecord } from '../identity/client-store';
import { epochDeliveryOutcome } from './psi-epoch-delivery';
import { openEpochNote, type OpenedEpochNote } from './psi-epoch-note';
import { applyEpochNote, maxEpochFor, restoreEpochRecord, serializeEpochRecord, type ApplyOutcome } from './psi-epoch-book';
import { claimedFpOf, dispatchSealed, epochWireOf } from './psi-epoch-sealed';

/** The holder's tick is its own clock in 5-minute units (the know-sync period). A clock that goes back makes it go back, which drops `prev`. */
export const PSI_TICK_MINUTES = 5;

/**
 * What the book lookup returns for a claimed sender. `ref` is whatever the caller needs to carry from the lookup to the pairwise-secret step (the book
 * record the lookup returned): it travels WITH the contact this decision saw, so the secret is derived from that record and never from a later read, a
 * second lookup, or state shared with another note handled at the same time.
 */
export interface EpochContact<R = unknown> {
  id: string;
  /** The contact's stored fingerprint. It must equal the claimed one exactly, or the contact is not the sender. */
  fingerprint: string;
  /**
   * True when the contact is not admitted for inbound traffic (a blocked contact, by either flag). It is the book's admit check, so it also fails closed
   * for any other state that check refuses: read it as "not admitted", not literally as "blocked".
   */
  blocked: boolean;
  ref: R;
}

export interface EpochReceiveDeps<R = unknown> {
  /** F1. Only exactly true switches the path on. */
  receiveOn: boolean;
  /** Our own canonical 64-hex fingerprint. */
  ownerFp: string;
  /** The local book, by the claimed fingerprint. Not a network fetch. */
  findContact: (fp: string) => Promise<EpochContact<R> | null>;
  /** The pairwise secret with THAT contact (the object findContact returned for this note), or null if it cannot be derived (no usable key). */
  pairSecretFor: (contact: EpochContact<R>) => Promise<Uint8Array | null>;
  /** The holder's clock in whole minutes, read once per accepted note. */
  nowMinutes: () => number;
  /** The store's writer of the epoch record: the only one there is. It runs the decision on the HELD record and never on a blocked contact. */
  adopt: (
    contactId: string,
    decide: (heldEpoch: string | null, contact: ContactRecord) => string | null,
  ) => Promise<{ applied: boolean }>;
}

export type EpochReceiveResult =
  | { kind: 'not-epoch' } //      not this seam's package: the caller keeps its other paths
  | { kind: 'benign-ack' } //     F1 off: acked, nothing parsed or stored, no record
  | { kind: 'unverified' } //     malformed, unknown sender, or no way to verify: counted, no fingerprint kept
  | { kind: 'blocked-drop' } //   a blocked contact: acked, no record, nothing replays
  | { kind: 'bad-mac' } //        a record WITHOUT the fingerprint
  | { kind: 'adopted' }
  | { kind: 'already-held' } //   a duplicate or an older epoch: nothing to do
  | { kind: 'conflict' } //       the same epoch with different bytes: dropped
  | { kind: 'out-of-range' } //   malformed fields, or an epoch above what this clock allows: dropped
  | { kind: 'retry' }; //         the store could not take the write now: leave it for a later poll

export async function receiveEpochNote<R>(plain: Uint8Array, deps: EpochReceiveDeps<R>): Promise<EpochReceiveResult> {
  const dispatch = dispatchSealed(plain);
  if (dispatch === 'other') return { kind: 'not-epoch' };
  // F1 off reads the length and two bytes, and nothing more: no parse, no MAC, no lookup. This covers a malformed one too.
  if (deps.receiveOn !== true) return { kind: 'benign-ack' };
  if (dispatch === 'malformed') return { kind: 'unverified' };

  const fp = claimedFpOf(plain);
  const wire = epochWireOf(plain);
  let contact: EpochContact<R> | null = null;
  let opened: Extract<OpenedEpochNote, { ok: true }> | null = null;
  let cannotVerify = false;

  const outcome = await epochDeliveryOutcome({
    receiveOn: true,
    inBook: async () => {
      const c = await deps.findContact(fp);
      // EXACT equality with the stored canonical fingerprint: a store that matches loosely (a prefix, a respelling) does not make a sender.
      contact = c !== null && c.fingerprint === fp ? c : null;
      return contact !== null;
    },
    blocked: () => (contact as EpochContact<R> | null)?.blocked === true,
    macOk: async () => {
      const sPair = await deps.pairSecretFor(contact as unknown as EpochContact<R>);
      if (sPair === null) {
        cannotVerify = true;
        return false;
      }
      let r: OpenedEpochNote;
      try {
        r = openEpochNote(wire, { sPair, fpSender: fp, fpReceiver: deps.ownerFp });
      } catch {
        cannotVerify = true; // a context that cannot be formed (a bad own fingerprint, a bad secret) verifies nothing
        return false;
      }
      if (!r.ok) return false;
      opened = r;
      return true;
    },
  });

  if (outcome === 'unverified') return { kind: 'unverified' };
  if (outcome === 'blocked-drop') return { kind: 'blocked-drop' };
  if (outcome === 'bad-mac') return cannotVerify ? { kind: 'unverified' } : { kind: 'bad-mac' };
  if (outcome !== 'adopt' || contact === null || opened === null) return { kind: 'unverified' }; // unreachable by construction; fails closed

  const note = opened as Extract<OpenedEpochNote, { ok: true }>;
  const now = deps.nowMinutes(); // read once: it feeds the bound and the tick
  const tick = Math.floor(now / PSI_TICK_MINUTES);
  const bound = maxEpochFor(now);
  const state: { decided: boolean; outcome: ApplyOutcome } = { decided: false, outcome: 'invalid' };
  let result: { applied: boolean };
  try {
    result = await deps.adopt((contact as EpochContact<R>).id, (held) => {
      state.decided = true; // the decision can run more than once (a retry on a newer record): the last run is the one that counts
      const record = held === null ? null : restoreEpochRecord(held);
      const r = applyEpochNote(record, { epoch: note.epoch, know: note.know, trust: note.trust }, tick, bound);
      state.outcome = r.outcome;
      return r.outcome === 'adopted' && r.record !== null ? serializeEpochRecord(r.record) : null;
    });
  } catch {
    return { kind: 'retry' };
  }
  // The write never asked us: the contact was blocked (or gone) between the lookup and the write.
  if (!state.decided) return { kind: 'blocked-drop' };
  if (state.outcome === 'adopted') return result.applied ? { kind: 'adopted' } : { kind: 'retry' };
  if (state.outcome === 'duplicate' || state.outcome === 'stale') return { kind: 'already-held' };
  if (state.outcome === 'conflict') return { kind: 'conflict' };
  return { kind: 'out-of-range' };
}
