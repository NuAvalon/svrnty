// src/lib/trust/psi-epoch-delivery.ts
/**
 * What the receive path does with a sealed epoch note, as ONE pure decision, in the order that matters. The decision table is ruled; this is it
 * written down so that the order cannot drift:
 *
 *   1. receive switch (F1) OFF          -> 'benign-ack'. Nothing else is looked at: no book lookup, no MAC, no parse of the note.
 *   2. claimed sender not in the book   -> 'unverified'. The same path as any unverified frame: counted, no fingerprint kept, and NEVER the
 *                                          "not in your contacts" record (anyone could raise that notice by naming a fingerprint).
 *   3. in the book, blocked             -> 'blocked-drop'. Acked, no record, nothing replays on unblock. No pairwise secret is derived and no MAC
 *                                          is checked for a blocked contact.
 *   4. in the book, MAC does not verify -> 'bad-mac'. A record WITHOUT the fingerprint.
 *   5. in the book, MAC verifies        -> 'adopt'. The note goes to the epoch book.
 *
 * `inBook`, `blocked` and `macOk` are thunks so that a step that is not reached never runs: the pairwise-secret derivation and the MAC are only
 * paid for, and only exposed, at step 4.
 */
export type EpochDeliveryOutcome = 'benign-ack' | 'unverified' | 'blocked-drop' | 'bad-mac' | 'adopt';

export interface EpochDeliveryInputs {
  receiveOn: boolean;
  inBook: () => boolean;
  blocked: () => boolean;
  macOk: () => boolean;
}

export function epochDeliveryOutcome(i: EpochDeliveryInputs): EpochDeliveryOutcome {
  if (i.receiveOn !== true) return 'benign-ack';
  if (!i.inBook()) return 'unverified';
  if (i.blocked()) return 'blocked-drop';
  return i.macOk() ? 'adopt' : 'bad-mac';
}
