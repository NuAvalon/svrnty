// src/lib/trust/beacon-confirmed.ts — #822 (a) S2b-1: which pairs this device has CONFIRMED, and the one rule that confirms a pair. Pure; storage is the store's.
//
// CONFIRMED means: a live exchange at THIS device showed that this contact's beacon key is fresh. After a lost phone the key we hold may be stale: a pair derived from a
// stale key is one whoever holds the old phone can compute, so no request may be made for it until fresh evidence arrives. The confirmed set is DEVICE-LOCAL pairing
// state: it is never exported and never restored, so a restored device starts with nothing confirmed, by construction.
//
// THE RULE (decideConfirm). Confirm only when ALL hold:
//  - the exchange was produced LIVE in this session. NO SOURCE PROVES THAT YET: the Grow-link ceremony is not bound to the session (its link is not single-use, serves the
//    same card for 7 days to anyone holding it, and carries no joiner nonce), so today NOTHING calls this rule and the confirmed set stays empty. Until a binding exists
//    (a joiner nonce the giver signs over, or an in-person short code) no request can be made for any pair. Previously, the intended source was the in-person / QR ceremony. NEVER an Import Contacts paste, a pasted card or any file: those can carry an OLD card
//    replayed from a seized device, and if its key equals the stale key we hold, keep-equal would confirm the stale key;
//  - the card carried a beacon key that passed the card check, and the intake verdict was add, backfill, or keep with the SAME key at the SAME generation
//    (not deferred, loud, none, own-key-unreadable, nor a keep that was counted as rollback or held-malformed).
// The wire has no write path to this set: an owner re-tap alone never confirms.
import type { PairConfirmedPort } from '../crypto/beacon-client';
import type { BeaconIntakeVerdict, CardBeacon, HeldBeaconKey } from './beacon-contact-key';

export interface ConfirmedEntry { generation: number }
export type BeaconConfirmed = Record<string, ConfirmedEntry>;

const PAIR_ID = /^[0-9a-f]{64}$/;
/** a bound so a damaged or hostile row cannot grow without limit */
export const MAX_CONFIRMED = 10_000;

export function isBeaconConfirmed(x: unknown): x is BeaconConfirmed {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return false;
  const entries = Object.entries(x as Record<string, unknown>);
  if (entries.length > MAX_CONFIRMED) return false;
  for (const [k, v] of entries) {
    if (!PAIR_ID.test(k)) return false;
    if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
    const e = v as Record<string, unknown>;
    if (Object.keys(e).length !== 1 || !Number.isSafeInteger(e.generation) || (e.generation as number) <= 0) return false;
  }
  return true;
}

/** A NEW map with the pair confirmed at this generation. Monotone: a lower generation never lowers a held one. The input is never mutated. */
export function withConfirmed(map: BeaconConfirmed, pairId: string, generation: number): BeaconConfirmed {
  if (!PAIR_ID.test(pairId)) throw new Error('beacon confirmed: the pair id must be 64 lowercase hex');
  if (!Number.isSafeInteger(generation) || generation <= 0) throw new Error('beacon confirmed: the generation must be a positive integer');
  const held = map[pairId];
  const next = { ...map, [pairId]: { generation: held ? Math.max(held.generation, generation) : generation } };
  if (Object.keys(next).length > MAX_CONFIRMED) throw new Error('beacon confirmed: too many pairs');
  return next;
}

/** Where the card came from. 'live-ceremony' is the ONLY source that can confirm. */
export type ConfirmSource = 'live-ceremony' | 'import';

export interface ConfirmDecision { confirm: boolean; generation?: number }

export function decideConfirm(
  verdict: BeaconIntakeVerdict,
  counted: string | undefined,
  source: ConfirmSource,
  held: HeldBeaconKey | undefined,
  card: CardBeacon,
): ConfirmDecision {
  const NO: ConfirmDecision = { confirm: false };
  if (source !== 'live-ceremony') return NO;
  const k = card.beaconKey;
  if (!k) return NO;
  if (verdict === 'add' || verdict === 'backfill') return { confirm: true, generation: k.keyGeneration };
  if (verdict === 'keep' && counted === undefined && held && held.beacon_public_key === k.publicKey && held.beacon_key_generation === k.keyGeneration) {
    return { confirm: true, generation: k.keyGeneration };
  }
  return NO;
}

/**
 * The generation of the beacon key this device HOLDS for the contact behind `pairId`, or undefined when there is no such contact or it holds no well-formed key.
 * The confirmed port asks it at every question, so a key replaced since the confirm is seen at once.
 */
export type HeldGenerationOf = (pairId: string) => Promise<number | undefined>;

/**
 * The port the client asks. A pair is confirmed only while the confirm was made for the key this device holds NOW: the stored entry's generation must equal the held key's generation.
 * A pair confirmed at generation N is therefore NOT confirmed after the held key is replaced by generation N+1 (nor after any other change of the held generation), and stays unconfirmed
 * until a live confirm records the new generation. Any doubt (a read that fails, a row that is not a valid map, no held key, a generation that is not a positive integer, a resolver that
 * throws) answers FALSE: nothing is confirmed on a guess.
 */
export function createConfirmedPort(read: () => Promise<unknown>, heldGenerationOf: HeldGenerationOf): PairConfirmedPort {
  return {
    async isConfirmed(pairId: string): Promise<boolean> {
      try {
        const m = await read();
        if (!isBeaconConfirmed(m)) return false;
        if (!Object.prototype.hasOwnProperty.call(m, pairId)) return false;
        const held = await heldGenerationOf(pairId);
        if (typeof held !== 'number' || !Number.isSafeInteger(held) || held <= 0) return false;
        return m[pairId].generation === held;
      } catch {
        return false;
      }
    },
  };
}
