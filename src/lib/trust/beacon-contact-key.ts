// src/lib/trust/beacon-contact-key.ts — #822 (a) S2a: what to do with the beacon key a contact's signed card carries (pure; storage and screens are the callers').
//
// classifyImportedCard has already done the checking: d.beaconKey is non-null ONLY under a valid signature, for a key that passes checkBeaconPublicKey and the
// generation rules, and d.beaconKeyDropped says why a present key was dropped. This module decides what the caller does with that, in ONE place, so the two
// intake paths (the paste/QR import and the Grow-link ceremony) cannot drift.
//
// Rules:
//  - Stored for EVERY contact the card is valid for, whatever their trust level (a stored key enables nothing by itself).
//  - A held key is NEVER replaced here. A valid card with a higher generation is 'deferred' (counted, nothing written): replacing a key must first plan and
//    queue the withdraw of the rows deposited under the old key while the old key can still name them, and that release-first path is a later slice.
//  - The same generation with a different key is 'loud': nothing changes, and the caller shows ONE fixed sentence that carries no key and no generation.
//  - If this device's OWN beacon key cannot be read, the card's key is dropped (the reflection check cannot run): the contact is still added, and a later
//    re-share fills the key in. No "pending, unchecked" key is ever stored.
import type { BeaconKeyRead } from '../identity/client-store';
import type { BeaconKeyRecord } from '../identity/beacon-key-record';

export interface HeldBeaconKey { beacon_public_key?: string; beacon_key_generation?: number }
export interface CardBeacon {
  beaconKey: { publicKey: string; keyGeneration: number } | null;
  beaconKeyDropped?: string;
}

export type BeaconIntakeVerdict = 'add' | 'backfill' | 'keep' | 'deferred' | 'loud' | 'none';
export interface BeaconIntake {
  verdict: BeaconIntakeVerdict;
  /** the fields to write on the contact: non-empty ONLY for 'add' and 'backfill' */
  fields: { beacon_public_key?: string; beacon_key_generation?: number };
  /** a fixed word counting why a present key was not stored, or undefined */
  counted?: string;
}

const NONE: BeaconIntake = { verdict: 'none', fields: {} };

/** What the classifier needs about this device's own key: the key to refuse to reflect, or "unreadable". */
export type OwnBeacon = { state: 'readable'; publicKey: string | undefined } | { state: 'unreadable' };

/** Reads this device's own beacon public key with the STRICT reader (never mints). 'none' = no key was ever held, so there is nothing a card could reflect. */
export async function ownBeaconFrom(
  read: () => Promise<BeaconKeyRead>,
  publicKeyOf: (rec: BeaconKeyRecord) => Promise<string>,
): Promise<OwnBeacon> {
  let r: BeaconKeyRead;
  try { r = await read(); } catch { return { state: 'unreadable' }; }
  if (r.state === 'none') return { state: 'readable', publicKey: undefined };
  if (r.state !== 'held') return { state: 'unreadable' };
  try { return { state: 'readable', publicKey: await publicKeyOf(r.record) }; } catch { return { state: 'unreadable' }; }
}

/** The held key as the classifier's knownBeacon option, or undefined. */
export function knownBeaconOf(existing: HeldBeaconKey | undefined): { publicKey: string; keyGeneration: number } | undefined {
  if (!existing || typeof existing.beacon_public_key !== 'string' || typeof existing.beacon_key_generation !== 'number') return undefined;
  return { publicKey: existing.beacon_public_key, keyGeneration: existing.beacon_key_generation };
}

export function decideBeaconIntake(existing: HeldBeaconKey | undefined, card: CardBeacon, own: OwnBeacon): BeaconIntake {
  if (own.state === 'unreadable') return card.beaconKey || card.beaconKeyDropped ? { verdict: 'none', fields: {}, counted: 'own-key-unreadable' } : NONE;
  const held = knownBeaconOf(existing);
  const k = card.beaconKey;
  if (!k) {
    if (card.beaconKeyDropped === 'conflict') return { verdict: 'loud', fields: {}, counted: 'conflict' };
    if (card.beaconKeyDropped) return { verdict: held ? 'keep' : 'none', fields: {}, counted: card.beaconKeyDropped };
    return NONE; // the card carried no beacon key
  }
  if (!held) return { verdict: existing ? 'backfill' : 'add', fields: { beacon_public_key: k.publicKey, beacon_key_generation: k.keyGeneration } };
  if (k.keyGeneration > held.keyGeneration) return { verdict: 'deferred', fields: {}, counted: 'newer-generation-deferred' };
  if (k.keyGeneration === held.keyGeneration && k.publicKey === held.publicKey) return { verdict: 'keep', fields: {} };
  // the classifier drops these two before they get here; refuse them anyway so a classifier change cannot turn them into a write
  if (k.keyGeneration === held.keyGeneration) return { verdict: 'loud', fields: {}, counted: 'conflict' };
  return { verdict: 'keep', fields: {}, counted: 'rollback' };
}
