// src/lib/trust/beacon-key-intake.ts — #956 S1b: what a screen does with a 'replace' verdict, as ONE function of the ports it needs.
//
// Both intake paths (the paste/QR import and the Grow-link ceremony) call replaceContactBeaconKeyWith, so they cannot drift. It builds the secrets adapter for THIS
// pair out of the OLD key (read from the contact record the screen already holds, not from the wire's counterpartY input, which is not built yet), then runs
// replaceHeldBeaconKey, which is release-first and has no network. Every doubt is a REFUSAL, and a refusal leaves the saved key unchanged:
//   - the contact holds no well-formed key, or the new generation is not newer (the decision already guarantees it; this is the belt to its braces);
//   - the old key cannot be decoded to a curve point: the rows deposited under it cannot be named, so they cannot be planned for withdrawal;
//   - the pair id cannot be derived (a locked session), or anything below throws.
//
// This module takes everything as arguments and imports nothing that touches storage, so it can be tested with fakes. The real ports are wired in
// beacon-key-intake-real.ts.
import { createBeaconSecrets, type BeaconSecretsDeps, type SeedStore } from './beacon-secrets';
import { replaceHeldBeaconKey, type HeldKey, type KeyReplaceOutcome } from './beacon-key-replace';
import { knownBeaconOf, type HeldBeaconKey } from './beacon-contact-key';
import { isBugError } from '../crypto/beacon-release-queue';
import type { BeaconStorePort, PairConfirmedPort } from '../crypto/beacon-client';
import type { Point } from '../crypto/beacon-prover';

export interface KeyIntakePorts {
  /** the pair id of a contact, from its fingerprint; throws on a locked session */
  pairIdFor(contactFingerprint: string): Promise<string>;
  /** the validated curve point of a stored beacon public key, or null if it cannot be decoded */
  decodeKey(publicKey: string): Promise<Point | null>;
  /** this identity's beacon secret scalar; undefined = no beacon key was ever held; THROWS if a key is held but cannot be read (never "none") */
  ownSecret(): Promise<bigint | undefined>;
  seeds: SeedStore;
  store: BeaconStorePort;
  confirmed: PairConfirmedPort;
  /** the compare-and-set write of the contact's key: applies only while the contact still holds `expected`; false = it moved */
  writeKeyIf(contactId: string, expected: HeldKey, next: HeldKey): Promise<boolean>;
  now(): number;
  /** the (slot, nullifier) derivation; tests inject a cheap one, production leaves it to the secrets adapter's default */
  slotOf?: BeaconSecretsDeps['slotOf'];
  /** told when a replacement meets one of the language's own bug errors ('replace': the composer; 'replace-sweep': the sweep after the key write). Never changes an outcome. */
  onUnexpected?: (where: 'replace' | 'replace-sweep', err: unknown) => void;
}

export interface ReplaceTarget {
  /** the contact record's id and fingerprint, and the key it holds now */
  contact: { id: string; fingerprint: string } & HeldBeaconKey;
  /** the newer key the verdict carries */
  next: { publicKey: string; keyGeneration: number };
}

export async function replaceContactBeaconKeyWith(ports: KeyIntakePorts, target: ReplaceTarget): Promise<KeyReplaceOutcome> {
  try {
    const held = knownBeaconOf(target.contact);
    if (!held) return { kind: 'refused' };                               // no well-formed key is held: there is nothing to replace, and nothing to name
    if (!(target.next.keyGeneration > held.keyGeneration)) return { kind: 'refused' };
    const oldPoint = await ports.decodeKey(held.publicKey);
    if (!oldPoint) return { kind: 'refused' };                           // the old rows cannot be named, so they cannot be planned for withdrawal
    const pairId = await ports.pairIdFor(target.contact.fingerprint);
    const secrets = createBeaconSecrets({
      seeds: ports.seeds,
      secretX: ports.ownSecret,
      counterpartY: async (p) => (p === pairId ? oldPoint : undefined), // the OLD key, for THIS pair only
      now: ports.now,
      ...(ports.slotOf ? { slotOf: ports.slotOf } : {}),
    });
    return await replaceHeldBeaconKey(
      { pairId, store: ports.store, secrets, now: ports.now, confirmed: ports.confirmed, writeKey: (expected, next) => ports.writeKeyIf(target.contact.id, expected, next), onUnexpected: ports.onUnexpected },
      { publicKey: held.publicKey, generation: held.keyGeneration },
      { publicKey: target.next.publicKey, generation: target.next.keyGeneration },
    );
  } catch (e) {
    if (isBugError(e)) { try { ports.onUnexpected?.('replace', e); } catch { /* a reporter that throws changes nothing */ } }   // a refusal with no trace would hide a defect behind "could not save"
    return { kind: 'refused' };
  }
}
