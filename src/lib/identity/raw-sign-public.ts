// src/lib/identity/raw-sign-public.ts
/**
 * A contact's Ed25519 signing key, taken from the OpenPGP public key the book stores for them, and ONLY if that key is the one their fingerprint
 * commits to. Used to derive the pairwise secret with a contact (deriveSharedSecret(ownerSeed, thisKey)); the secret is only as good as the key it is
 * derived from, so the key is bound to the fingerprint here, in the one place that reads it.
 *
 *   signPubForContact(contact) -> the 32 bytes, or null
 *
 * It takes the contact RECORD the caller already holds (the one the "is this sender in the book" step returned), not a fingerprint to look up again:
 * a second read could see a key that was rotated in between, and a MAC checked against a key the decision never saw would prove the wrong thing.
 *
 * What it demands, in order. Anything else is null, and null means "no way to verify", never "guess":
 *   1. the stored fingerprint is exactly canonical: 64 lowercase hex characters. fingerprintMatchesKey also accepts a prefix of 16 to 64 hex characters
 *      and folds case and punctuation, so the exact form is checked FIRST; this path must not inherit that looseness. (Do not "simplify" this away:
 *      that matcher is lenient on purpose, for a claim a person typed, and a pairwise secret derived from a key that merely matched a prefix would
 *      let a good MAC "prove" the wrong sender.)
 *   2. fingerprintMatchesKey (the book's own check, imported, not copied) says the armored key and the contact's two post-quantum public keys hash to
 *      that fingerprint.
 *   3. the PRIMARY key packet is an Ed25519 key. Never a subkey, even an Ed25519 one: an RSA or other-curve primary with an Ed25519 subkey is null.
 *   4. its point is a real, torsion-free, non-small-order Ed25519 point.
 *
 * A svrnty identity's primary key is openpgp ecc 'ed25519' (algo 22, eddsaLegacy): publicParams.Q is 33 bytes with the 0x40 native-point prefix. It is
 * the same key as raw-sign.ts's extractRawSign(...).signPub, so the pairwise secret both sides compute is the same.
 */
import { enums, readKey } from 'openpgp';
import { ed25519 } from '@noble/curves/ed25519.js';
import { fingerprintMatchesKey } from './fingerprint';

export interface ContactKeyMaterial {
  fingerprint: string;
  public_key: string;
  pq_kem_public_key?: string;
  pq_sig_public_key?: string;
}

const CANONICAL_FP = /^[0-9a-f]{64}$/;
// The public-key algorithm id openpgp reports for the key packet (a number): EdDSA legacy (22, what a svrnty identity is) or the newer Ed25519 (27).
const ED25519_ALGOS = new Set<number>([enums.publicKey.eddsaLegacy, enums.publicKey.ed25519]);

const strip0x40 = (q: Uint8Array): Uint8Array => (q.length === 33 && q[0] === 0x40 ? q.slice(1) : q);

/** True for a real Ed25519 point of prime order: not the identity, not any small-order point, no torsion component. */
export function isUsableEd25519Point(raw: Uint8Array): boolean {
  if (!(raw instanceof Uint8Array) || raw.length !== 32) return false;
  try {
    const p = ed25519.Point.fromBytes(raw);
    return !p.isSmallOrder() && p.isTorsionFree();
  } catch {
    return false; // not a point at all
  }
}

/**
 * The PRIMARY key packet's Ed25519 point, with nothing checked against any fingerprint. Exported for its own tests only; every caller goes through
 * signPubForContact (a guard pins that no other file imports this).
 */
export async function primaryEd25519PointOf(armored: string): Promise<Uint8Array | null> {
  if (typeof armored !== 'string' || armored.length === 0) return null;
  try {
    const key = await readKey({ armoredKey: armored });
    const kp = key.keyPacket as unknown as { algorithm?: number; publicParams?: { A?: Uint8Array; Q?: Uint8Array } };
    if (typeof kp.algorithm !== 'number' || !ED25519_ALGOS.has(kp.algorithm)) return null;
    const point = kp.publicParams?.A ?? kp.publicParams?.Q;
    if (!(point instanceof Uint8Array)) return null;
    const raw = strip0x40(point);
    return raw.length === 32 && isUsableEd25519Point(raw) ? raw.slice() : null;
  } catch {
    return null;
  }
}

export async function signPubForContact(contact: ContactKeyMaterial): Promise<Uint8Array | null> {
  if (contact === null || typeof contact !== 'object') return null;
  if (typeof contact.fingerprint !== 'string' || !CANONICAL_FP.test(contact.fingerprint)) return null;
  if (typeof contact.public_key !== 'string' || contact.public_key.length === 0) return null;
  let bound: boolean;
  try {
    bound = await fingerprintMatchesKey(contact.fingerprint, contact.public_key, {
      kem_public_key: contact.pq_kem_public_key,
      sig_public_key: contact.pq_sig_public_key,
    });
  } catch {
    return null;
  }
  if (bound !== true) return null;
  return primaryEd25519PointOf(contact.public_key);
}
