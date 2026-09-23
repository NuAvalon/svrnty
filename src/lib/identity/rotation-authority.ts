// src/lib/identity/rotation-authority.ts
//
// The openpgp-FREE rotation-authority core, split out of fingerprint.ts. fingerprint.ts imports
// `readKey` from openpgp for its armored-key / PWA identity path, so the air-gap ceremony-keygen
// (release-signing root, no browser) derives the rotation-authority commitment (nac) WITHOUT
// dragging openpgp into its bundle by importing from here. @noble-only.
//
// Byte-IDENTICAL to the original fingerprint.ts definitions (see fingerprint.ts@9904acde / @018a8136):
// same domain-separated HKDF info strings, same primitive order, same concat/hash. fingerprint.ts now
// re-exports these for backward compat — every existing importer of './fingerprint' is unaffected.
// Mirrors the fingerprint-canonical.ts extraction (same openpgp-free-leaf pattern).

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

function rotationAuthorityLeg(masterSecret: Uint8Array, epoch: number, name: string, len: number): Uint8Array {
  // noble hashes v2 types `info` as Uint8Array; this is the UTF-8 of the domain-separated info string.
  const info = utf8ToBytes(`svrnty:rotation-authority:v1:epoch-${epoch}:${name}`);
  return hkdf(sha256, masterSecret, undefined, info, len);
}

export type NextAuthorityKeypair = {
  edSecret: Uint8Array;
  edPublic: Uint8Array;
  dsaSecret: Uint8Array;
  dsaPublic: Uint8Array;
};

/**
 * Re-derive the NEXT epoch's rotation-AUTHORITY keypair from the cold seed.
 * SIGN-ONLY (ed25519 + ML-DSA-87). Used at genesis (to hash the pubs) and at rotation (to reveal).
 */
export function deriveNextAuthorityKeypair(masterSecret: Uint8Array, epoch: number): NextAuthorityKeypair {
  const edSecret = rotationAuthorityLeg(masterSecret, epoch, 'ed', 32);
  const dsaSeed = rotationAuthorityLeg(masterSecret, epoch, 'dsa', 32);
  const dsa = ml_dsa87.keygen(dsaSeed);
  return {
    edSecret,
    edPublic: ed25519.getPublicKey(edSecret),
    dsaSecret: dsa.secretKey,
    dsaPublic: dsa.publicKey,
  };
}

/**
 * Pre-commit the NEXT epoch's rotation-AUTHORITY key: SHA256(authEd ‖ authDsa), both raw sign-only pubs
 * DERIVED deterministically from masterSecret via domain-separated HKDF. Genesis calls this while
 * masterSecret is in-hand (before fill(0)). At rotation, the owner re-derives K_auth from the same
 * cold seed, reveals these two pubs (verifier checks H(reveal)==commitment), and signs the successor
 * with the matching secrets.
 */
export function deriveNextAuthorityCommitment(masterSecret: Uint8Array, epoch: number): string {
  const authEd = ed25519.getPublicKey(rotationAuthorityLeg(masterSecret, epoch, 'ed', 32));
  const authDsa = ml_dsa87.keygen(rotationAuthorityLeg(masterSecret, epoch, 'dsa', 32)).publicKey;
  return bytesToHex(sha256(concatBytes(authEd, authDsa)));
}
