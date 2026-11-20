// src/lib/crypto/owner-authority-commitment.ts
/**
 * The owner-authority commitment: the one 64-hex value a card pins for the master-derived key that signs guardian sets and relay moves.
 *
 *   commitment = hex( SHA-256( LP("svrnty-owner-authority-v1") || LP(ed25519 public key) || LP(ML-DSA-87 public key) ) )
 *
 * It is DELIBERATELY not the raw SHA-256 of the two keys: the rotation commitment (deriveNextAuthorityCommitment) is that raw hash, and the two
 * must never be confusable, because a domain tag on a signature cannot say WHICH key signed, only the pin can. One helper, so the pointer
 * verifier and (later) the card builder compute exactly the same bytes. Pure: no I/O, no clock, no randomness, no secrets.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { lpBin, lpStr } from './lp-tlv';

export const OWNER_AUTHORITY_LABEL = 'svrnty-owner-authority-v1';
export const OWNER_AUTHORITY_ED_LEN = 32;
export const OWNER_AUTHORITY_DSA_LEN = 2592;

export function ownerAuthorityCommitment(edPublic: Uint8Array, dsaPublic: Uint8Array): string {
  if (!(edPublic instanceof Uint8Array) || edPublic.length !== OWNER_AUTHORITY_ED_LEN) throw new Error('owner authority: bad Ed25519 key length');
  if (!(dsaPublic instanceof Uint8Array) || dsaPublic.length !== OWNER_AUTHORITY_DSA_LEN) throw new Error('owner authority: bad ML-DSA-87 key length');
  const a = lpStr(OWNER_AUTHORITY_LABEL), b = lpBin(edPublic), c = lpBin(dsaPublic);
  const msg = new Uint8Array(a.length + b.length + c.length);
  msg.set(a, 0); msg.set(b, a.length); msg.set(c, a.length + b.length);
  return bytesToHex(sha256(msg));
}
