// src/lib/crypto/node-zero-2fa.ts
// Two-factor front-door for the Node Zero forever-key: masterSecret = scrypt(seed, password).
//
// ── WHY ── Peter #143240 · Archie BUILD-GO #143272 · Flint reqs #143258 ──
//   The b-MINIMAL model backed up ONE secret (masterSecret → seed phrase); a found seed phrase alone
//   re-materialized the entire forever-key. Peter asked for TWO factors — a seed phrase AND "a spell"
//   (password), BOTH required. This module is that front-door: it turns (seed, password) into the 32B
//   masterSecret that deriveNodeZero() then consumes UNCHANGED. Everything below masterSecret (identity
//   legs, canonical fingerprint, rotation-authority nac) is byte-identical to the non-2FA model — the
//   ONLY new crypto for the forever-key is this one memory-hard KDF.
//
// ── FROZEN forever (v1) ── these bytes are part of forever-key recovery for ALL TIME. GATED on Flint's
//   independent byte-confirm before the real mint. Do not edit without re-minting the identity.
//     scheme        = "svrnty:node-zero-2fa-scrypt:v1"
//     KDF           = scrypt (N=2^18, r=8, p=1, dkLen=32)     — @noble/hashes, memory-hard (~256 MB)
//     input         = lpBin(seed) ‖ lpBin(utf8(NFKD(password)))   — length-prefixed, injective
//     salt          = utf8(SALT_DOMAIN) ‖ salt16              — domain-separated + unique random 16B
//     SALT_DOMAIN   = "svrnty:node-zero-2fa:v1:"
//     normalization = NFKD (BIP39 passphrase convention — DR reproduces across input methods)
//
//   N-choice (Flint's non-blocking note 1, resolved by measurement): 2^18 is 2× the N≥2^17 floor's
//   brute-force wall against a weak memorized password, while its ~256MB working set (measured RSS
//   ~338MB) keeps DR recoverable on constrained/future air-gap hardware. 2^19 (~512MB working set,
//   measured RSS ~759MB) was REJECTED: a forever-key's DR must run on modest hardware for decades, and
//   759MB risks OOM on a small live-USB — do-no-harm availability outweighs the marginal extra margin.
//   ~16.5s/call at 2^18 is negligible for once-mint + rare non-interactive DR.
//
// ── SECURITY (Flint reqs 1 & 6) ── The password is the low-entropy factor. Feeding BOTH factors into
//   ONE memory-hard scrypt means a seed-thief (holds the seed phrase; salt+params are public) pays a
//   FULL scrypt evaluation (~256 MB, ~16s) PER password guess — the offline-brute-force wall. A
//   password-thief is stopped by the seed's 32B entropy regardless of KDF cost. The SEALED password
//   backup (not a memorized string) is the real second factor; a memorized "spell" is low-entropy —
//   Hypatia's mental-model flag. scrypt is already in-tree ⇒ the audited mint surface is unchanged
//   (vs Argon2id, a new dependency needing its own audit).
//
// @noble-only (no openpgp): safe for the air-gap keygen bundle. lpBin is Flint's byte-pinned shared
// framing helper (#141596) from lp-tlv.ts — reused, never re-inlined (his guard 1).

import { scrypt } from '@noble/hashes/scrypt.js';
import { utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { lpBin } from './lp-tlv';

/** FROZEN v1 two-factor scheme constants — recovering Node Zero REQUIRES these exact values. */
export const NODE_ZERO_2FA = {
  scheme: 'svrnty:node-zero-2fa-scrypt:v1',
  kdf: 'scrypt',
  N: 2 ** 18, // 262144 — memory-hard cost (~256MB working set); 2× the N≥2^17 floor (Flint req 1),
  //             chosen over 2^19 to keep DR available on constrained air-gap hardware (measured tradeoff).
  r: 8,
  p: 1,
  dkLen: 32,
  saltDomain: 'svrnty:node-zero-2fa:v1:',
  saltBytes: 16,
  normalization: 'NFKD' as const,
  inputEncoding: 'lpBin(seed)||lpBin(utf8(NFKD(password)))',
} as const;

export interface ScryptParams { N: number; r: number; p: number; dkLen: number }

/** The frozen scrypt params, recorded in the genesis attestation for DR determinism (Flint req 2,3). */
export const FROZEN_SCRYPT_PARAMS: ScryptParams = {
  N: NODE_ZERO_2FA.N, r: NODE_ZERO_2FA.r, p: NODE_ZERO_2FA.p, dkLen: NODE_ZERO_2FA.dkLen,
};

/**
 * Derive the 32B Node Zero masterSecret from the two required factors.
 *
 * Deterministic: identical (seed, password, salt, params) ⇒ identical masterSecret ⇒ identical
 * forever-key. This is the DR re-materialization contract — the seed phrase + the sealed password +
 * the (public) salt & params recorded at genesis reconstruct the exact minted identity, and NOTHING
 * ELSE does (wrong password ⇒ different masterSecret ⇒ different fingerprint ⇒ the mint's fp-assert
 * refuses to write; found-seed-alone is insufficient).
 *
 * @param seed     32B high-entropy factor (backed up as the seed phrase)
 * @param password operator "spell" (sealed independently) — NFKD-normalized then utf8-encoded here
 * @param salt     16B non-secret random (recorded in the genesis attestation)
 * @param params   scrypt params (recorded in the genesis attestation; defaults to FROZEN_SCRYPT_PARAMS)
 */
export function deriveMasterSecret2FA(
  seed: Uint8Array,
  password: string,
  salt: Uint8Array,
  params: ScryptParams = FROZEN_SCRYPT_PARAMS,
): Uint8Array {
  if (seed.length !== 32) throw new Error(`2FA seed must be 32B, got ${seed.length}B`);
  if (salt.length !== NODE_ZERO_2FA.saltBytes) {
    throw new Error(`2FA salt must be ${NODE_ZERO_2FA.saltBytes}B, got ${salt.length}B`);
  }
  // NFKD first (BIP39 convention) so a spell typed on a different machine/keyboard reproduces the
  // exact bytes — a silent normalization mismatch would be a catastrophic, un-debuggable DR failure.
  const pw = password.normalize('NFKD');
  const pwBytes = utf8ToBytes(pw);
  if (pwBytes.length === 0) throw new Error('2FA password must be non-empty');

  const input = concatBytes(lpBin(seed), lpBin(pwBytes));
  const scryptSalt = concatBytes(utf8ToBytes(NODE_ZERO_2FA.saltDomain), salt);
  return scrypt(input, scryptSalt, { N: params.N, r: params.r, p: params.p, dkLen: params.dkLen });
}

/** Generate a fresh 16B non-secret salt (recorded in the genesis attestation). */
export function generate2FASalt(): Uint8Array {
  const s = new Uint8Array(NODE_ZERO_2FA.saltBytes);
  crypto.getRandomValues(s);
  return s;
}
