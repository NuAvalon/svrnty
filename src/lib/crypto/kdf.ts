// src/lib/crypto/kdf.ts
// Single passphrase key-derivation + authenticated-encryption primitive for svrnty.
//
// WHY THIS FILE EXISTS (lane 0.10 — "kill dual KDF"):
// The codebase had two divergent passphrase KDFs — Argon2id in
// `crypto/encrypted-backup.ts` (identity export) and PBKDF2-600k in
// `sync/backup.ts` (vault export). Two implementations of the same job is a
// hazard: a reviewer must audit both, and a caller can silently pick the weaker
// one. This module is the ONE derivation path. Both the identity export and the
// vault (.svrnty v3) derive keys here. `sync/backup.ts` is retired to a
// legacy-READ-only path (no new file is ever written with PBKDF2).
//
// Memory-hard Argon2id is the right defense for a human passphrase against
// offline GPU/ASIC brute force. Parameters per Flint spec v0.1.3.
//
// Co-review: Flint (crypto). Design: Athena's G3 `.svrnty` v3 (co-verified).

import { argon2id } from '@noble/hashes/argon2.js';

// ── KDF parameters (Flint spec v0.1.3) ───────────────────────────────
export const ARGON2_TIME_COST = 3; // iterations
export const ARGON2_MEMORY_COST = 65536; // 64 MiB, in KiB
export const ARGON2_PARALLELISM = 1;
export const ARGON2_KEY_LENGTH = 32; // 256-bit key for AES-256-GCM
export const SALT_LENGTH = 16; // 128-bit salt
export const IV_LENGTH = 12; // 96-bit IV for AES-GCM

// ── F1: hard ceilings for params read from an UNTRUSTED file ──────────
// The decrypt/import path reads memory_cost/time_cost/parallelism from the file
// header and runs argon2id BEFORE any auth-tag check. A crafted file with a huge
// memory_cost would OOM or hang the victim's browser — a denial-of-service on
// import, which is exactly the attacker-supplied surface. AAD does NOT fix this
// (the KDF runs first). So every decode path MUST clamp params before deriveKey.
// Ceilings == the write-side constants: we never emit anything heavier, so
// anything heavier is hostile.
export const ARGON2_MAX_TIME_COST = 4;
export const ARGON2_MAX_MEMORY_COST = 65536; // 64 MiB — refuse to allocate more
export const ARGON2_MAX_PARALLELISM = 4;

// ── F3: passphrase-strength floor for WRITE paths ─────────────────────
// Combined with Argon2id memory-hardness, a length floor materially raises the
// offline brute-force cost. Enforced on encrypt only; decrypt never rejects a
// passphrase for being short (old files must still open). 12 aligns with the
// audit floor for the identity-unlock passphrase — the vault protects the same
// private keys, so it uses the same bar (Flint rec #3, PR #2).
export const MIN_PASSPHRASE_LENGTH = 12;

// ── Types ─────────────────────────────────────────────────────────────
/** KDF descriptor stored in cleartext so any version can be decoded later. */
export interface Argon2Params {
  algorithm: 'argon2id';
  salt: string; // base64
  time_cost: number;
  memory_cost: number; // KiB
  parallelism: number;
}

// ── base64 helpers (browser-safe, no Buffer) ──────────────────────────
export function toBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ── Randomness ────────────────────────────────────────────────────────
export function randomBytes(len: number): Uint8Array {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

// ── Param construction / validation ───────────────────────────────────
export function defaultArgon2Params(salt: Uint8Array): Argon2Params {
  return {
    algorithm: 'argon2id',
    salt: toBase64(salt),
    time_cost: ARGON2_TIME_COST,
    memory_cost: ARGON2_MEMORY_COST,
    parallelism: ARGON2_PARALLELISM,
  };
}

/** F3 — reject weak passphrases on WRITE paths. */
export function assertPassphraseStrength(passphrase: string): void {
  if (!passphrase || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(
      `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`,
    );
  }
}

/** F1 — reject/clamp hostile KDF params BEFORE deriveKey on any decode path. */
export function assertParamsWithinLimits(p: {
  algorithm?: string;
  time_cost: number;
  memory_cost: number;
  parallelism: number;
}): void {
  if (p.algorithm !== undefined && p.algorithm !== 'argon2id') {
    throw new Error(`Unsupported KDF algorithm: ${p.algorithm}`);
  }
  if (
    !Number.isInteger(p.time_cost) ||
    !Number.isInteger(p.memory_cost) ||
    !Number.isInteger(p.parallelism)
  ) {
    throw new Error('KDF parameters must be integers');
  }
  if (p.time_cost < 1 || p.memory_cost < 1 || p.parallelism < 1) {
    throw new Error('KDF parameters must be positive');
  }
  if (p.time_cost > ARGON2_MAX_TIME_COST) {
    throw new Error(`KDF time_cost ${p.time_cost} exceeds limit ${ARGON2_MAX_TIME_COST}`);
  }
  if (p.memory_cost > ARGON2_MAX_MEMORY_COST) {
    throw new Error(
      `KDF memory_cost ${p.memory_cost} KiB exceeds limit ${ARGON2_MAX_MEMORY_COST} KiB`,
    );
  }
  if (p.parallelism > ARGON2_MAX_PARALLELISM) {
    throw new Error(`KDF parallelism ${p.parallelism} exceeds limit ${ARGON2_MAX_PARALLELISM}`);
  }
}

// ── Derivation ────────────────────────────────────────────────────────
/**
 * Derive a 256-bit AES key from a passphrase via Argon2id.
 * Caller MUST have validated params with assertParamsWithinLimits() first on
 * any path where the params came from an untrusted file.
 * The returned bytes are the raw key — zero them after importKey.
 */
export function deriveKeyArgon2id(
  passphrase: string,
  salt: Uint8Array,
  params: { time_cost: number; memory_cost: number; parallelism: number },
): Uint8Array {
  // Enforce F1 AT the derivation point — so no decode path can ever run
  // argon2id with unclamped, attacker-supplied params (the param-bomb is exactly
  // the class a future caller could reintroduce). Decode paths SHOULD still call
  // assertParamsWithinLimits early for a clear error, but this is the guarantee
  // it can never be skipped (Flint rec #1, PR #2). No-op on the write paths,
  // whose params are the fixed in-range constants.
  assertParamsWithinLimits(params);
  const passphraseBytes = new TextEncoder().encode(passphrase);
  return argon2id(passphraseBytes, salt, {
    t: params.time_cost,
    m: params.memory_cost,
    p: params.parallelism,
    dkLen: ARGON2_KEY_LENGTH,
  });
}

// ── Authenticated encryption (AES-256-GCM, optional AAD) ──────────────
/**
 * AES-256-GCM encrypt. If `aad` is given, the auth tag also covers it, so any
 * later tamper on the AAD bytes (e.g. a file's cleartext header) makes decrypt
 * fail. Returns ciphertext WITH the appended GCM tag.
 */
export async function aesGcmEncrypt(
  keyBytes: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);
  const algo: AesGcmParams = aad
    ? { name: 'AES-GCM', iv, additionalData: aad }
    : { name: 'AES-GCM', iv };
  const ct = await crypto.subtle.encrypt(algo, key, plaintext);
  return new Uint8Array(ct);
}

/**
 * AES-256-GCM decrypt. Throws if the tag fails (wrong passphrase, corrupted
 * ciphertext, or tampered AAD). Pass the SAME `aad` bytes used at encrypt time.
 */
export async function aesGcmDecrypt(
  keyBytes: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);
  const algo: AesGcmParams = aad
    ? { name: 'AES-GCM', iv, additionalData: aad }
    : { name: 'AES-GCM', iv };
  const pt = await crypto.subtle.decrypt(algo, key, ciphertext);
  return new Uint8Array(pt);
}
