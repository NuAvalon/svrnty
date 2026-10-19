// src/lib/crypto/kdf.test.ts
// #542: deriveKeyArgon2idAsync must be a BYTE-IDENTICAL, drop-in async form of the
// sync deriveKeyArgon2id — the vault export/restore freeze fix moves the 64MB
// Argon2id off the main thread WITHOUT changing the crypto, so old .svrnty backups
// still open. In node there is no DOM Worker, so the async wrapper takes its SYNC
// FALLBACK here — which pins exactly the invariant callers depend on (async === sync
// + params validation + interop). The real off-thread WORKER path is browser-only
// and is QA'd in the PWA (Athena). Reduced params for speed; the equality holds for
// any params (both call the same noble argon2id).
//   node --import tsx --test src/lib/crypto/kdf.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  deriveKeyArgon2id,
  deriveKeyArgon2idAsync,
  aesGcmEncrypt,
  aesGcmDecrypt,
  randomBytes,
  ARGON2_MAX_MEMORY_COST,
} from './kdf.js';

const PASS = 'correct horse battery staple';
const SALT = new Uint8Array(16).fill(7);
const FAST = { time_cost: 1, memory_cost: 256, parallelism: 1 }; // reduced for test speed

test('async derivation is BYTE-IDENTICAL to the sync path (no crypto change)', async () => {
  const sync = deriveKeyArgon2id(PASS, SALT, FAST);
  const asyncKey = await deriveKeyArgon2idAsync(PASS, SALT, FAST);
  assert.equal(asyncKey.length, 32);
  assert.equal(bytesToHex(asyncKey), bytesToHex(sync)); // same key ⇒ old backups still open
});

test('async derivation is deterministic (same inputs → same key)', async () => {
  const a = await deriveKeyArgon2idAsync(PASS, SALT, FAST);
  const b = await deriveKeyArgon2idAsync(PASS, SALT, FAST);
  assert.equal(bytesToHex(a), bytesToHex(b));
});

test('interop: a key derived async decrypts ciphertext made with the sync key (and vice versa)', async () => {
  const syncKey = deriveKeyArgon2id(PASS, SALT, FAST);
  const asyncKey = await deriveKeyArgon2idAsync(PASS, SALT, FAST);
  const iv = randomBytes(12);
  const msg = new TextEncoder().encode('vault payload');
  // encrypt with the async-derived key, decrypt with the sync-derived key
  const ct = await aesGcmEncrypt(asyncKey, iv, msg);
  const pt = await aesGcmDecrypt(syncKey, iv, ct);
  assert.equal(new TextDecoder().decode(pt), 'vault payload');
});

test('async path enforces the F1 param clamp (hostile memory_cost rejected before any work)', async () => {
  await assert.rejects(
    deriveKeyArgon2idAsync(PASS, SALT, { time_cost: 1, memory_cost: ARGON2_MAX_MEMORY_COST + 1, parallelism: 1 }),
    /memory_cost .* exceeds limit/,
  );
});

test('different passphrase → different key (sanity)', async () => {
  const a = await deriveKeyArgon2idAsync(PASS, SALT, FAST);
  const b = await deriveKeyArgon2idAsync(PASS + '!', SALT, FAST);
  assert.notEqual(bytesToHex(a), bytesToHex(b));
});
