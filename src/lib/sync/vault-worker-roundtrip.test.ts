// Task #542 — vault export/restore was freezing because packVault:365 + unpackVault:488 ran a 64 MiB
// pure-JS Argon2id (noble, sync-only) inline on the main thread. The fix moves it to a first-party
// Web Worker (argon2-async.ts / argon2-worker.ts). Flint's do-no-harm acceptance bar (recovery path):
// the fix must be BYTE-IDENTICAL to the old path so every existing .svrnty file still restores.
//
// deriveKeyArgon2idAsync's key MUST equal the sync deriveKeyArgon2id's key. In node (no Worker global)
// the async wrapper falls back to the SAME sync fn, so this asserts the wrapper is a faithful
// pass-through (byte-identical → restore-compatible). The BROWSER worker path (off-thread, no freeze)
// is Flint's live restore-integrity co-witness + Hypatia's e2e — not node-testable.
//
// Small params here (1 MiB / t=1) keep the test fast: the wrapper is param-agnostic, so byte-equality
// holds for the production 64 MiB params too.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { deriveKeyArgon2id, toBase64, type Argon2Params } from '../crypto/kdf';
import { deriveKeyArgon2idAsync } from '../crypto/argon2-async';

const SALT = new Uint8Array(16).fill(0x2a);
const FAST_PARAMS: Argon2Params = {
  algorithm: 'argon2id',
  salt: toBase64(SALT),
  time_cost: 1,
  memory_cost: 1024, // 1 MiB — fast; wrapper is param-agnostic so 64 MiB behaves the same
  parallelism: 1,
};
const PASSPHRASE = 'correct horse battery staple'; // 12+ chars

test('deriveKeyArgon2idAsync is byte-identical to sync deriveKeyArgon2id (→ old .svrnty files restore)', async () => {
  const sync = deriveKeyArgon2id(PASSPHRASE, SALT, FAST_PARAMS);
  const asy = await deriveKeyArgon2idAsync(PASSPHRASE, SALT, FAST_PARAMS);
  assert.equal(asy.length, 32, '256-bit AES key');
  assert.deepEqual([...asy], [...sync], 'async (worker/fallback) key must equal the sync key BYTE-FOR-BYTE');
});

test('a different passphrase derives a different key (sanity — not a constant)', async () => {
  const a = await deriveKeyArgon2idAsync(PASSPHRASE, SALT, FAST_PARAMS);
  const b = await deriveKeyArgon2idAsync('a totally different passphrase', SALT, FAST_PARAMS);
  assert.notDeepEqual([...a], [...b]);
});

// Flint's INDEPENDENT KDF reference vectors (KB#89821, #140321) at the PRODUCTION params
// (argon2id t=3 / m=64 MiB / p=1 / dkLen=32). deriveKeyArgon2idAsync (node fallback → the SAME
// derivation the worker runs) must reproduce them BYTE-EXACT — this turns "byte-identical by
// construction" into VERIFIED, catching any passphrase-encode / param-mapping corruption on the
// worker boundary (the exact way plumbing silently changes a derived key → permanent restore loss).
// SLOW (~12s each — 64 MiB pure-JS Argon2): a crypto co-witness gate, not a per-commit test. Flint
// independently re-runs these against the real browser worker + does the full vault artifact round-trip.
const hex = (u: Uint8Array) => [...u].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (s: string) => new Uint8Array((s.match(/../g) ?? []).map((h) => parseInt(h, 16)));
const prodParams = (salt: Uint8Array): Argon2Params => ({
  algorithm: 'argon2id',
  salt: toBase64(salt),
  time_cost: 3,
  memory_cost: 65536, // 64 MiB — the shipped params (Flint co-set; never tune down)
  parallelism: 1,
});
const FLINT_VECTORS: ReadonlyArray<readonly [string, string, string]> = [
  ['correct horse battery staple!', '000102030405060708090a0b0c0d0e0f', '3dec89261035de72dc5ea8803934bf80ef5279963c129b7fe9e4413ab3c6b150'],
  ['another-test-passphrase-123', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '58159e6a02a83ead6a24785b5e6c526453c26f87311c15968025f90bf76b7367'],
  ['abcdefghijkl', 'ffffffffffffffffffffffffffffffff', 'a5d0d19ae9afc2dc3a312d52824592cdd7cb7085a7831fb5b807e033295cc9bd'],
];
for (const [pass, saltHex, wantHex] of FLINT_VECTORS) {
  test(`Flint KDF vector reproduces byte-exact @64MiB (~12s): "${pass.slice(0, 20)}"`, async () => {
    const salt = fromHex(saltHex);
    const key = await deriveKeyArgon2idAsync(pass, salt, prodParams(salt));
    assert.equal(hex(key), wantHex, 'worker/fallback key must equal Flint independent vector byte-for-byte');
  });
}

test('vault.ts routes BOTH KDF call sites through the off-thread wrapper (never the sync one)', () => {
  const src = readFileSync(new URL('./vault.ts', import.meta.url), 'utf8');
  const asyncCalls = src.match(/deriveKeyArgon2idAsync\(/g) ?? [];
  assert.ok(asyncCalls.length >= 2, 'packVault + unpackVault must both call deriveKeyArgon2idAsync');
  // The sync main-thread call would re-freeze the tab. `\bderiveKeyArgon2id\(` matches deriveKeyArgon2id(
  // but NOT deriveKeyArgon2idAsync( (the char after `2id` is `A`, not `(`).
  assert.doesNotMatch(src, /\bderiveKeyArgon2id\(/, 'vault.ts must NOT call the sync deriveKeyArgon2id directly');
});
