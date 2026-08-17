// src/lib/crypto/hybrid-envelope-guard.test.ts
// Run: tsc->CJS then node (repo extensionless-source convention), e.g.
//   npx tsc src/lib/crypto/hybrid-envelope-guard.test.ts --module commonjs --target es2020 \
//     --moduleResolution node --esModuleInterop --skipLibCheck --outDir <out> --rootDir src
//   node <out>/lib/crypto/hybrid-envelope-guard.test.js
//
// Asserts the §6 wire-invariant predicate (Flint svrnty_hybrid_envelope_format_v1). Standalone:
// no dependency on Flint's not-yet-landed encrypt primitive — it exercises the classifier
// against synthetic §6a/§6b/§6c fixtures. The live send-path wiring plugs assertHybridOnly()
// into the real outbound on Flint's primitive ping.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyEnvelope,
  assertHybridOnly,
  NonHybridCiphertextError,
  RECOGNIZED_HYBRID_SUITES,
} from './hybrid-envelope-guard';

function validEnvelope(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    suite_id: 'svrnty-hybrid-v1-cat3',
    epk_classical: 'ZXBrX2NsYXNzaWNhbA', // non-empty
    kem_ct_pq: 'a2VtX2N0X3Bx', //           non-empty (the PQ leg)
    aead_iv: 'aXYxMjM0NTY3ODkw',
    aead_ct: 'Y2lwaGVydGV4dA', // AES-256-GCM ciphertext + tag (base64) — the only payload copy
    ...over,
  };
}

// ── PASS: well-formed HybridEnvelope ─────────────────────────────────────────
test('a well-formed cat3 HybridEnvelope classifies as hybrid-envelope', () => {
  assert.equal(classifyEnvelope(validEnvelope()), 'hybrid-envelope');
});

test('a cat5 future-epoch HybridEnvelope is still hybrid (accepted, §7)', () => {
  assert.equal(classifyEnvelope(validEnvelope({ suite_id: 'svrnty-hybrid-v1-cat5' })), 'hybrid-envelope');
});

test('a HybridEnvelope serialized as a JSON string classifies as hybrid', () => {
  assert.equal(classifyEnvelope(JSON.stringify(validEnvelope())), 'hybrid-envelope');
});

test('assertHybridOnly does not throw on a valid envelope', () => {
  assert.doesNotThrow(() => assertHybridOnly(validEnvelope()));
});

// ── FAIL §6a: plaintext JSON (the identity-exchange card must never leave in the clear) ──
test('a plaintext identity-exchange card → plaintext-json (FAIL)', () => {
  const card = { fingerprint: 'FP', display_name: 'Alice', public_key: 'PK', email: 'a@e.x' };
  assert.equal(classifyEnvelope(card), 'plaintext-json');
  assert.throws(
    () => assertHybridOnly(card),
    (e: unknown) => e instanceof NonHybridCiphertextError && e.klass === 'plaintext-json',
  );
});

// ── FAIL §6b: openpgp classical (the current exchange.ts path) ───────────────
test('an openpgp-armored message → openpgp-classical (FAIL)', () => {
  const pgp = '-----BEGIN PGP MESSAGE-----\nhQEMAxyz...\n-----END PGP MESSAGE-----';
  assert.equal(classifyEnvelope(pgp), 'openpgp-classical');
  assert.throws(
    () => assertHybridOnly(pgp, 'exchange.ts'),
    (e: unknown) => e instanceof NonHybridCiphertextError && e.klass === 'openpgp-classical',
  );
});

// ── FAIL §6c / §3: the PQ leg stripped (the footgun the format kills) ────────
test('a HybridEnvelope with EMPTY kem_ct_pq → malformed-hybrid (FAIL, PQ leg stripped)', () => {
  assert.equal(classifyEnvelope(validEnvelope({ kem_ct_pq: '' })), 'malformed-hybrid');
  assert.throws(() => assertHybridOnly(validEnvelope({ kem_ct_pq: '' })));
});

test('a HybridEnvelope MISSING kem_ct_pq entirely → malformed-hybrid (FAIL)', () => {
  const e = validEnvelope();
  delete e.kem_ct_pq;
  assert.equal(classifyEnvelope(e), 'malformed-hybrid');
});

test('an unrecognized/weak suite_id → malformed-hybrid (FAIL, downgrade attempt)', () => {
  assert.equal(classifyEnvelope(validEnvelope({ suite_id: 'weak-classical-only' })), 'malformed-hybrid');
});

test('a HybridEnvelope missing aead_ct → malformed-hybrid (FAIL, no payload)', () => {
  const e = validEnvelope();
  delete e.aead_ct;
  assert.equal(classifyEnvelope(e), 'malformed-hybrid');
});

// ── FAIL: opaque / unknown ───────────────────────────────────────────────────
test('an opaque non-JSON non-PGP string → unknown (FAIL)', () => {
  assert.equal(classifyEnvelope('rawbytes-not-json'), 'unknown');
  assert.throws(() => assertHybridOnly('rawbytes-not-json'));
});

test('a JSON array (not an object) → unknown (FAIL)', () => {
  assert.equal(classifyEnvelope([1, 2, 3]), 'unknown');
});

// ── The recognized-suite set (launch + future epoch) ─────────────────────────
test('recognized suites = cat3 (launch) + cat5 (future epoch)', () => {
  assert.deepEqual([...RECOGNIZED_HYBRID_SUITES].sort(), ['svrnty-hybrid-v1-cat3', 'svrnty-hybrid-v1-cat5']);
});
