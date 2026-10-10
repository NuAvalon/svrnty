// src/lib/trust/mutual-trust-sync.hfp.test.ts
// PSI hash-to-point regression guard (B-3) — the TS twin of the Python vector assert.
// Locks hashFingerprintToPoint() to the ONE canonical H(fp) so the TS phone client and the
// Python client-kit can never silently re-diverge (the B-3 bug: divergent H(fp) → cross-impl
// PSI intersection ALWAYS empty, silently). A permanent CI assert beats a one-time re-derivation.
//
// Single source of truth for the vector: svrnty_psi_hfp_testvector.py
// (+ its Python-side twin infra/satellite/client-kit/test_psi_hfp_vector.py). Constants hard-coded
// here per that file's VECTOR export ("import or hard-code these") — TS repo can't import the .py.
//
// Run: npx tsx --test src/lib/trust/mutual-trust-sync.hfp.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hashFingerprintToPoint } from './mutual-trust-sync';

// ── LOCKED canonical vector (single source of truth = the Python file above) ──
const FP_PINNED      = 'd7f541228e72b7e7214d37560bba52c426707122ec09f6e82bcd491a4131bbdb'; // 64 lc hex
const EXPECTED_H_HEX = '593f2af22eddc0c20cd83e8b14f406f66933bade3b0a176fdb7528756bcb7aa9'; // canonical H(fp)
const OLD_BROKEN_HEX = 'bad4e078c0d3c166bdb3f950b3503d9763985ad9235cb59dc83d9e5f41430e40'; // pre-fix B-3 (must NOT recur)

// CONDITION 1 (vector file): H(fp) MUST equal the canonical constant, byte-for-byte.
test('B-3 guard: hashFingerprintToPoint(FP_PINNED) == canonical (byte-matches Python client-kit)', () => {
  const got = bytesToHex(hashFingerprintToPoint(FP_PINNED));
  assert.equal(got, EXPECTED_H_HEX, 'H(fp) DRIFT — TS diverged from the locked canonical vector');
  assert.notEqual(got, OLD_BROKEN_HEX, 'REGRESSED to the old-broken B-3 H(fp)');
});

// CONDITION 2 (vector file): dropping the point-clamp is safe ONLY because getSharedSecret
// rejects an all-zero (low-order) result — the orchestrator must treat that as "no match", never
// return 32 zero bytes silently. Assert x25519.getSharedSecret REJECTS each known low-order u.
const LOW_ORDER_U = [
  '0000000000000000000000000000000000000000000000000000000000000000', // 0 (order 1)
  '0100000000000000000000000000000000000000000000000000000000000000', // 1
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800', // order-8
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157', // order-8
];
test('low-order guard: getSharedSecret rejects low-order u (never returns all-zero silently)', () => {
  const sk = new Uint8Array(32).fill(7); // any scalar; noble clamps internally
  for (const uHex of LOW_ORDER_U) {
    const u = hexToBytes(uHex);
    assert.throws(
      () => x25519.getSharedSecret(sk, u),
      `low-order u ${uHex.slice(0, 8)}… must be rejected, not silently accepted as all-zero`,
    );
  }
});
