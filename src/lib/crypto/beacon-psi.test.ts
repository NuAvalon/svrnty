// src/lib/crypto/beacon-psi.test.ts
// Run: npx tsx --test src/lib/crypto/beacon-psi.test.ts
//
// Proves the #588 beacon DH-PSI bond layer (beacon-psi.ts) — the v2 PIN3 SIGNAL-2 (mutual BOND):
//   • both parties derive the SAME bond M from real X25519-DH-derived secrets;
//   • a lone deposit share ≠ the bond (counterpart-blind);
//   • the bond rotates per epoch (cross-epoch unlinkable, R2);
//   • the bond is pair-specific (A-B bond ≠ A-C bond).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  deriveSharedSecret,
  bondBase,
  identityScalar,
  depositShare,
  bondToken,
  bondsMatch,
} from './beacon-psi';

function mint() {
  const sk = ed25519.utils.randomSecretKey();
  const pk = ed25519.getPublicKey(sk);
  return { sk, pk };
}

test('bond: both parties derive the SAME mutual token from real DH secrets', () => {
  const A = mint();
  const B = mint();
  const epoch = 2960;

  // Each party derives the pair-secret from THEIR side — must agree (X25519-DH symmetric).
  const sA = deriveSharedSecret(A.sk, B.pk);
  const sB = deriveSharedSecret(B.sk, A.pk);
  assert.deepEqual(sA, sB, 'pair-secret s symmetric across both sides');

  const a = identityScalar(A.sk);
  const b = identityScalar(B.sk);

  const HA = bondBase(sA, epoch);
  const HB = bondBase(sB, epoch);
  assert.ok(HA.equals(HB), 'both derive the same bond base H_G');

  const D_A = depositShare(HA, a); // A's deposit
  const D_B = depositShare(HB, b); // B's deposit

  const M_A = bondToken(D_B, a); // A computes bond from B's share + a
  const M_B = bondToken(D_A, b); // B computes bond from A's share + b
  assert.ok(bondsMatch(M_A, M_B), 'both derive the SAME bond token M = a·b·H');
});

test('bond: a lone deposit share is NOT the bond (counterpart-blind)', () => {
  const A = mint();
  const B = mint();
  const s = deriveSharedSecret(A.sk, B.pk);
  const a = identityScalar(A.sk);
  const b = identityScalar(B.sk);
  const H = bondBase(s, 2960);
  const D_A = depositShare(H, a);
  const D_B = depositShare(H, b);
  const M = bondToken(D_B, a);
  assert.ok(!bondsMatch(D_A, M), "A's own share ≠ the bond");
  assert.ok(!bondsMatch(D_B, M), "B's own share ≠ the bond");
});

test('bond: rotates per epoch (cross-epoch unlinkable)', () => {
  const A = mint();
  const B = mint();
  const s = deriveSharedSecret(A.sk, B.pk);
  const a = identityScalar(A.sk);
  const b = identityScalar(B.sk);

  const M1 = bondToken(depositShare(bondBase(s, 2960), b), a);
  const M2 = bondToken(depositShare(bondBase(s, 2961), b), a);
  assert.ok(!bondsMatch(M1, M2), 'different epoch ⇒ different bond token');
});

test('bond: pair-specific (A-B bond ≠ A-C bond)', () => {
  const A = mint();
  const B = mint();
  const C = mint();
  const epoch = 2960;
  const a = identityScalar(A.sk);
  const b = identityScalar(B.sk);
  const c = identityScalar(C.sk);

  const sAB = deriveSharedSecret(A.sk, B.pk);
  const sAC = deriveSharedSecret(A.sk, C.pk);

  const M_AB = bondToken(depositShare(bondBase(sAB, epoch), b), a);
  const M_AC = bondToken(depositShare(bondBase(sAC, epoch), c), a);
  assert.ok(!bondsMatch(M_AB, M_AC), 'bond is pair-specific');
});
