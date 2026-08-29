// IdentitySeal φ geometry — determinism + golden-ratio cascade.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PHI, PHI_INV, composePhiSeal } from '../../components/identity/IdentitySeal';

const FP_A = '5408785bfc9f6fa84bb8e44c90c0c03eaaaaaaaa';
const FP_B = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

test('same fingerprint ⇒ identical seal geometry', () => {
  const a = composePhiSeal(FP_A);
  const b = composePhiSeal(FP_A);
  assert.deepEqual(a, b);
});

test('different fingerprints ⇒ different seals', () => {
  const a = composePhiSeal(FP_A);
  const b = composePhiSeal(FP_B);
  assert.notDeepEqual(a.blades, b.blades);
  assert.notEqual(a.chords.length, 0);
});

test('rings follow φ cascade R · φ⁻ⁿ', () => {
  const g = composePhiSeal(FP_A);
  assert.ok(Math.abs(g.r1 / g.R - PHI_INV) < 1e-9);
  assert.ok(Math.abs(g.r2 / g.r1 - PHI_INV) < 1e-9);
  assert.ok(Math.abs(g.r3 / g.r2 - PHI_INV) < 1e-9);
  assert.ok(Math.abs(PHI * PHI_INV - 1) < 1e-12);
});

test('five angular blades (pentagonal / φ symmetry)', () => {
  assert.equal(composePhiSeal(FP_A).blades.length, 5);
});
