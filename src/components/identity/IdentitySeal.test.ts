// IdentitySeal crystal geometry — determinism + φ cascade + habit fold + digit shift.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  PHI,
  PHI_INV,
  CRYSTAL_HABITS,
  composePhiSeal,
  composeSigilSeal,
  foldFromFingerprint,
  shiftFingerprintDigit,
  fingerprintHex,
  randomFingerprint,
  unicursalHexagramPath,
} from './IdentitySeal';

const FP_A = '5408785bfc9f6fa84bb8e44c90c0c03eaaaaaaaa';
const FP_B = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

test('same fingerprint ⇒ identical crystal geometry', () => {
  const a = composePhiSeal(FP_A);
  const b = composePhiSeal(FP_A);
  assert.deepEqual(a, b);
});

test('different fingerprints ⇒ different crystals', () => {
  const a = composePhiSeal(FP_A);
  const b = composePhiSeal(FP_B);
  assert.notDeepEqual(a.spines, b.spines);
  assert.ok(a.spines.length > 0);
});

test('rings follow φ cascade R · φ⁻ⁿ', () => {
  const g = composePhiSeal(FP_A);
  assert.ok(Math.abs(g.r1 / g.R - PHI_INV) < 1e-9);
  assert.ok(Math.abs(g.r2 / g.r1 - PHI_INV) < 1e-9);
  assert.ok(Math.abs(g.r3 / g.r2 - PHI_INV) < 1e-9);
  assert.ok(Math.abs(PHI * PHI_INV - 1) < 1e-12);
});

test('fold is a habit in 3–9 and matches spine count', () => {
  const g = composePhiSeal(FP_A);
  assert.ok((CRYSTAL_HABITS as readonly number[]).includes(g.fold));
  assert.equal(g.spines.length, g.fold);
  assert.equal(g.fold, foldFromFingerprint(FP_A));
});

test('base-10 habit picker can yield every habit including 3,7,9', () => {
  const seen = new Set<number>();
  for (let i = 0; i < 400 && seen.size < CRYSTAL_HABITS.length; i++) {
    seen.add(foldFromFingerprint(randomFingerprint()));
  }
  for (const h of CRYSTAL_HABITS) {
    assert.ok(seen.has(h), `missing habit ${h}`);
  }
});

test('6-fold seals carry a unicursal hexagram path', () => {
  let found = false;
  for (let i = 0; i < 80; i++) {
    const g = composePhiSeal(randomFingerprint());
    if (g.fold === 6) {
      assert.ok(g.unicursal && g.unicursal.startsWith('M '));
      found = true;
      break;
    }
  }
  assert.ok(found, 'expected to sample a 6-fold habit');
  assert.ok(unicursalHexagramPath(50, 50, 40, 0).includes('L'));
});

test('non-6 habits omit unicursal', () => {
  for (let i = 0; i < 60; i++) {
    const g = composePhiSeal(randomFingerprint());
    if (g.fold !== 6) {
      assert.equal(g.unicursal, null);
      return;
    }
  }
});

test('lab sigil variant remains 5-fold', () => {
  assert.equal(composeSigilSeal(FP_A).fold, 5);
  assert.equal(composeSigilSeal(FP_A).blades.length, 5);
});

test('±1 digit changes the crystal', () => {
  const base = fingerprintHex(FP_A);
  const shifted = shiftFingerprintDigit(base, 0, 1);
  assert.notEqual(base, shifted);
  assert.notDeepEqual(composePhiSeal(base).spines, composePhiSeal(shifted).spines);
});
