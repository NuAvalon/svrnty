// IdentitySeal crystal geometry — determinism + φ cascade + digit shift.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  PHI,
  PHI_INV,
  composePhiSeal,
  composeSigilSeal,
  shiftFingerprintDigit,
  fingerprintHex,
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

test('six crystal spines (hexagonal / snowflake habit)', () => {
  const g = composePhiSeal(FP_A);
  assert.equal(g.fold, 6);
  assert.equal(g.spines.length, 6);
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
