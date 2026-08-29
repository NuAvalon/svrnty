// IdentitySeal — sacred geometry catalog + φ crystal + habit fold.

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
  SACRED_CATALOG,
  unicursalHexagramPaths,
} from './IdentitySeal';

const FP_A = '5408785bfc9f6fa84bb8e44c90c0c03eaaaaaaaa';
const FP_B = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

test('same fingerprint ⇒ identical crystal geometry', () => {
  assert.deepEqual(composePhiSeal(FP_A), composePhiSeal(FP_A));
});

test('different fingerprints ⇒ different crystals', () => {
  const a = composePhiSeal(FP_A);
  const b = composePhiSeal(FP_B);
  assert.notDeepEqual(a.spines, b.spines);
});

test('rings follow φ cascade R · φ⁻ⁿ', () => {
  const g = composePhiSeal(FP_A);
  assert.ok(Math.abs(g.r1 / g.R - PHI_INV) < 1e-9);
  assert.ok(Math.abs(g.r2 / g.r1 - PHI_INV) < 1e-9);
  assert.ok(Math.abs(PHI * PHI_INV - 1) < 1e-12);
});

test('fold ∈ 3–10 and matches spine count', () => {
  const g = composePhiSeal(FP_A);
  assert.ok((CRYSTAL_HABITS as readonly number[]).includes(g.fold));
  assert.equal(g.spines.length, g.fold);
  assert.equal(g.fold, foldFromFingerprint(FP_A));
});

test('sacred catalog covers every fold', () => {
  for (const h of CRYSTAL_HABITS) {
    assert.ok(SACRED_CATALOG[h].length >= 2, `fold ${h} needs options`);
  }
});

test('circle options exist on every fold; seed of life on fold 6', () => {
  for (const h of CRYSTAL_HABITS) {
    assert.ok(SACRED_CATALOG[h].some((o) => o.id === 'circle'), `fold ${h} circle`);
    assert.ok(SACRED_CATALOG[h].some((o) => o.id === 'circles'), `fold ${h} φ circles`);
  }
  assert.ok(SACRED_CATALOG[6].some((o) => o.id === 'seed'));
});

test('Crowley unicursal is a single wireframe path', () => {
  const paths = unicursalHexagramPaths(50, 50, 40, 0);
  assert.equal(paths.length, 1);
  assert.ok(paths[0].startsWith('M '));
  assert.ok(paths[0].endsWith(' Z') || paths[0].endsWith('Z'));
  // Six vertices + close ⇒ five " L " separators in the polyline
  assert.equal(paths[0].split(' L ').length, 6);
});

test('hexagonal seals include compound hexagram and unicursal options', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 120; i++) {
    const g = composePhiSeal(randomFingerprint());
    if (g.fold === 6) seen.add(g.figureId);
  }
  assert.ok(seen.has('hexagram') || seen.has('hexagram-inv'), 'expected compound hexagram');
  assert.ok(seen.has('unicursal') || seen.has('unicursal-inv'), 'expected unicursal');
});

test('inversions appear in the wild', () => {
  let found = false;
  for (let i = 0; i < 150; i++) {
    const id = composePhiSeal(randomFingerprint()).figureId;
    if (id.includes('inv')) { found = true; break; }
  }
  assert.ok(found);
});

test('lab sigil variant remains 5-fold', () => {
  assert.equal(composeSigilSeal(FP_A).fold, 5);
});

test('±1 digit changes the crystal', () => {
  const base = fingerprintHex(FP_A);
  const shifted = shiftFingerprintDigit(base, 0, 1);
  assert.notDeepEqual(composePhiSeal(base).spines, composePhiSeal(shifted).spines);
});
