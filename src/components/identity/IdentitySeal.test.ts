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
  sacredEntryFromFingerprint,
  shiftFingerprintDigit,
  fingerprintHex,
  randomFingerprint,
  SACRED_CATALOG,
  SACRED_FLAT,
  unicursalHexagramPaths,
  unicursalClassicPaths,
  unicursalPentagramPaths,
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

test('fold ∈ 3–10 and matches spine count + flat entry', () => {
  const g = composePhiSeal(FP_A);
  const entry = sacredEntryFromFingerprint(FP_A);
  assert.ok((CRYSTAL_HABITS as readonly number[]).includes(g.fold));
  assert.equal(g.spines.length, g.fold);
  assert.equal(g.fold, foldFromFingerprint(FP_A));
  assert.equal(g.fold, entry.fold);
  assert.equal(g.figureId, entry.option.id);
});

test('flat pool covers every fold; no dead gon; equal entry odds basis', () => {
  assert.ok(SACRED_FLAT.length >= 40);
  for (const h of CRYSTAL_HABITS) {
    assert.ok(SACRED_CATALOG[h].length >= 2, `fold ${h} needs options`);
    assert.ok(!SACRED_CATALOG[h].some((o) => (o.id as string) === 'gon'));
  }
  const folds = new Set(SACRED_FLAT.map((e) => e.fold));
  for (const h of CRYSTAL_HABITS) assert.ok(folds.has(h));
});

test('unicursal pentagram + hexagram both in catalog', () => {
  assert.ok(SACRED_CATALOG[5].some((o) => o.id === 'unicursal-pent'));
  assert.ok(SACRED_CATALOG[5].some((o) => o.id === 'unicursal-pent-inv'));
  assert.ok(SACRED_CATALOG[6].some((o) => o.id === 'unicursal'));
  assert.ok(SACRED_CATALOG[6].some((o) => o.id === 'unicursal-inv'));
  const pent = unicursalPentagramPaths(50, 50, 40, 0);
  assert.equal(pent.length, 1);
  assert.equal(pent[0].split(' L ').length, 6);
});

test('flower + metatron on fold 6; circles on selected folds', () => {
  assert.ok(SACRED_CATALOG[6].some((o) => o.id === 'flower'));
  assert.ok(SACRED_CATALOG[6].some((o) => o.id === 'metatron'));
  assert.ok(SACRED_CATALOG[6].some((o) => o.id === 'seed'));
  for (const h of [3, 5, 6, 10] as const) {
    assert.ok(SACRED_CATALOG[h].some((o) => o.id === 'circle'), `fold ${h} circle`);
    assert.ok(SACRED_CATALOG[h].some((o) => o.id === 'circles'), `fold ${h} φ circles`);
  }
});

test('Crowley unicursal is a single √3 wireframe path', () => {
  const paths = unicursalHexagramPaths(50, 50, 40, 0);
  assert.equal(paths.length, 1);
  assert.equal(unicursalClassicPaths(50, 50, 40, 0)[0], paths[0]);
  assert.equal(paths[0].split(' L ').length, 6);
});

test('flat pool produces varied figures in the wild', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 600; i++) {
    seen.add(composePhiSeal(randomFingerprint()).figureId);
  }
  assert.ok(seen.size >= 12, `expected broad figure variety, got ${seen.size}`);
  assert.ok(
    [...seen].some((id) => id.includes('unicursal')),
    'expected unicursal family'
  );
});

test('inversions appear in the wild', () => {
  let found = false;
  for (let i = 0; i < 200; i++) {
    if (composePhiSeal(randomFingerprint()).figureId.includes('inv')) {
      found = true;
      break;
    }
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
