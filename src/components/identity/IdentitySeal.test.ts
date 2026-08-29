// IdentitySeal — sacred geometry catalog + φ crystal + habit fold.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  PHI,
  PHI_INV,
  CRYSTAL_HABITS,
  composePhiSeal,
  composeGrowthSeal,
  composeSigilSeal,
  foldFromFingerprint,
  sacredEntryFromFingerprint,
  shiftFingerprintDigit,
  fingerprintHex,
  randomFingerprint,
  SACRED_CATALOG,
  SACRED_FLAT,
  SACRED_DEMOTED,
  starPolygonPath,
  hexagramCompoundPath,
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

test('flat pool covers every fold; no dead gon', () => {
  assert.ok(SACRED_FLAT.length >= 30);
  for (const h of CRYSTAL_HABITS) {
    assert.ok(SACRED_CATALOG[h].length >= 2, `fold ${h} needs options`);
    assert.ok(!SACRED_CATALOG[h].some((o) => (o.id as string) === 'gon'));
  }
  const folds = new Set(SACRED_FLAT.map((e) => e.fold));
  for (const h of CRYSTAL_HABITS) assert.ok(folds.has(h));
});

test('pentagram {5/2} continuous; hexagram ★ remains the fold-6 star (no Crowley unicursal)', () => {
  assert.ok(SACRED_CATALOG[5].some((o) => o.id === 'star' && o.k === 2));
  assert.ok(SACRED_CATALOG[6].some((o) => o.id === 'hexagram'));
  assert.ok(!SACRED_CATALOG[6].some((o) => (o.id as string).startsWith('unicursal')));
  const pent = starPolygonPath(50, 50, 40, 5, 2, 0);
  assert.equal(pent.split(' L ').length, 6);
  const hex = hexagramCompoundPath(50, 50, 40, 0);
  assert.ok(hex.includes('Z M'), 'compound ★ is two triangles');
});

test('flower + metatron + seed demoted from production pool', () => {
  assert.ok(!SACRED_CATALOG[6].some((o) => o.id === 'flower'));
  assert.ok(!SACRED_CATALOG[6].some((o) => o.id === 'metatron'));
  assert.ok(!SACRED_CATALOG[6].some((o) => o.id === 'seed'));
  assert.ok(SACRED_DEMOTED.some((e) => e.option.id === 'flower'));
  assert.ok(SACRED_DEMOTED.some((e) => e.option.id === 'metatron'));
  assert.ok(SACRED_DEMOTED.some((e) => e.option.id === 'seed'));
  assert.ok(!SACRED_FLAT.some((e) => e.option.id === 'flower' || e.option.id === 'metatron' || e.option.id === 'seed'));
  for (const h of [3, 5, 6, 10] as const) {
    assert.ok(SACRED_CATALOG[h].some((o) => o.id === 'circle'), `fold ${h} circle`);
    assert.ok(SACRED_CATALOG[h].some((o) => o.id === 'circles'), `fold ${h} φ circles`);
  }
});

test('flat pool produces varied figures in the wild', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 600; i++) {
    seen.add(composePhiSeal(randomFingerprint()).figureId);
  }
  assert.ok(seen.size >= 8, `expected broad figure variety, got ${seen.size}`);
  assert.ok(seen.has('star') || seen.has('hexagram'));
  assert.ok(!seen.has('flower') && !seen.has('metatron') && !seen.has('seed'));
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

test('no UI label says inverted pentagram', () => {
  for (const h of CRYSTAL_HABITS) {
    for (const o of SACRED_CATALOG[h]) {
      assert.ok(!/inverted pentagram/i.test(o.label), o.label);
    }
  }
});

test('lab sigil variant remains 5-fold', () => {
  assert.equal(composeSigilSeal(FP_A).fold, 5);
});

test('canonical orientation: spine 0 points up — no free whole-seal rotation', () => {
  for (let i = 0; i < 40; i++) {
    const g = composePhiSeal(randomFingerprint());
    const s0 = g.spines[0];
    // tip should be above center (smaller y in SVG)
    assert.ok(s0.y2 < s0.y1 - 5, 'spine 0 tip above center');
    // tip roughly on vertical axis through center
    assert.ok(Math.abs(s0.x2 - s0.x1) < 1.5, 'spine 0 near vertical');
  }
});

test('±1 digit does not yield a pure rotation twin of the same crystal', () => {
  const base = fingerprintHex(FP_A);
  const shifted = shiftFingerprintDigit(base, 7, 1);
  const a = composePhiSeal(base);
  const b = composePhiSeal(shifted);
  // If fold+figure match, dendrite/facet structure must still differ (not spin-only)
  if (a.fold === b.fold && a.figureId === b.figureId && a.R === b.R) {
    assert.notDeepEqual(a.branches, b.branches);
  }
});

test('growth seal is deterministic and spine-0 up', () => {
  assert.deepEqual(composeGrowthSeal(FP_A), composeGrowthSeal(FP_A));
  const g = composeGrowthSeal(FP_A);
  assert.ok((CRYSTAL_HABITS as readonly number[]).includes(g.fold));
  assert.equal(g.spines.length, g.fold);
  assert.ok(g.notches.length >= g.fold, 'at least one notch per spine');
  assert.ok(g.orbs.length >= g.fold + 1, 'tip orbs + core orb');
  assert.ok(g.arcs.length >= 1, 'at least one gated arc');
  assert.ok(g.spines[0].y2 < g.spines[0].y1 - 5);
  assert.ok(Math.abs(g.spines[0].x2 - g.spines[0].x1) < 1.5);
});

test('growth differs across fingerprints; no named glyph ids', () => {
  const a = composeGrowthSeal(FP_A);
  const b = composeGrowthSeal(FP_B);
  assert.notDeepEqual(a.branches, b.branches);
  assert.notDeepEqual(a.arcs, b.arcs);
  assert.equal(a.figureId, 'growth');
  for (let i = 0; i < 80; i++) {
    const id = composeGrowthSeal(randomFingerprint()).figureId;
    assert.equal(id, 'growth');
  }
});
