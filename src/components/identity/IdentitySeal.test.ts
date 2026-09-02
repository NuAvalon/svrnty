// IdentitySeal — sacred geometry catalog + φ crystal + habit fold.

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  PHI,
  PHI_INV,
  CRYSTAL_HABITS,
  composePhiSeal,
  composeOrganicSeal,
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

test('seal is case-invariant — same key, upper vs lower fingerprint ⇒ identical seal', () => {
  // Regression: seed-phrase restore uppercased the fingerprint while creation stores
  // lowercase; every seal seeds from fnv(fp), which used to be case-sensitive, so a
  // recovered identity appeared to change its glyph. The seal must be a function of
  // the KEY, not its string case.
  const lower = FP_A;
  const upper = FP_A.toUpperCase();
  assert.deepEqual(composePhiSeal(upper), composePhiSeal(lower));
  assert.deepEqual(composeGrowthSeal(upper), composeGrowthSeal(lower));
  assert.deepEqual(composeSigilSeal(upper), composeSigilSeal(lower));
  assert.deepEqual(composeOrganicSeal(upper), composeOrganicSeal(lower));
  assert.equal(foldFromFingerprint(upper), foldFromFingerprint(lower));
  // and formatting-insensitive (spaced/colon fingerprints render the same seal)
  const spaced = FP_A.replace(/(....)/g, '$1 ').trim();
  assert.deepEqual(composePhiSeal(spaced), composePhiSeal(lower));
});

test('rings follow φ cascade R · φ⁻ⁿ', () => {
  const g = composePhiSeal(FP_A);
  assert.ok(Math.abs(g.r1 / g.R - PHI_INV) < 1e-9);
  assert.ok(Math.abs(g.r2 / g.r1 - PHI_INV) < 1e-9);
  assert.ok(Math.abs(PHI * PHI_INV - 1) < 1e-12);
});

test('φ droplets: five soft rings with micro aberrations', () => {
  const g = composePhiSeal(FP_A);
  assert.equal(g.rings.length, 5);
  // Each ring near its φ station (aberration ≤ ~1.2% outer … ~2.4% core)
  const stations = [g.R, g.r1, g.r2, g.r3, g.rCore];
  for (let i = 0; i < 5; i++) {
    assert.ok(Math.abs(g.rings[i] / stations[i] - 1) < 0.03, `ring ${i} aberration`);
  }
});

test('ogham notches: at least one per spine', () => {
  const g = composePhiSeal(FP_A);
  assert.ok(g.notches.length >= g.fold, 'at least one notch per spine');
});

test('organic is a Crystal clone with denser recursive forks', () => {
  const crystal = composePhiSeal(FP_A);
  const organic = composeOrganicSeal(FP_A);
  assert.equal(organic.fold, crystal.fold);
  assert.equal(organic.figureId, crystal.figureId);
  assert.deepEqual(organic.rings, crystal.rings);
  assert.deepEqual(organic.notches, crystal.notches);
  assert.deepEqual(organic.spines, crystal.spines);
  assert.notDeepEqual(organic.branches, crystal.branches);
  assert.ok(organic.figure.includes('organic'));
  let maxBranches = 0;
  for (let i = 0; i < 60; i++) {
    maxBranches = Math.max(maxBranches, composeOrganicSeal(randomFingerprint()).branches.length);
  }
  assert.ok(maxBranches >= 12, `expected organic fork density, got max ${maxBranches}`);
});

test('growth (post-Metatron) is deterministic, spine-0 up, no named glyphs', () => {
  assert.deepEqual(composeGrowthSeal(FP_A), composeGrowthSeal(FP_A));
  const g = composeGrowthSeal(FP_A);
  assert.equal(g.figureId, 'growth');
  assert.ok(g.notches.length >= g.fold);
  assert.ok(g.spines[0].y2 < g.spines[0].y1 - 5);
  for (let i = 0; i < 40; i++) {
    assert.equal(composeGrowthSeal(randomFingerprint()).figureId, 'growth');
  }
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

test('archive freeze fixtures still match Crystal / Growth / Organic', async () => {
  const { readFileSync } = await import('node:fs');
  const { dirname, join } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  // IdentitySeal.test.ts lives next to archive/
  const here = dirname(fileURLToPath(import.meta.url));
  const frozen = JSON.parse(readFileSync(join(here, 'archive/fixtures/5fold.json'), 'utf8')) as {
    fingerprint: string;
    crystal: { fold: number; figureId: string; spineCount: number; branchCount: number; notchCount: number };
    growth: { fold: number; figureId: string; spineCount: number; branchCount: number; notchCount: number };
    organic: { fold: number; figureId: string; spineCount: number; branchCount: number; notchCount: number };
  };
  const crystal = composePhiSeal(frozen.fingerprint);
  const growth = composeGrowthSeal(frozen.fingerprint);
  const organic = composeOrganicSeal(frozen.fingerprint);
  assert.equal(crystal.fold, frozen.crystal.fold);
  assert.equal(crystal.figureId, frozen.crystal.figureId);
  assert.equal(crystal.spines.length, frozen.crystal.spineCount);
  assert.equal(crystal.branches.length, frozen.crystal.branchCount);
  assert.equal(crystal.notches.length, frozen.crystal.notchCount);
  assert.equal(growth.fold, frozen.growth.fold);
  assert.equal(growth.figureId, frozen.growth.figureId);
  assert.equal(growth.spines.length, frozen.growth.spineCount);
  assert.equal(growth.branches.length, frozen.growth.branchCount);
  assert.equal(growth.notches.length, frozen.growth.notchCount);
  assert.equal(organic.fold, frozen.organic.fold);
  assert.equal(organic.figureId, frozen.organic.figureId);
  assert.equal(organic.spines.length, frozen.organic.spineCount);
  assert.equal(organic.branches.length, frozen.organic.branchCount);
  assert.equal(organic.notches.length, frozen.organic.notchCount);
});
