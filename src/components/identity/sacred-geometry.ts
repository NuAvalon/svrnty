// Sacred geometry figures for IdentitySeal — fingerprint picks fold + figure.
// Deterministic only (I-6). No Math.random. All paths formula-generated.

const PHI_INV = (Math.sqrt(5) - 1) / 2;

export type CrystalHabit = 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10;

export type SacredFigureId =
  | 'star'
  | 'star-inv'
  | 'star-alt'
  | 'star-alt-inv'
  | 'hexagram'
  | 'hexagram-inv'
  | 'triquetra'
  | 'vesica'
  | 'diamond'
  | 'circle'
  | 'circles'
  | 'seed'
  | 'flower'
  | 'metatron';

export interface SacredOption {
  id: SacredFigureId;
  label: string;
  /** Star density k for {n/k}; unused for compound/special figures */
  k?: number;
}

export interface SacredEntry {
  fold: CrystalHabit;
  option: SacredOption;
}

/**
 * Per-fold catalogs. No dead `gon` (crystal already draws the N-gon).
 * No preference duplicates. Flat pool below makes every entry equally likely.
 */
export const SACRED_CATALOG: Record<CrystalHabit, SacredOption[]> = {
  3: [
    { id: 'triquetra', label: 'triquetra' },
    { id: 'vesica', label: 'vesica piscis' },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
  ],
  4: [
    { id: 'diamond', label: 'diamond' },
    { id: 'vesica', label: 'vesica cross' },
    { id: 'star', label: 'compound {4/2}', k: 2 },
  ],
  5: [
    { id: 'star', label: 'pentagram {5/2}', k: 2 },
    { id: 'star-inv', label: 'rotated pentagram', k: 2 },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
    { id: 'vesica', label: 'vesica' },
  ],
  6: [
    { id: 'hexagram', label: 'hexagram ★' },
    { id: 'hexagram-inv', label: 'rotated hexagram' },
    { id: 'seed', label: 'seed of life' },
    { id: 'flower', label: 'flower of life' },
    { id: 'metatron', label: "Metatron's cube" },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
  ],
  7: [
    { id: 'star', label: 'heptagram {7/2}', k: 2 },
    { id: 'star-inv', label: 'rotated {7/2}', k: 2 },
    { id: 'star-alt', label: 'heptagram {7/3}', k: 3 },
    { id: 'star-alt-inv', label: 'rotated {7/3}', k: 3 },
  ],
  8: [
    { id: 'star', label: 'octagram {8/3}', k: 3 },
    { id: 'star-inv', label: 'rotated {8/3}', k: 3 },
    { id: 'star-alt', label: 'compound {8/2}', k: 2 },
    { id: 'star-alt-inv', label: 'rotated {8/2}', k: 2 },
  ],
  9: [
    { id: 'star', label: 'nonagram {9/2}', k: 2 },
    { id: 'star-inv', label: 'rotated {9/2}', k: 2 },
    { id: 'star-alt', label: 'compound {9/3}', k: 3 },
    { id: 'star-alt-inv', label: 'rotated {9/3}', k: 3 },
    { id: 'star', label: 'nonagram {9/4}', k: 4 },
    { id: 'star-inv', label: 'rotated {9/4}', k: 4 },
  ],
  10: [
    { id: 'star', label: 'decagram {10/3}', k: 3 },
    { id: 'star-inv', label: 'rotated {10/3}', k: 3 },
    { id: 'star-alt', label: 'compound {10/4}', k: 4 },
    { id: 'star-alt-inv', label: 'rotated {10/4}', k: 4 },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
  ],
};

/** Flat pool — every (fold, figure) entry equally likely. */
export const SACRED_FLAT: SacredEntry[] = (
  Object.keys(SACRED_CATALOG) as unknown as string[]
).flatMap((key) => {
  const fold = Number(key) as CrystalHabit;
  return SACRED_CATALOG[fold].map((option) => ({ fold, option }));
});

export function pickSacredEntry(seed: number): SacredEntry {
  const n = SACRED_FLAT.length;
  return SACRED_FLAT[((seed % n) + n) % n];
}

/** @deprecated fold-scoped pick — prefer pickSacredEntry for equal odds. */
export function pickSacredOption(fold: CrystalHabit, seed: number): SacredOption {
  const catalog = SACRED_CATALOG[fold];
  return catalog[((seed % catalog.length) + catalog.length) % catalog.length];
}

function pt(cx: number, cy: number, r: number, a: number) {
  return { x: cx + Math.cos(a) * r, y: cy + Math.sin(a) * r };
}

function fmt(p: { x: number; y: number }) {
  return `${p.x.toFixed(2)},${p.y.toFixed(2)}`;
}

function gcd(a: number, b: number): number {
  let x = Math.abs(a);
  let y = Math.abs(b);
  while (y) {
    const t = y;
    y = x % y;
    x = t;
  }
  return x || 1;
}

/**
 * Star polygon {n/k}. When gcd(n,k)=1 → one continuous stroke.
 * When gcd>1 → compound of gcd components (e.g. {6/2} hexagram ★, {10/4} = two pentagrams).
 * Density k is formula-driven — not a hand-drawn glyph.
 */
export function starPolygonPath(
  cx: number,
  cy: number,
  R: number,
  n: number,
  k: number,
  rot: number,
  inverted = false
): string {
  const flip = inverted ? Math.PI : 0;
  const base = rot + flip - Math.PI / 2;
  const verts = Array.from({ length: n }, (_, i) => pt(cx, cy, R, base + (i * 2 * Math.PI) / n));
  const d = gcd(n, k);
  const parts: string[] = [];
  for (let start = 0; start < d; start++) {
    const order: number[] = [];
    let idx = start;
    for (let i = 0; i < n / d; i++) {
      order.push(idx);
      idx = (idx + k) % n;
    }
    order.push(order[0]);
    parts.push(`M ${order.map((i) => fmt(verts[i])).join(' L ')}`);
  }
  return parts.join(' ');
}

/** Compound hexagram — two overlapping triangles (★), equivalent to {6/2}. */
export function hexagramCompoundPath(
  cx: number,
  cy: number,
  R: number,
  rot: number,
  inverted = false
): string {
  const flip = inverted ? Math.PI / 6 : 0;
  const base = rot + flip - Math.PI / 2;
  const up = [0, 2, 4].map((i) => fmt(pt(cx, cy, R, base + (i * Math.PI) / 3)));
  const down = [1, 3, 5].map((i) => fmt(pt(cx, cy, R, base + (i * Math.PI) / 3)));
  return `M ${up.join(' L ')} Z M ${down.join(' L ')} Z`;
}

/** Exact circle as SVG path (two semicircle arcs). */
export function circlePath(cx: number, cy: number, r: number): string {
  const x0 = (cx + r).toFixed(2);
  const x1 = (cx - r).toFixed(2);
  const y = cy.toFixed(2);
  const rr = r.toFixed(2);
  return `M ${x0},${y} A ${rr},${rr} 0 1 1 ${x1},${y} A ${rr},${rr} 0 1 1 ${x0},${y}`;
}

/** Arc from angle a0 to a1 around center (sweep ≥ 0, ≤ 2π). */
function arcPath(
  cx: number,
  cy: number,
  r: number,
  a0: number,
  a1: number,
  large = false
): string {
  const p0 = pt(cx, cy, r, a0);
  const p1 = pt(cx, cy, r, a1);
  const la = large ? 1 : 0;
  return `M ${fmt(p0)} A ${r.toFixed(2)},${r.toFixed(2)} 0 ${la} 1 ${fmt(p1)}`;
}

/** Triquetra — three vesica lobes as exact circular arcs. */
export function triquetraPath(cx: number, cy: number, R: number, rot: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 3; i++) {
    const a0 = rot - Math.PI / 2 + (i * 2 * Math.PI) / 3;
    const c = pt(cx, cy, R * PHI_INV, a0);
    const r = R * PHI_INV * 1.15;
    const start = a0 + Math.PI - Math.PI / 3;
    const end = a0 + Math.PI + Math.PI / 3;
    parts.push(arcPath(c.x, c.y, r, start, end, false));
  }
  return parts.join(' ');
}

/** Vesica piscis — exact circle outlines (cross of two vesicas for fold 4). */
export function vesicaPaths(
  cx: number,
  cy: number,
  R: number,
  rot: number,
  cross: boolean
): string[] {
  const d = R * PHI_INV;
  const r = R * PHI_INV * 1.15;
  const a = rot;
  const c1 = pt(cx, cy, d, a);
  const c2 = pt(cx, cy, d, a + Math.PI);
  const out = [circlePath(c1.x, c1.y, r), circlePath(c2.x, c2.y, r)];
  if (cross) {
    const c3 = pt(cx, cy, d, a + Math.PI / 2);
    const c4 = pt(cx, cy, d, a + (3 * Math.PI) / 2);
    out.push(circlePath(c3.x, c3.y, r), circlePath(c4.x, c4.y, r));
  }
  return out;
}

/** Concentric φ cascade: R, R·φ⁻¹, R·φ⁻². */
export function phiCirclePaths(cx: number, cy: number, R: number): string[] {
  return [
    circlePath(cx, cy, R),
    circlePath(cx, cy, R * PHI_INV),
    circlePath(cx, cy, R * PHI_INV * PHI_INV),
  ];
}

/** Seed of life — center + 6 petal circles (scaled inside the crystal). */
export function seedOfLifePaths(cx: number, cy: number, R: number, rot: number): string[] {
  const r = R * PHI_INV * 0.85;
  const out = [circlePath(cx, cy, r)];
  for (let i = 0; i < 6; i++) {
    const a = rot - Math.PI / 2 + (i * Math.PI) / 3;
    const c = pt(cx, cy, r, a);
    out.push(circlePath(c.x, c.y, r));
  }
  return out;
}

/**
 * Flower of life — seed + one outer ring (13 circles).
 * Held inside ~0.55R so it accents the crystal instead of filling the seal.
 */
export function flowerOfLifePaths(cx: number, cy: number, R: number, rot: number): string[] {
  const r = R * PHI_INV * 0.55;
  const paths = [circlePath(cx, cy, r)];
  for (let i = 0; i < 6; i++) {
    const a = rot - Math.PI / 2 + (i * Math.PI) / 3;
    const c = pt(cx, cy, r, a);
    paths.push(circlePath(c.x, c.y, r));
  }
  for (let i = 0; i < 6; i++) {
    const a = rot - Math.PI / 2 + (i * Math.PI) / 3;
    const c = pt(cx, cy, 2 * r, a);
    paths.push(circlePath(c.x, c.y, r));
  }
  return paths;
}

/**
 * Metatron's cube — light skeleton, not every-pair spaghetti.
 * 13 fruit-of-life centers; draw radii, inner/outer hex, and compound hexagram.
 * Reads as Metatron without burying the crystal.
 */
export function metatronPaths(cx: number, cy: number, R: number, rot: number): string[] {
  const r = R * PHI_INV * 0.42;
  const base = rot - Math.PI / 2;
  const inner = Array.from({ length: 6 }, (_, i) => pt(cx, cy, r, base + (i * Math.PI) / 3));
  const outer = Array.from({ length: 6 }, (_, i) => pt(cx, cy, 2 * r, base + (i * Math.PI) / 3));
  const lines: string[] = [];

  // Radii: center → inner → outer along each ray
  for (let i = 0; i < 6; i++) {
    lines.push(`M ${fmt({ x: cx, y: cy })} L ${fmt(outer[i])}`);
  }
  // Inner hexagon
  for (let i = 0; i < 6; i++) {
    lines.push(`M ${fmt(inner[i])} L ${fmt(inner[(i + 1) % 6])}`);
  }
  // Outer hexagon
  for (let i = 0; i < 6; i++) {
    lines.push(`M ${fmt(outer[i])} L ${fmt(outer[(i + 1) % 6])}`);
  }
  // Compound hexagram on outer vertices
  for (const step of [2, 3]) {
    for (let i = 0; i < 6; i++) {
      if (step === 3 && i >= 3) continue; // diameters once
      lines.push(`M ${fmt(outer[i])} L ${fmt(outer[(i + step) % 6])}`);
    }
  }
  // Inner hexagram accents
  for (let i = 0; i < 6; i++) {
    lines.push(`M ${fmt(inner[i])} L ${fmt(inner[(i + 2) % 6])}`);
  }
  return lines;
}

export interface SacredRender {
  label: string;
  paths: { d: string; op: number; w: number }[];
}

/** Build sacred overlay paths for a fold + picked option. */
export function composeSacredFigure(
  fold: CrystalHabit,
  option: SacredOption,
  cx: number,
  cy: number,
  R: number,
  rot: number
): SacredRender {
  const r = R * 0.92;
  const paths: SacredRender['paths'] = [];

  const push = (d: string, op = 0.7, w = 1.1) => {
    if (d) paths.push({ d, op, w });
  };

  switch (option.id) {
    case 'diamond': {
      const base = rot + Math.PI / 4 - Math.PI / 2;
      const pts = [0, 1, 2, 3].map((i) => fmt(pt(cx, cy, r, base + (i * Math.PI) / 2)));
      push(`M ${pts.join(' L ')} Z`);
      break;
    }
    case 'star':
    case 'star-inv':
      push(starPolygonPath(cx, cy, r, fold, option.k ?? 2, rot, option.id === 'star-inv'));
      break;
    case 'star-alt':
    case 'star-alt-inv':
      push(starPolygonPath(cx, cy, r, fold, option.k ?? 3, rot, option.id === 'star-alt-inv'));
      break;
    case 'hexagram':
      push(hexagramCompoundPath(cx, cy, r, rot, false), 0.65, 1.05);
      break;
    case 'hexagram-inv':
      push(hexagramCompoundPath(cx, cy, r, rot, true), 0.65, 1.05);
      break;
    case 'triquetra':
      push(triquetraPath(cx, cy, r, rot), 0.65, 1.05);
      break;
    case 'vesica':
      for (const d of vesicaPaths(cx, cy, R, rot, fold === 4)) {
        push(d, 0.45, 0.9);
      }
      break;
    case 'circle':
      push(circlePath(cx, cy, r), 0.75, 1.2);
      break;
    case 'circles':
      phiCirclePaths(cx, cy, r).forEach((d, i) => push(d, 0.7 - i * 0.12, 1.15 - i * 0.15));
      break;
    case 'seed':
      for (const d of seedOfLifePaths(cx, cy, R, rot)) {
        push(d, 0.42, 0.8);
      }
      break;
    case 'flower':
      for (const d of flowerOfLifePaths(cx, cy, R, rot)) {
        push(d, 0.28, 0.55);
      }
      break;
    case 'metatron':
      for (const d of metatronPaths(cx, cy, R, rot)) {
        push(d, 0.32, 0.5);
      }
      break;
    default:
      break;
  }

  return { label: option.label, paths };
}
