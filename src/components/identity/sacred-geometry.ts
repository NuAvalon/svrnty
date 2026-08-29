// Sacred geometry figures for IdentitySeal — fingerprint picks fold + figure.
// Deterministic only (I-6). No Math.random.

const PHI_INV = (Math.sqrt(5) - 1) / 2;

export type CrystalHabit = 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10;

export type SacredFigureId =
  | 'gon'
  | 'star'
  | 'star-inv'
  | 'hexagram'
  | 'hexagram-inv'
  | 'unicursal'
  | 'unicursal-inv'
  | 'star-alt' // second denser star {n/k'} when available
  | 'star-alt-inv'
  | 'triquetra'
  | 'vesica'
  | 'diamond'
  | 'circle'
  | 'circles' // φ-nested concentric rings
  | 'seed'; // seed of life (fold 6)

export interface SacredOption {
  id: SacredFigureId;
  label: string;
  /** Star density k for {n/k}; unused for compound/special figures */
  k?: number;
}

/** Catalog per fold — sacred geometry seed set (uniform; no preference weights). */
export const SACRED_CATALOG: Record<CrystalHabit, SacredOption[]> = {
  3: [
    { id: 'gon', label: 'triangle' },
    { id: 'triquetra', label: 'triquetra' },
    { id: 'vesica', label: 'vesica piscis' },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
  ],
  4: [
    { id: 'gon', label: 'square' },
    { id: 'diamond', label: 'diamond' },
    { id: 'vesica', label: 'vesica cross' },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
  ],
  5: [
    { id: 'gon', label: 'pentagon' },
    { id: 'star', label: 'pentagram', k: 2 },
    { id: 'star-inv', label: 'inverted pentagram', k: 2 },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
  ],
  6: [
    { id: 'gon', label: 'hexagon' },
    { id: 'hexagram', label: 'hexagram' },
    { id: 'hexagram-inv', label: 'inverted hexagram' },
    { id: 'unicursal', label: 'unicursal hexagram' },
    { id: 'unicursal-inv', label: 'inverted unicursal' },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
    { id: 'seed', label: 'seed of life' },
  ],
  7: [
    { id: 'gon', label: 'heptagon' },
    { id: 'star', label: 'heptagram {7/2}', k: 2 },
    { id: 'star-alt', label: 'heptagram {7/3}', k: 3 },
    { id: 'star-inv', label: 'inverted {7/2}', k: 2 },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
  ],
  8: [
    { id: 'gon', label: 'octagon' },
    { id: 'star', label: 'octagram {8/3}', k: 3 },
    { id: 'star-inv', label: 'inverted octagram', k: 3 },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
  ],
  9: [
    { id: 'gon', label: 'nonagon' },
    { id: 'star', label: 'nonagram {9/2}', k: 2 },
    { id: 'star-alt', label: 'nonagram {9/4}', k: 4 },
    { id: 'star-inv', label: 'inverted {9/2}', k: 2 },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
  ],
  10: [
    { id: 'gon', label: 'decagon' },
    { id: 'star', label: 'decagram {10/3}', k: 3 },
    { id: 'star-inv', label: 'inverted {10/3}', k: 3 },
    { id: 'star-alt', label: 'compound {10/4}', k: 4 },
    { id: 'star-alt-inv', label: 'inverted {10/4}', k: 4 },
    { id: 'circle', label: 'circle' },
    { id: 'circles', label: 'φ circles' },
  ],
};

export function pickSacredOption(fold: CrystalHabit, seed: number): SacredOption {
  const catalog = SACRED_CATALOG[fold];
  return catalog[seed % catalog.length];
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
 * Star polygon {n/k}. When gcd(n,k)=1 → one unicursal stroke.
 * When gcd>1 → compound of gcd components (e.g. {10/4} = two pentagrams).
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

/** Compound hexagram — two overlapping triangles (★), not unicursal. */
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

/**
 * Crowley unicursal hexagram — single continuous wireframe (one stroke).
 * Six vertices in unicursal order: top → SE → NW → NE → SW → bottom → top.
 * Not the double/interlaced filled ribbon from Wikimedia.
 */
export function unicursalHexagramPaths(
  cx: number,
  cy: number,
  R: number,
  rot: number
): string[] {
  // Unit coords (y-down), classic Crowley proportions
  const raw: [number, number][] = [
    [0, -1],
    [0.8660254, 0.5],
    [-0.5, -0.2886751],
    [0.5, -0.2886751],
    [-0.8660254, 0.5],
    [0, 1],
  ];
  const c = Math.cos(rot);
  const s = Math.sin(rot);
  const pts = raw.map(([x, y]) => {
    const xr = (x * c - y * s) * R;
    const yr = (x * s + y * c) * R;
    return `${(cx + xr).toFixed(2)},${(cy + yr).toFixed(2)}`;
  });
  return [`M ${pts.join(' L ')} Z`];
}

/** Single-string helper (one wireframe path). */
export function unicursalHexagramPath(cx: number, cy: number, R: number, rot: number): string {
  return unicursalHexagramPaths(cx, cy, R, rot)[0];
}

/** Triquetra — three vesica lobes (approximate circular arcs as polylines). */
export function triquetraPath(cx: number, cy: number, R: number, rot: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 3; i++) {
    const a0 = rot - Math.PI / 2 + (i * 2 * Math.PI) / 3;
    const c = pt(cx, cy, R * PHI_INV, a0);
    const r = R * 0.72;
    const segs = 16;
    const pts: string[] = [];
    for (let s = 0; s <= segs; s++) {
      const ang = a0 + Math.PI + (-Math.PI / 3) + (s / segs) * ((2 * Math.PI) / 3);
      pts.push(fmt(pt(c.x, c.y, r, ang)));
    }
    parts.push(`M ${pts.join(' L ')}`);
  }
  return parts.join(' ');
}

/** Vesica piscis — two overlapping circles as outlines (or cross of two vesicas for fold 4). */
export function vesicaPaths(cx: number, cy: number, R: number, rot: number, cross: boolean): string[] {
  const d = R * PHI_INV;
  const r = R * 0.72;
  const a = rot;
  const c1 = pt(cx, cy, d, a);
  const c2 = pt(cx, cy, d, a + Math.PI);
  const circle = (c: { x: number; y: number }) => {
    // Approximate circle with polygon
    const segs = 24;
    const pts = Array.from({ length: segs }, (_, i) =>
      fmt(pt(c.x, c.y, r, (i * 2 * Math.PI) / segs))
    );
    return `M ${pts.join(' L ')} Z`;
  };
  const out = [circle(c1), circle(c2)];
  if (cross) {
    const c3 = pt(cx, cy, d, a + Math.PI / 2);
    const c4 = pt(cx, cy, d, a + (3 * Math.PI) / 2);
    out.push(circle(c3), circle(c4));
  }
  return out;
}

/** Exact circle as SVG path (two semicircle arcs). */
export function circlePath(cx: number, cy: number, r: number): string {
  const x0 = (cx + r).toFixed(2);
  const x1 = (cx - r).toFixed(2);
  const y = cy.toFixed(2);
  const rr = r.toFixed(2);
  return `M ${x0},${y} A ${rr},${rr} 0 1 1 ${x1},${y} A ${rr},${rr} 0 1 1 ${x0},${y}`;
}

/** Concentric φ cascade: R, R·φ⁻¹, R·φ⁻². */
export function phiCirclePaths(cx: number, cy: number, R: number): string[] {
  const r1 = R;
  const r2 = R * PHI_INV;
  const r3 = R * PHI_INV * PHI_INV;
  return [circlePath(cx, cy, r1), circlePath(cx, cy, r2), circlePath(cx, cy, r3)];
}

/** Seed of life — center + 6 petal circles (radius = R·φ⁻¹). */
export function seedOfLifePaths(cx: number, cy: number, R: number, rot: number): string[] {
  const r = R * PHI_INV;
  const out = [circlePath(cx, cy, r)];
  for (let i = 0; i < 6; i++) {
    const a = rot - Math.PI / 2 + (i * Math.PI) / 3;
    const c = pt(cx, cy, r, a);
    out.push(circlePath(c.x, c.y, r));
  }
  return out;
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
    case 'gon':
      // Frame already drawn by crystal layers — no extra star
      break;
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
    case 'unicursal':
      push(unicursalHexagramPaths(cx, cy, r, rot)[0], 0.72, 1.15);
      break;
    case 'unicursal-inv':
      push(unicursalHexagramPaths(cx, cy, r, rot + Math.PI)[0], 0.72, 1.15);
      break;
    case 'triquetra':
      push(triquetraPath(cx, cy, r, rot), 0.6, 1.0);
      break;
    case 'vesica':
      for (const d of vesicaPaths(cx, cy, R, rot, fold === 4)) {
        push(d, 0.4, 0.85);
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
        push(d, 0.55, 0.95);
      }
      break;
    default:
      break;
  }

  return { label: option.label, paths };
}
