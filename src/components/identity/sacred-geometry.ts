// Sacred geometry figures for IdentitySeal — fingerprint picks fold + figure.
// Deterministic only (I-6). No Math.random.

const PHI_INV = (Math.sqrt(5) - 1) / 2;

export type CrystalHabit = 3 | 4 | 5 | 6 | 7 | 8 | 9;

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
  | 'diamond';

export interface SacredOption {
  id: SacredFigureId;
  label: string;
  /** Star density k for {n/k}; unused for compound/special figures */
  k?: number;
}

/** Catalog per fold — sacred geometry seed set. */
export const SACRED_CATALOG: Record<CrystalHabit, SacredOption[]> = {
  3: [
    { id: 'gon', label: 'triangle' },
    { id: 'triquetra', label: 'triquetra' },
    { id: 'vesica', label: 'vesica piscis' },
  ],
  4: [
    { id: 'gon', label: 'square' },
    { id: 'diamond', label: 'diamond' },
    { id: 'vesica', label: 'vesica cross' },
  ],
  5: [
    { id: 'gon', label: 'pentagon' },
    { id: 'star', label: 'pentagram', k: 2 },
    { id: 'star-inv', label: 'inverted pentagram', k: 2 },
  ],
  6: [
    // Hexagrams weighted — compound ★ is the favorite; unicursal kept for variety
    { id: 'hexagram', label: 'hexagram' },
    { id: 'hexagram', label: 'hexagram' },
    { id: 'hexagram-inv', label: 'inverted hexagram' },
    { id: 'unicursal', label: 'unicursal hexagram' },
    { id: 'unicursal-inv', label: 'inverted unicursal' },
    { id: 'gon', label: 'hexagon' },
  ],
  7: [
    { id: 'gon', label: 'heptagon' },
    { id: 'star', label: 'heptagram {7/2}', k: 2 },
    { id: 'star-alt', label: 'heptagram {7/3}', k: 3 },
    { id: 'star-inv', label: 'inverted {7/2}', k: 2 },
  ],
  8: [
    { id: 'gon', label: 'octagon' },
    { id: 'star', label: 'octagram {8/3}', k: 3 },
    { id: 'star-inv', label: 'inverted octagram', k: 3 },
  ],
  9: [
    { id: 'gon', label: 'nonagon' },
    { id: 'star', label: 'nonagram {9/2}', k: 2 },
    { id: 'star-alt', label: 'nonagram {9/4}', k: 4 },
    { id: 'star-inv', label: 'inverted {9/2}', k: 2 },
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

/** Unicursal star polygon {n/k} — one continuous stroke when gcd(n,k)=1. */
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
  const order: number[] = [];
  let idx = 0;
  for (let i = 0; i < n; i++) {
    order.push(idx);
    idx = (idx + k) % n;
  }
  order.push(order[0]);
  return `M ${order.map((i) => fmt(verts[i])).join(' L ')}`;
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
 * Classic Crowley / Thelemic unicursal hexagram — one continuous outline.
 * Proportions match the familiar banner shape (not a regular-hexagon stitch).
 * Unit coords derived from the standard 0–100 glyph: top tip, upper points,
 * waist crossings, lower tips, back to top.
 */
export function unicursalHexagramPath(cx: number, cy: number, R: number, rot: number): string {
  // Normalized from classic viewBox path
  // M50,0 L61,33 L100,33 L70,55 L82,100 L50,72 L18,100 L30,55 L0,33 L39,33 Z
  const unit: [number, number][] = [
    [0.0, -1.0],
    [0.22, -0.34],
    [1.0, -0.34],
    [0.4, 0.1],
    [0.64, 1.0],
    [0.0, 0.44],
    [-0.64, 1.0],
    [-0.4, 0.1],
    [-1.0, -0.34],
    [-0.22, -0.34],
  ];
  // Fit width-1.0 glyph into radius R (glyph half-width ≈ 1)
  const scale = R * 0.92;
  const c = Math.cos(rot);
  const s = Math.sin(rot);
  const pts = unit.map(([x, y]) => {
    const xr = x * c - y * s;
    const yr = x * s + y * c;
    return `${(cx + xr * scale).toFixed(2)},${(cy + yr * scale).toFixed(2)}`;
  });
  return `M ${pts[0]} L ${pts.slice(1).join(' L ')} Z`;
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
      push(unicursalHexagramPath(cx, cy, r, rot + Math.PI / 2));
      break;
    case 'unicursal-inv':
      push(unicursalHexagramPath(cx, cy, r, rot + Math.PI / 2 + Math.PI));
      break;
    case 'triquetra':
      push(triquetraPath(cx, cy, r, rot), 0.6, 1.0);
      break;
    case 'vesica':
      for (const d of vesicaPaths(cx, cy, R, rot, fold === 4)) {
        push(d, 0.4, 0.85);
      }
      break;
    default:
      break;
  }

  return { label: option.label, paths };
}
