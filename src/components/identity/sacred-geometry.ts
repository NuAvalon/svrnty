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
    { id: 'gon', label: 'hexagon' },
    { id: 'hexagram', label: 'hexagram' },
    { id: 'hexagram-inv', label: 'inverted hexagram' },
    { id: 'unicursal', label: 'unicursal hexagram' },
    { id: 'unicursal-inv', label: 'inverted unicursal' },
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
  10: [
    { id: 'gon', label: 'decagon' },
    { id: 'star', label: 'decagram {10/3}', k: 3 },
    { id: 'star-inv', label: 'inverted {10/3}', k: 3 },
    { id: 'star-alt', label: 'compound {10/4}', k: 4 },
    { id: 'star-alt-inv', label: 'inverted {10/4}', k: 4 },
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
 * Crowley unicursal hexagram — Wikimedia Commons geometry
 * (File:Crowley_unicursal_hexagram.svg). Two interlaced triangle-paths
 * (one + rotate 180°), not a banner outline or regular-hexagon stitch.
 * Returns one or more SVG path `d` strings in viewBox-local form already
 * mapped into (cx,cy,R) with optional rotation about center.
 */
export function unicursalHexagramPaths(
  cx: number,
  cy: number,
  R: number,
  rot: number
): string[] {
  // Absolute vertices of the Wikimedia "triangle" path (viewBox 0 0 200 220).
  // Origin path: m100,10 l86.60,150 l-86.60,-50 l62.46,25.86 l-62.46,-105.86
  //              l-62.46,105.86 l62.46,-25.86 l-86.60,50 l86.60,-150 z
  const ox = 100;
  const oy = 110; // rotate origin in the SVG
  const raw: [number, number][] = [
    [100, 10],
    [186.602539, 160],
    [100, 110],
    [162.460411, 135.85787],
    [100, 30],
    [37.539589, 135.85787],
    [100, 110],
    [13.397461, 160],
    [100, 10],
  ];
  // Fit height 200 → diameter 2R
  const scale = (2 * R) / 200;
  const c = Math.cos(rot);
  const s = Math.sin(rot);

  const mapPts = (pts: [number, number][], mirror: boolean) => {
    const out = pts.map(([x, y]) => {
      let lx = (x - ox) * scale;
      let ly = (y - oy) * scale;
      if (mirror) {
        lx = -lx;
        ly = -ly;
      }
      const xr = lx * c - ly * s;
      const yr = lx * s + ly * c;
      return `${(cx + xr).toFixed(2)},${(cy + yr).toFixed(2)}`;
    });
    return `M ${out.join(' L ')} Z`;
  };

  return [mapPts(raw, false), mapPts(raw, true)];
}

/** Single-string helper (joins both interlaced paths). */
export function unicursalHexagramPath(cx: number, cy: number, R: number, rot: number): string {
  return unicursalHexagramPaths(cx, cy, R, rot).join(' ');
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
      for (const d of unicursalHexagramPaths(cx, cy, r, rot)) {
        push(d, 0.72, 1.1);
      }
      break;
    case 'unicursal-inv':
      for (const d of unicursalHexagramPaths(cx, cy, r, rot + Math.PI)) {
        push(d, 0.72, 1.1);
      }
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
