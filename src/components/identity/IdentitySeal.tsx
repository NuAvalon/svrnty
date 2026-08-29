'use client';

// Deterministic identity seals from fingerprint (I-6).
// Variants share the same fingerprint → different geometry grammars.
// Default production variant: `phi` — sacred-geometry crystal (φ measure + catalog figure).
// Lab-only `sigil` keeps the earlier 5-fold pentagram stack for comparison.

import { useMemo } from 'react';
import { solarEmber as E } from '../recovery/solar-ember';
import {
  pickSacredEntry,
  composeSacredFigure,
  starPolygonPath,
  type CrystalHabit as SacredHabit,
} from './sacred-geometry';

export {
  SACRED_CATALOG,
  SACRED_FLAT,
  SACRED_DEMOTED,
  pickSacredOption,
  pickSacredEntry,
  composeSacredFigure,
  starPolygonPath,
  hexagramCompoundPath,
} from './sacred-geometry';
export type { SacredOption, SacredFigureId, SacredEntry } from './sacred-geometry';

/** φ = (1 + √5) / 2 */
export const PHI = (1 + Math.sqrt(5)) / 2;
export const PHI_INV = PHI - 1;
export const GOLDEN_ANGLE = (2 * Math.PI) / (PHI * PHI);

export type SealVariant = 'growth' | 'phi' | 'sigil' | 'rosette' | 'lattice' | 'ring' | 'none';

export const SEAL_VARIANTS: { id: SealVariant; title: string; blurb: string }[] = [
  { id: 'growth', title: 'Growth', blurb: 'Branches past the rim · broken ripple-arcs · notches · orbs' },
  { id: 'phi', title: 'Crystal', blurb: 'Sacred tech · {n/k} stars · φ measure (flower/Metatron demoted)' },
  { id: 'sigil', title: 'Sigil (old)', blurb: 'Earlier 5-fold pentagram stack' },
  { id: 'rosette', title: 'Rosette', blurb: 'Soft Bezier petals (earlier draft)' },
  { id: 'lattice', title: 'Lattice', blurb: 'Crystal spines + branches, no facets' },
  { id: 'ring', title: 'Ring', blurb: 'Polygon cascade + core only' },
  { id: 'none', title: 'None', blurb: 'Empty mark — card without a seal' },
];

/**
 * Crystal habits — trigonal through decagon (cyber-sigil 10-point).
 * Sacred figure (hexagram, {n/k} star, flower, Metatron…) from the flat pool.
 */
export const CRYSTAL_HABITS = [3, 4, 5, 6, 7, 8, 9, 10] as const;
export type CrystalHabit = (typeof CRYSTAL_HABITS)[number];

/**
 * Uniform habit over the flat sacred pool — fold comes with the figure.
 * Every (fold, figure) entry is equally likely (no preference weights).
 */
export function sacredEntryFromFingerprint(fingerprint: string) {
  const n = hexNibbles(fingerprint);
  const seed = fnv(fingerprint) ^ (n[2] * 17 + n[3] * 31 + (n[5] << 4));
  return pickSacredEntry(seed);
}

export function foldFromFingerprint(fingerprint: string): CrystalHabit {
  return sacredEntryFromFingerprint(fingerprint).fold;
}

export const HABIT_LABEL: Record<CrystalHabit, string> = {
  3: 'trigonal',
  4: 'square',
  5: 'pentagon',
  6: 'hexagonal',
  7: 'heptagon',
  8: 'octagon',
  9: 'nonagon',
  10: 'decagon',
};
export function hexNibbles(fingerprint: string): number[] {
  const hex = fingerprint.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  const out: number[] = [];
  for (let i = 0; i < Math.min(hex.length, 32); i++) {
    out.push(parseInt(hex[i], 16));
  }
  while (out.length < 16) out.push(0);
  return out;
}

export function fingerprintHex(fingerprint: string, len = 40): string {
  const hex = fingerprint.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  return (hex + '0'.repeat(len)).slice(0, len);
}

/** Increment one hex digit at `index` by `delta` (wrap 0–f). */
export function shiftFingerprintDigit(fingerprint: string, index: number, delta: number): string {
  const hex = fingerprintHex(fingerprint);
  const i = ((index % hex.length) + hex.length) % hex.length;
  const chars = hex.split('');
  const v = (parseInt(chars[i], 16) + delta + 16) % 16;
  chars[i] = v.toString(16);
  return chars.join('');
}

/** Cryptographically-strong random fingerprint hex (lab only — not an identity). */
export function randomFingerprint(len = 40): string {
  const bytes = new Uint8Array(Math.ceil(len / 2));
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').slice(0, len);
}

export function fnv(fp: string): number {
  let h = 2166136261;
  for (let i = 0; i < fp.length; i++) {
    h ^= fp.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

function pt(cx: number, cy: number, r: number, a: number) {
  return { x: cx + Math.cos(a) * r, y: cy + Math.sin(a) * r };
}

function fmt(p: { x: number; y: number }) {
  return `${p.x.toFixed(2)},${p.y.toFixed(2)}`;
}

type Line = { x1: number; y1: number; x2: number; y2: number; op: number; w: number };

/**
 * Default seal: crystalline habit + sacred-geometry figure from fingerprint.
 * φ sets radial cascade + dendrite lengths; fold + catalog figure are seeded separately.
 */
export function composePhiSeal(fingerprint: string) {
  const n = hexNibbles(fingerprint);
  const seed = fnv(fingerprint);
  const cx = 50;
  const cy = 50;

  const R = 40 + (n[0] % 5); // 40–44 — wider radius spread
  const r1 = R * PHI_INV;
  const r2 = R * PHI_INV * PHI_INV;
  const r3 = R * PHI_INV ** 3;
  const rCore = R * PHI_INV ** 4;

  // Flat sacred pool → fold + figure equally likely across all catalog entries
  const entry = sacredEntryFromFingerprint(fingerprint);
  const fold = entry.fold;
  const sacredOpt = entry.option;

  // Canonical orientation: spine / vertex 0 at top. No free whole-seal rotation —
  // two fingerprints must never be the same crystal merely spun (incl. 360°/fold twins).
  // Former rotation entropy goes into per-arm structure below instead.
  const rot = -Math.PI / 2;
  const branchAng = Math.PI / fold;
  // 0..1 from leftover seed bits — scales dendrite/facet asymmetry, not spin
  const structMix = ((seed >>> 3) % 1000) / 1000;
  const radiusJitter = ((n[1] + n[4]) % 7) / 7;

  const sacred = composeSacredFigure(fold as SacredHabit, sacredOpt, cx, cy, R, rot);

  const spines: Line[] = [];
  const branches: Line[] = [];
  const facets: string[] = [];
  const blades: string[] = [];

  for (let i = 0; i < fold; i++) {
    const a = rot + (i * 2 * Math.PI) / fold;
    const tip = pt(cx, cy, R, a);
    const mid = pt(cx, cy, r1, a);
    const near = pt(cx, cy, r2, a);

    spines.push({ x1: cx, y1: cy, x2: tip.x, y2: tip.y, op: 0.55, w: 1.05 });

    // ~50/50 dendrite gates; lengths use structMix so orientation bits still alter shape
    const branchLen =
      (R - r1) * PHI_INV * (0.7 + (n[i % n.length] / 15) * 0.4 + structMix * 0.2 + radiusJitter * 0.1);
    if (n[i % n.length] & 1) {
      branches.push({
        x1: mid.x, y1: mid.y,
        x2: mid.x + Math.cos(a - branchAng) * branchLen,
        y2: mid.y + Math.sin(a - branchAng) * branchLen,
        op: 0.42, w: 0.75,
      });
      branches.push({
        x1: mid.x, y1: mid.y,
        x2: mid.x + Math.cos(a + branchAng) * branchLen * (0.85 + structMix * 0.2),
        y2: mid.y + Math.sin(a + branchAng) * branchLen * (0.85 + structMix * 0.2),
        op: 0.42, w: 0.75,
      });
    }

    if (n[(i + 6) % n.length] & 2) {
      const len2 = (r1 - r2) * PHI_INV * (0.65 + (n[(i + 3) % n.length] / 20) + structMix * 0.15);
      branches.push({
        x1: near.x, y1: near.y,
        x2: near.x + Math.cos(a - branchAng) * len2,
        y2: near.y + Math.sin(a - branchAng) * len2,
        op: 0.32, w: 0.6,
      });
      branches.push({
        x1: near.x, y1: near.y,
        x2: near.x + Math.cos(a + branchAng) * len2,
        y2: near.y + Math.sin(a + branchAng) * len2,
        op: 0.32, w: 0.6,
      });
    }

    if (n[(i + 2) % n.length] & 1) {
      const half = (Math.PI / fold) * PHI_INV * (0.5 + (n[i % n.length] / 20) + structMix * 0.1);
      const p0 = pt(cx, cy, r2, a);
      const p1 = pt(cx, cy, (r1 + r2) / 2, a - half);
      const p2 = pt(cx, cy, r1, a);
      const p3 = pt(cx, cy, (r1 + r2) / 2, a + half);
      facets.push(`M ${fmt(p0)} L ${fmt(p1)} L ${fmt(p2)} L ${fmt(p3)} Z`);
    }

    if (n[(i + 4) % n.length] & 4) {
      const half = (Math.PI / fold) * (0.3 + radiusJitter * 0.1);
      const p0 = pt(cx, cy, r1 + (R - r1) * PHI_INV, a);
      const p1 = pt(cx, cy, (r1 + R) / 2, a - half);
      const p2 = tip;
      const p3 = pt(cx, cy, (r1 + R) / 2, a + half);
      facets.push(`M ${fmt(p0)} L ${fmt(p1)} L ${fmt(p2)} L ${fmt(p3)} Z`);
    }
  }

  // N-gon frames at R, R/φ, R/φ² (crystal habit)
  const hexAt = (radius: number, phase = 0) =>
    Array.from({ length: fold }, (_, i) => {
      const a = rot + phase + (i * 2 * Math.PI) / fold;
      return fmt(pt(cx, cy, radius, a));
    }).join(' ');

  const hexOuter = hexAt(R);
  const hexMid = hexAt(r1);
  const hexInner = hexAt(r2);
  const hexCore = hexAt(r3);

  // Compatibility: first sacred path alias (lab/tests)
  const sacredPath = sacred.paths[0]?.d ?? null;

  // Edge ticks at vertices + mid-edges
  const ticks: { x1: number; y1: number; x2: number; y2: number; major: boolean }[] = [];
  for (let i = 0; i < fold * 2; i++) {
    const a = rot + (i * Math.PI) / fold;
    const major = i % 2 === 0;
    const p0 = pt(cx, cy, major ? R - 3 : R - 1.8, a);
    const p1 = pt(cx, cy, R + 2.2, a);
    ticks.push({ x1: p0.x, y1: p0.y, x2: p1.x, y2: p1.y, major });
  }

  // Construction circles (ring variant / faint underlay)
  const rings = [R, r1, r2] as const;

  // Compatibility aliases used by older render paths / tests
  const chords = [...spines, ...branches];
  const dualPts = hexMid;
  const corePent = hexCore;

  return {
    R, r1, r2, r3, rCore,
    fold,
    habit: HABIT_LABEL[fold],
    figure: sacred.label,
    figureId: sacredOpt.id,
    sacredPaths: sacred.paths,
    blades,
    facets,
    spines,
    branches,
    chords,
    ticks,
    dualPts,
    corePent,
    hexOuter,
    hexMid,
    hexInner,
    hexCore,
    sacredPath,
    rings,
  };
}

/**
 * Growth seal — fold + φ skeleton; branches, notches, orbs, and broken ripple-arcs.
 * Opacities/weights: veil × φ⁻ᵈ (fingerprint sets veil). No named sacred fills.
 * Ripples are gated arc segments (not solid circles) so the seal isn't caged.
 */
export function composeGrowthSeal(fingerprint: string) {
  const n = hexNibbles(fingerprint);
  const seed = fnv(fingerprint);
  const cx = 50;
  const cy = 50;

  const R = 40 + (n[0] % 5);
  const r1 = R * PHI_INV;
  const r2 = R * PHI_INV * PHI_INV;
  const r3 = R * PHI_INV ** 3;
  const rCore = R * PHI_INV ** 4;

  const fold = CRYSTAL_HABITS[((seed >>> 5) + n[2] + n[7]) % CRYSTAL_HABITS.length];
  const rot = -Math.PI / 2;
  const structMix = ((seed >>> 3) % 1000) / 1000;
  const radiusJitter = ((n[1] + n[4]) % 7) / 7;

  const veil = PHI_INV * (0.85 + structMix * PHI_INV);
  const opAt = (d: number) => Math.max(0.1, veil * PHI_INV ** d);
  const wAt = (d: number) => Math.max(0.4, PHI * PHI_INV ** d);

  const starKs: Partial<Record<CrystalHabit, number>> = {
    5: 2, 6: 2, 7: 2 + (n[8] % 2), 8: 2 + (n[8] % 2), 9: 2 + (n[8] % 3), 10: 3 + (n[8] % 2),
  };
  const k = starKs[fold];
  const sacredPaths =
    k != null
      ? [{ d: starPolygonPath(cx, cy, R * 0.88, fold, k, rot, false), op: opAt(3), w: wAt(3) }]
      : [];

  type Orb = { cx: number; cy: number; r: number; op: number; w: number };
  type Arc = { d: string; op: number; w: number };
  type Ripple = { r: number; op: number; w: number };

  const spines: Line[] = [];
  const branches: Line[] = [];
  const notches: Line[] = [];
  const orbs: Orb[] = [];
  const arcs: Arc[] = [];

  const spineOp = opAt(0);
  const spineW = wAt(1);
  const br1Op = opAt(1);
  const br1W = wAt(2);
  const br2Op = opAt(2);
  const br2W = wAt(3);
  const notchOp = opAt(2);
  const notchW = wAt(2);
  const tipOrbOp = opAt(1);
  const forkOrbOp = opAt(2);
  const coreOrbOp = opAt(0);

  const pushSectorArc = (
    radius: number,
    a0: number,
    a1: number,
    depth: number,
    bright = false,
  ) => {
    if (a1 <= a0) return;
    const p0 = pt(cx, cy, radius, a0);
    const p1 = pt(cx, cy, radius, a1);
    arcs.push({
      d: `M ${fmt(p0)} A ${radius.toFixed(2)},${radius.toFixed(2)} 0 0 1 ${fmt(p1)}`,
      op: bright ? Math.min(veil, opAt(depth) * PHI) : opAt(depth),
      w: bright ? wAt(depth) : wAt(depth + 1),
    });
  };

  for (let i = 0; i < fold; i++) {
    const a = rot + (i * 2 * Math.PI) / fold;
    const tip = pt(cx, cy, R, a);
    spines.push({ x1: cx, y1: cy, x2: tip.x, y2: tip.y, op: spineOp, w: spineW });

    const bit = n[i % n.length];
    const bit2 = n[(i + 5) % n.length];
    const bit3 = n[(i + 9) % n.length];
    const nextBit = n[(i + 1) % n.length];
    const aNext = a + (2 * Math.PI) / fold;

    const tipR = PHI_INV * (1.1 + (bit % 3) * 0.35 + radiusJitter * 0.2);
    orbs.push({ cx: tip.x, cy: tip.y, r: tipR, op: tipOrbOp, w: wAt(2) });

    const forkAt = (baseR: number, ang: number, len: number, depth: number, side: number) => {
      const origin = pt(cx, cy, baseR, a);
      const ba = ang + side * ((Math.PI / fold) * (PHI_INV + structMix * PHI_INV * PHI_INV + bit / 40));
      const end = {
        x: origin.x + Math.cos(ba) * len,
        y: origin.y + Math.sin(ba) * len,
      };
      branches.push({
        x1: origin.x, y1: origin.y, x2: end.x, y2: end.y,
        op: depth === 1 ? br1Op : br2Op,
        w: depth === 1 ? br1W : br2W,
      });
      return { ...end, ang: ba };
    };

    let left: { x: number; y: number; ang: number } | null = null;
    let right: { x: number; y: number; ang: number } | null = null;

    // Branches grow more often and can overshoot the rim slightly
    if (bit & 1 || bit2 & 1) {
      const len1 = (R - r1) * (0.85 + (bit / 18) + structMix * 0.25 + radiusJitter * 0.15);
      left = forkAt(r1, a, len1, 1, -1);
      right = forkAt(r1, a, len1 * (0.9 + structMix * PHI_INV), 1, 1);

      if (bit2 & 1) {
        orbs.push({
          cx: left.x, cy: left.y,
          r: PHI_INV * (0.9 + (bit2 % 3) * 0.2),
          op: forkOrbOp, w: wAt(3),
        });
      }
      if (bit2 & 2) {
        orbs.push({
          cx: right.x, cy: right.y,
          r: PHI_INV * (0.9 + ((bit2 >> 2) % 3) * 0.2),
          op: forkOrbOp, w: wAt(3),
        });
      }

      if (bit2 & 1 || bit3 & 1) {
        const len2 = len1 * PHI_INV * (0.85 + (bit2 / 20));
        for (const tipB of [left, right]) {
          const side = tipB === left ? -1 : 1;
          const end = {
            x: tipB.x + Math.cos(tipB.ang + side * PHI_INV) * len2,
            y: tipB.y + Math.sin(tipB.ang + side * PHI_INV) * len2,
          };
          branches.push({ x1: tipB.x, y1: tipB.y, x2: end.x, y2: end.y, op: br2Op, w: br2W });
          if (bit3 & 4) {
            orbs.push({ cx: end.x, cy: end.y, r: PHI_INV * 0.7, op: opAt(3), w: wAt(3) });
          }
        }
      }
      if (bit2 & 2) {
        const len2b = len1 * PHI_INV * (0.7 + structMix * 0.25);
        forkAt((r1 + r2) / 2, a, len2b, 2, (bit3 & 1) ? 1 : -1);
      }
    }

    if (bit3 & 2) {
      const lenIn = (r1 - r2) * (0.8 + (bit3 / 20) + radiusJitter * 0.1);
      forkAt(r2, a, lenIn, 1, -1);
      forkAt(r2, a, lenIn * PHI_INV, 1, 1);
    }

    const notchCount = 1 + (bit % 3);
    for (let t = 0; t < notchCount; t++) {
      const frac = PHI_INV * (0.45 + t * 0.22 + ((bit3 + t) % 5) * 0.02);
      const along = rCore + (R - rCore) * Math.min(0.92, frac);
      const p = pt(cx, cy, along, a);
      const perp = a + Math.PI / 2;
      const half = PHI_INV * (2.4 + (bit % 3) * 0.8 + (t === 0 ? 0.5 : 0));
      notches.push({
        x1: p.x - Math.cos(perp) * half,
        y1: p.y - Math.sin(perp) * half,
        x2: p.x + Math.cos(perp) * half,
        y2: p.y + Math.sin(perp) * half,
        op: notchOp, w: notchW,
      });
      if (bit2 & 4 && t === 0) {
        const p2 = pt(cx, cy, along + PHI_INV * 2, a);
        notches.push({
          x1: p2.x - Math.cos(perp) * (half * PHI_INV),
          y1: p2.y - Math.sin(perp) * (half * PHI_INV),
          x2: p2.x + Math.cos(perp) * (half * PHI_INV),
          y2: p2.y + Math.sin(perp) * (half * PHI_INV),
          op: opAt(3), w: wAt(3),
        });
      }
    }

    // ── Broken ripple-arcs (the pond) — frequent sectors, not full circles ──
    const inset = 0.06 + (bit % 3) * 0.02;
    const a0 = a + inset;
    const a1 = aNext - inset;

    // Soft weather on r1 / r2 / r3 — most sectors get at least one
    if (bit & 1 || nextBit & 1) {
      pushSectorArc(r1 * (1 + ((bit % 3) - 1) * 0.008), a0, a1, 1, false);
    }
    if (bit & 2 || nextBit & 2) {
      pushSectorArc(r2 * (1 + ((bit2 % 3) - 1) * 0.01), a0, a1, 2, false);
    }
    if (bit3 & 1 || (bit ^ nextBit) & 1) {
      pushSectorArc(r3 * (1 + ((bit3 % 3) - 1) * 0.012), a0, a1, 3, false);
    }

    // Brighter accent breaths (rarer) — still on φ radii
    if ((bit & 4) && (nextBit & 1)) {
      pushSectorArc(bit & 2 ? r1 : r2, a0 + 0.02, a1 - 0.02, bit & 2 ? 1 : 2, true);
    }

    // Soft tip curl — small arc past the rim between neighboring tips (organic, not a cage)
    if (bit3 & 1 || bit & 1) {
      const tip0 = pt(cx, cy, R * 0.96, a);
      const tip1 = pt(cx, cy, R * 0.96, aNext);
      const midA = (a + aNext) / 2;
      // Arc radius slightly larger than chord → gentle outward petal
      const chord = Math.hypot(tip1.x - tip0.x, tip1.y - tip0.y);
      const petalR = Math.max(chord * PHI_INV * 1.15, R * PHI_INV * PHI_INV);
      arcs.push({
        d: `M ${fmt(tip0)} A ${petalR.toFixed(2)},${petalR.toFixed(2)} 0 0 1 ${fmt(tip1)}`,
        op: opAt(1),
        w: wAt(2),
      });
      void midA;
    }
  }

  orbs.push({
    cx, cy,
    r: PHI_INV * (1.8 + ((seed >>> 7) % 5) * 0.15),
    op: coreOrbOp, w: wAt(1),
  });

  const hexAt = (radius: number) =>
    Array.from({ length: fold }, (_, i) => {
      const a = rot + (i * 2 * Math.PI) / fold;
      return fmt(pt(cx, cy, radius, a));
    }).join(' ');

  // Only whisper-faint full rings (inner) — the visible pond is the arcs above
  const rippleRadii = [r1, r2, r3];
  const ripples: Ripple[] = rippleRadii.map((r, i) => ({
    r,
    op: opAt(i + 2), // quieter: start at depth 2
    w: wAt(i + 3),
  }));

  return {
    R, r1, r2, r3, rCore,
    fold,
    habit: HABIT_LABEL[fold],
    figure: k != null ? `{${fold}/${k}} growth` : 'growth',
    figureId: 'growth' as const,
    veil,
    sacredPaths,
    spines,
    branches,
    notches,
    arcs,
    orbs,
    hexOuter: hexAt(R),
    hexMid: hexAt(r1),
    hexInner: hexAt(r2),
    hexCore: hexAt(r3),
    hexOp: opAt(3),
    hexW: wAt(3),
    coreOp: opAt(0),
    coreW: wAt(1),
    ripples,
    rings: [...rippleRadii, rCore, R * PHI_INV ** 4] as unknown as readonly [number, number, number, number, number],
  };
}

/** Lab-only: earlier 5-fold pentagram stack (kept for A/B). */
export function composeSigilSeal(fingerprint: string) {
  const n = hexNibbles(fingerprint);
  const seed = fnv(fingerprint);
  const cx = 50;
  const cy = 50;

  const R = 42 + (n[0] % 3);
  const r1 = R * PHI_INV;
  const r2 = R * PHI_INV * PHI_INV;
  const r3 = R * PHI_INV ** 3;
  const rCore = R * PHI_INV ** 4;

  const fold = 5;
  const rot = ((seed % 360) + (n[1] / 15) * 36) * (Math.PI / 180);

  const outer: { x: number; y: number }[] = [];
  const mid: { x: number; y: number }[] = [];
  const inner: { x: number; y: number }[] = [];
  for (let i = 0; i < fold; i++) {
    const a = rot + (i * 2 * Math.PI) / fold;
    outer.push(pt(cx, cy, R, a));
    mid.push(pt(cx, cy, r1, a));
    inner.push(pt(cx, cy, r2, a));
  }

  const blades: string[] = [];
  for (let i = 0; i < fold; i++) {
    const a = rot + (i * 2 * Math.PI) / fold;
    const tip = pt(cx, cy, R, a);
    const half = (Math.PI / fold) * PHI_INV * (0.85 + (n[i % n.length] / 15) * 0.3);
    const left = pt(cx, cy, r1, a - half);
    const right = pt(cx, cy, r1, a + half);
    blades.push(`M ${cx} ${cy} L ${left.x.toFixed(2)} ${left.y.toFixed(2)} L ${tip.x.toFixed(2)} ${tip.y.toFixed(2)} L ${right.x.toFixed(2)} ${right.y.toFixed(2)} Z`);
  }

  const chords: Line[] = [];
  for (let i = 0; i < fold; i++) {
    if (n[i] >= 4) {
      const a = outer[i];
      const b = outer[(i + 1) % fold];
      chords.push({ x1: a.x, y1: a.y, x2: b.x, y2: b.y, op: 0.35 + (n[i] % 4) * 0.05, w: 0.9 });
    }
    if (n[(i + 5) % n.length] >= 3) {
      const a = outer[i];
      const b = outer[(i + 2) % fold];
      chords.push({ x1: a.x, y1: a.y, x2: b.x, y2: b.y, op: 0.45 + (n[i] % 5) * 0.06, w: 1.05 });
    }
    chords.push({ x1: mid[i].x, y1: mid[i].y, x2: outer[i].x, y2: outer[i].y, op: 0.28, w: 0.7 });
    if (n[(i + 8) % n.length] >= 6) {
      const a = inner[i];
      const b = inner[(i + 2) % fold];
      chords.push({ x1: a.x, y1: a.y, x2: b.x, y2: b.y, op: 0.32, w: 0.65 });
    }
  }

  const ticks: { x1: number; y1: number; x2: number; y2: number; major: boolean }[] = [];
  for (let i = 0; i < 13; i++) {
    const a = rot + i * GOLDEN_ANGLE;
    const major = i % 3 === 0;
    const p0 = pt(cx, cy, major ? R - 3.5 : R - 2, a);
    const p1 = pt(cx, cy, R + 2.5, a);
    ticks.push({ x1: p0.x, y1: p0.y, x2: p1.x, y2: p1.y, major });
  }

  const dualRot = rot + Math.PI / fold;
  const dualPts = Array.from({ length: fold }, (_, i) => {
    const a = dualRot + (i * 2 * Math.PI) / fold;
    return fmt(pt(cx, cy, r1, a));
  }).join(' ');

  const corePent = Array.from({ length: fold }, (_, i) => {
    const a = rot + (i * 2 * Math.PI) / fold;
    return fmt(pt(cx, cy, r3, a));
  }).join(' ');

  return {
    R, r1, r2, r3, rCore, blades, chords, ticks, dualPts, corePent,
    facets: [] as string[],
    spines: [] as Line[],
    branches: [] as Line[],
    hexOuter: '',
    hexMid: dualPts,
    hexInner: '',
    hexCore: corePent,
    sacredPath: null as string | null,
    sacredPaths: [] as { d: string; op: number; w: number }[],
    figure: 'sigil',
    figureId: 'gon' as const,
    rings: [R, r1, r2] as const,
    fold,
  };
}

/** Earlier soft-petal draft — kept as a lab variant. */
export function composeRosetteSeal(fingerprint: string) {
  const n = hexNibbles(fingerprint);
  const seed = fnv(fingerprint);
  const cx = 50;
  const cy = 50;
  const petals: string[] = [];
  const arcs: { d: string; op: number }[] = [];
  const count = 7 + (n[0] % 2);
  for (let i = 0; i < count; i++) {
    const a0 = ((seed % 360) + i * (360 / count)) * (Math.PI / 180);
    const r1 = 14 + (n[i % n.length] % 6);
    const r2 = 26 + (n[(i + 3) % n.length] % 10);
    const r3 = 34 + (n[(i + 5) % n.length] % 6);
    const x1 = cx + Math.cos(a0) * r1;
    const y1 = cy + Math.sin(a0) * r1;
    const x2 = cx + Math.cos(a0 + 0.42) * r2;
    const y2 = cy + Math.sin(a0 + 0.42) * r2;
    const x3 = cx + Math.cos(a0 - 0.42) * r2;
    const y3 = cy + Math.sin(a0 - 0.42) * r2;
    const x4 = cx + Math.cos(a0) * r3;
    const y4 = cy + Math.sin(a0) * r3;
    petals.push(
      `M ${cx} ${cy} L ${x3.toFixed(1)} ${y3.toFixed(1)} Q ${x2.toFixed(1)} ${y2.toFixed(1)} ${x1.toFixed(1)} ${y1.toFixed(1)} Z`
    );
    arcs.push({
      d: `M ${x1.toFixed(1)} ${y1.toFixed(1)} Q ${x4.toFixed(1)} ${y4.toFixed(1)} ${(cx + Math.cos(a0 + 0.55) * r2).toFixed(1)} ${(cy + Math.sin(a0 + 0.55) * r2).toFixed(1)}`,
      op: 0.25 + (n[i % n.length] % 5) * 0.06,
    });
  }
  const ticks: { x1: number; y1: number; x2: number; y2: number; major: boolean }[] = [];
  for (let i = 0; i < 24; i++) {
    const a = (i / 24) * Math.PI * 2 + ((seed % 17) * 0.01);
    const outer = 44;
    const inner = i % 3 === 0 ? 39 : 41;
    ticks.push({
      x1: cx + Math.cos(a) * inner,
      y1: cy + Math.sin(a) * inner,
      x2: cx + Math.cos(a) * outer,
      y2: cy + Math.sin(a) * outer,
      major: i % 3 === 0,
    });
  }
  const ringR = 36 + (n[8] % 3);
  const hexR = 7 + (n[9] % 3);
  const hexPts = Array.from({ length: 6 }, (_, i) => {
    const a = Math.PI / 6 + (i * Math.PI) / 3 + ((n[10] % 8) * 0.02);
    return `${(cx + Math.cos(a) * hexR).toFixed(1)},${(cy + Math.sin(a) * hexR).toFixed(1)}`;
  }).join(' ');
  return {
    petals,
    arcs,
    ticks,
    ringR,
    core: 4 + (n[9] % 3),
    hexPts,
    rings: [ringR + 6, ringR, ringR - 5] as const,
  };
}

function GrowthLayers({ g }: { g: ReturnType<typeof composeGrowthSeal> }) {
  return (
    <>
      {/* φ pond ripples — opacity/weight from veil × φ⁻ᵈᵉᵖᵗʰ */}
      {g.ripples.map((ring, i) => (
        <circle
          key={`ring-${i}`}
          cx="50"
          cy="50"
          r={ring.r}
          fill="none"
          stroke={E.accent}
          strokeOpacity={ring.op}
          strokeWidth={ring.w}
        />
      ))}
      <polygon
        points={g.hexOuter}
        fill="none"
        stroke={E.accent}
        strokeOpacity={g.hexOp}
        strokeWidth={g.hexW}
      />
      <polygon
        points={g.hexMid}
        fill="none"
        stroke={E.accent}
        strokeOpacity={g.hexOp * PHI_INV}
        strokeWidth={g.hexW * PHI_INV}
      />

      {g.sacredPaths.map((p, i) => (
        <path
          key={`sg${i}`}
          d={p.d}
          fill="none"
          stroke={E.accent}
          strokeOpacity={p.op}
          strokeWidth={p.w}
          strokeLinejoin="miter"
        />
      ))}

      {g.arcs.map((a, i) => (
        <path
          key={`arc${i}`}
          d={a.d}
          fill="none"
          stroke={E.accent2}
          strokeOpacity={a.op}
          strokeWidth={a.w}
          strokeLinecap="round"
        />
      ))}

      {g.spines.map((c, i) => (
        <line key={`s${i}`} x1={c.x1} y1={c.y1} x2={c.x2} y2={c.y2} stroke={E.accent} strokeOpacity={c.op} strokeWidth={c.w} />
      ))}
      {g.branches.map((c, i) => (
        <line key={`br${i}`} x1={c.x1} y1={c.y1} x2={c.x2} y2={c.y2} stroke={E.accent} strokeOpacity={c.op} strokeWidth={c.w} />
      ))}
      {g.notches.map((c, i) => (
        <line key={`n${i}`} x1={c.x1} y1={c.y1} x2={c.x2} y2={c.y2} stroke={E.accent2} strokeOpacity={c.op} strokeWidth={c.w} />
      ))}

      {g.orbs.map((o, i) => (
        <circle
          key={`orb${i}`}
          cx={o.cx}
          cy={o.cy}
          r={o.r}
          fill="none"
          stroke={i === g.orbs.length - 1 ? E.accent : E.accent2}
          strokeOpacity={o.op}
          strokeWidth={o.w}
        />
      ))}

      <polygon
        points={g.hexCore}
        fill="none"
        stroke={E.accent}
        strokeOpacity={g.coreOp}
        strokeWidth={g.coreW}
      />
    </>
  );
}

function CrystalLayers({
  g,
  facets,
}: {
  g: ReturnType<typeof composePhiSeal>;
  facets: boolean;
}) {
  return (
    <>
      {/* Faint construction rings */}
      {g.rings.map((r, i) => (
        <circle
          key={`ring-${i}`}
          cx="50"
          cy="50"
          r={r}
          fill="none"
          stroke={E.accent2}
          strokeOpacity={0.12 - i * 0.02}
          strokeWidth={0.6}
        />
      ))}

      {/* N-gon crystal habit frames */}
      <polygon points={g.hexOuter} fill="none" stroke={E.accent} strokeOpacity="0.45" strokeWidth="1.05" />
      <polygon points={g.hexMid} fill="none" stroke={E.accent} strokeOpacity="0.32" strokeWidth="0.8" />
      <polygon points={g.hexInner} fill="none" stroke={E.accent2} strokeOpacity="0.22" strokeWidth="0.7" />

      {/* Sacred geometry figure */}
      {g.sacredPaths?.map((p, i) => (
        <path
          key={`sg${i}`}
          d={p.d}
          fill="none"
          stroke={E.accent}
          strokeOpacity={p.op}
          strokeWidth={p.w}
          strokeLinejoin="miter"
        />
      ))}

      {g.ticks.map((t, i) => (
        <line
          key={`t${i}`}
          x1={t.x1}
          y1={t.y1}
          x2={t.x2}
          y2={t.y2}
          stroke={E.accent}
          strokeOpacity={t.major ? 0.4 : 0.22}
          strokeWidth={t.major ? 1 : 0.5}
        />
      ))}

      {/* Spines + dendrites */}
      {g.spines.map((c, i) => (
        <line key={`s${i}`} x1={c.x1} y1={c.y1} x2={c.x2} y2={c.y2} stroke={E.accent} strokeOpacity={c.op} strokeWidth={c.w} />
      ))}
      {g.branches.map((c, i) => (
        <line key={`br${i}`} x1={c.x1} y1={c.y1} x2={c.x2} y2={c.y2} stroke={E.accent} strokeOpacity={c.op} strokeWidth={c.w} />
      ))}

      {facets &&
        g.facets.map((d, i) => (
          <path
            key={`f${i}`}
            d={d}
            fill="none"
            stroke={E.accent}
            strokeOpacity={0.55}
            strokeWidth="0.65"
          />
        ))}

      <polygon points={g.hexCore} fill="none" stroke={E.accent} strokeOpacity="0.8" strokeWidth="1.1" />
      <circle cx="50" cy="50" r={g.rCore} fill="none" stroke={E.accent} strokeWidth="1.05" />
      <circle cx="50" cy="50" r="1.8" fill="none" stroke={E.accent} strokeWidth="1" />
    </>
  );
}

function SigilLayers({ g }: { g: ReturnType<typeof composeSigilSeal> }) {
  return (
    <>
      {g.rings.map((r, i) => (
        <circle
          key={`ring-${i}`}
          cx="50"
          cy="50"
          r={r}
          fill="none"
          stroke={i === 0 ? E.accent : E.accent2}
          strokeOpacity={0.42 - i * 0.1}
          strokeWidth={i === 0 ? 1.15 : 0.75}
        />
      ))}
      {g.ticks.map((t, i) => (
        <line
          key={`t${i}`}
          x1={t.x1}
          y1={t.y1}
          x2={t.x2}
          y2={t.y2}
          stroke={E.accent}
          strokeOpacity={t.major ? 0.45 : 0.28}
          strokeWidth={t.major ? 1.1 : 0.55}
        />
      ))}
      {g.blades.map((d, i) => (
        <path
          key={`b${i}`}
          d={d}
          fill="none"
          stroke={E.accent}
          strokeOpacity={0.55}
          strokeWidth="0.7"
        />
      ))}
      {g.chords.map((c, i) => (
        <line key={`c${i}`} x1={c.x1} y1={c.y1} x2={c.x2} y2={c.y2} stroke={E.accent} strokeOpacity={c.op} strokeWidth={c.w} />
      ))}
      <polygon points={g.dualPts} fill="none" stroke={E.accent} strokeOpacity="0.4" strokeWidth="0.85" />
      <polygon points={g.corePent} fill="none" stroke={E.accent} strokeOpacity="0.75" strokeWidth="1.05" />
      <circle cx="50" cy="50" r={g.rCore} fill="none" stroke={E.accent} strokeWidth="1.1" />
      <circle cx="50" cy="50" r="1.8" fill="none" stroke={E.accent} strokeWidth="1" />
    </>
  );
}

function RingOnly({ g }: { g: ReturnType<typeof composePhiSeal> }) {
  return (
    <>
      <polygon points={g.hexOuter} fill="none" stroke={E.accent} strokeOpacity="0.4" strokeWidth="1" />
      <polygon points={g.hexMid} fill="none" stroke={E.accent} strokeOpacity="0.3" strokeWidth="0.8" />
      <polygon points={g.hexInner} fill="none" stroke={E.accent2} strokeOpacity="0.22" strokeWidth="0.7" />
      {g.ticks.map((t, i) => (
        <line
          key={`t${i}`}
          x1={t.x1}
          y1={t.y1}
          x2={t.x2}
          y2={t.y2}
          stroke={E.accent}
          strokeOpacity={t.major ? 0.4 : 0.22}
          strokeWidth={t.major ? 1 : 0.5}
        />
      ))}
      <polygon points={g.hexCore} fill="none" stroke={E.accent} strokeOpacity="0.8" strokeWidth="1.1" />
      <circle cx="50" cy="50" r={g.rCore} fill="none" stroke={E.accent} strokeWidth="1.05" />
      <circle cx="50" cy="50" r="1.8" fill="none" stroke={E.accent} strokeWidth="1" />
    </>
  );
}

function RosetteLayers({ g }: { g: ReturnType<typeof composeRosetteSeal> }) {
  return (
    <>
      {g.rings.map((r, i) => (
        <circle
          key={`ring-${i}`}
          cx="50"
          cy="50"
          r={r}
          fill="none"
          stroke={E.accent}
          strokeOpacity={0.22 + (i === 1 ? 0.23 : 0)}
          strokeWidth={i === 1 ? 1.2 : 0.8}
        />
      ))}
      {g.ticks.map((t, i) => (
        <line
          key={`t${i}`}
          x1={t.x1}
          y1={t.y1}
          x2={t.x2}
          y2={t.y2}
          stroke={E.accent}
          strokeOpacity={0.35}
          strokeWidth={t.major ? 1.1 : 0.6}
        />
      ))}
      {g.petals.map((d, i) => (
        <path
          key={`p${i}`}
          d={d}
          fill="none"
          stroke={E.accent}
          strokeOpacity={0.5}
          strokeWidth="0.65"
        />
      ))}
      {g.arcs.map((a, i) => (
        <path key={`a${i}`} d={a.d} fill="none" stroke={E.accent} strokeOpacity={a.op} strokeWidth="0.7" />
      ))}
      <polygon points={g.hexPts} fill="none" stroke={E.accent} strokeOpacity="0.7" strokeWidth="1" />
      <circle cx="50" cy="50" r={g.core} fill="none" stroke={E.accent} strokeWidth="1.2" />
      <circle cx="50" cy="50" r="2" fill="none" stroke={E.accent} strokeWidth="1" />
    </>
  );
}

export function IdentitySeal({
  fingerprint,
  size = 72,
  label,
  variant = 'growth',
}: {
  fingerprint: string;
  size?: number;
  label?: string;
  variant?: SealVariant;
}) {
  const crystal = useMemo(
    () =>
      variant === 'phi' || variant === 'lattice' || variant === 'ring'
        ? composePhiSeal(fingerprint)
        : null,
    [fingerprint, variant]
  );
  const growth = useMemo(
    () => (variant === 'growth' ? composeGrowthSeal(fingerprint) : null),
    [fingerprint, variant]
  );
  const sigil = useMemo(
    () => (variant === 'sigil' ? composeSigilSeal(fingerprint) : null),
    [fingerprint, variant]
  );
  const rosette = useMemo(
    () => (variant === 'rosette' ? composeRosetteSeal(fingerprint) : null),
    [fingerprint, variant]
  );

  return (
    <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 100 100"
        role="img"
        aria-label={label || `Identity seal (${variant})`}
        style={{ filter: variant === 'none' ? undefined : `drop-shadow(0 0 12px ${E.accent}40)` }}
      >
        {variant === 'none' && (
          <circle
            cx="50"
            cy="50"
            r="36"
            fill="none"
            stroke={E.dim}
            strokeOpacity="0.35"
            strokeWidth="1"
            strokeDasharray="3 4"
          />
        )}
        {variant === 'growth' && growth && <GrowthLayers g={growth} />}
        {variant === 'phi' && crystal && <CrystalLayers g={crystal} facets />}
        {variant === 'lattice' && crystal && <CrystalLayers g={crystal} facets={false} />}
        {variant === 'ring' && crystal && <RingOnly g={crystal} />}
        {variant === 'sigil' && sigil && <SigilLayers g={sigil} />}
        {variant === 'rosette' && rosette && <RosetteLayers g={rosette} />}
      </svg>
      {label && (
        <span style={{ fontSize: 10, letterSpacing: '0.14em', textTransform: 'uppercase', color: E.muted, fontFamily: E.fontMono }}>
          {label}
        </span>
      )}
    </div>
  );
}
