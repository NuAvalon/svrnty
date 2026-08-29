'use client';

// Deterministic identity seal from fingerprint (I-6 render-provenance).
// Same fingerprint ⇒ same seal. Never Math.random / decorative noise.
//
// Geometry grammar: φ (golden ratio). Concentric rings at R · φ⁻ⁿ,
// 5-fold (pentagon/pentagram) lattice, angular chords — a sigil, not a soft rosette.
// Fingerprint nibbles only choose rotation, which chords light, and blade emphasis.

import { useMemo } from 'react';
import { solarEmber as E } from '../recovery/solar-ember';

/** φ = (1 + √5) / 2 */
export const PHI = (1 + Math.sqrt(5)) / 2;
/** 1/φ = φ − 1 */
export const PHI_INV = PHI - 1;
/** Golden angle (radians) ≈ 137.508° = 2π / φ² */
export const GOLDEN_ANGLE = (2 * Math.PI) / (PHI * PHI);

function hexNibbles(fingerprint: string): number[] {
  const hex = fingerprint.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  const out: number[] = [];
  for (let i = 0; i < Math.min(hex.length, 32); i++) {
    out.push(parseInt(hex[i], 16));
  }
  while (out.length < 16) out.push(0);
  return out;
}

/** FNV-1a over fingerprint for stable rotation. */
function fnv(fp: string): number {
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

/**
 * Pure geometry builder — exported for determinism tests.
 * Rings / skips / blades are φ-scaled; fingerprint only modulates.
 */
export function composePhiSeal(fingerprint: string) {
  const n = hexNibbles(fingerprint);
  const seed = fnv(fingerprint);
  const cx = 50;
  const cy = 50;

  // Base outer radius; tiny fingerprint jitter stays inside φ cascade.
  const R = 42 + (n[0] % 3); // 42–44
  const r1 = R * PHI_INV; // ≈ 0.618 R
  const r2 = R * PHI_INV * PHI_INV; // ≈ 0.382 R
  const r3 = R * PHI_INV ** 3; // ≈ 0.236 R
  const rCore = R * PHI_INV ** 4; // ≈ 0.146 R

  // 5-fold is φ’s native symmetry; rotation from fingerprint.
  const fold = 5;
  const rot = ((seed % 360) + (n[1] / 15) * 36) * (Math.PI / 180); // 36° = π/5 step family

  const outer: { x: number; y: number }[] = [];
  const mid: { x: number; y: number }[] = [];
  const inner: { x: number; y: number }[] = [];
  for (let i = 0; i < fold; i++) {
    const a = rot + (i * 2 * Math.PI) / fold;
    outer.push(pt(cx, cy, R, a));
    mid.push(pt(cx, cy, r1, a));
    inner.push(pt(cx, cy, r2, a));
  }

  // Angular blades: straight wedges center → R/φ shoulders → outer tip at R
  const blades: string[] = [];
  for (let i = 0; i < fold; i++) {
    const a = rot + (i * 2 * Math.PI) / fold;
    const tip = pt(cx, cy, R, a);
    // Half-gap: π/5 scaled by φ⁻¹ so shoulders sit in golden proportion to the sector
    const half = (Math.PI / fold) * PHI_INV * (0.85 + (n[i % n.length] / 15) * 0.3);
    const left = pt(cx, cy, r1, a - half);
    const right = pt(cx, cy, r1, a + half);
    blades.push(`M ${cx} ${cy} L ${left.x.toFixed(2)} ${left.y.toFixed(2)} L ${tip.x.toFixed(2)} ${tip.y.toFixed(2)} L ${right.x.toFixed(2)} ${right.y.toFixed(2)} Z`);
  }

  // Chord lattice: pentagon edges + pentagram diagonals (skip 2), gated by nibbles
  const chords: { x1: number; y1: number; x2: number; y2: number; op: number; w: number }[] = [];
  for (let i = 0; i < fold; i++) {
    // Outer pentagon
    if (n[i] >= 4) {
      const a = outer[i];
      const b = outer[(i + 1) % fold];
      chords.push({ x1: a.x, y1: a.y, x2: b.x, y2: b.y, op: 0.35 + (n[i] % 4) * 0.05, w: 0.9 });
    }
    // Pentagram (skip 2) — φ’s diagonal
    if (n[(i + 5) % n.length] >= 3) {
      const a = outer[i];
      const b = outer[(i + 2) % fold];
      chords.push({ x1: a.x, y1: a.y, x2: b.x, y2: b.y, op: 0.45 + (n[i] % 5) * 0.06, w: 1.05 });
    }
    // Mid↔outer radial
    chords.push({
      x1: mid[i].x, y1: mid[i].y, x2: outer[i].x, y2: outer[i].y,
      op: 0.28, w: 0.7,
    });
    // Inner pentagram, thinner
    if (n[(i + 8) % n.length] >= 6) {
      const a = inner[i];
      const b = inner[(i + 2) % fold];
      chords.push({ x1: a.x, y1: a.y, x2: b.x, y2: b.y, op: 0.32, w: 0.65 });
    }
  }

  // Fibonacci tick count (13) around outer ring; major every φ-step feel (every 3rd ≈ fib)
  const ticks: { x1: number; y1: number; x2: number; y2: number; major: boolean }[] = [];
  const tickCount = 13; // F₇
  for (let i = 0; i < tickCount; i++) {
    const a = rot + i * GOLDEN_ANGLE;
    const major = i % 3 === 0;
    const outerT = R + 2.5;
    const innerT = major ? R - 3.5 : R - 2;
    const p0 = pt(cx, cy, innerT, a);
    const p1 = pt(cx, cy, outerT, a);
    ticks.push({ x1: p0.x, y1: p0.y, x2: p1.x, y2: p1.y, major });
  }

  // Dual pentagon (rotated 180/5) at mid radius — angular frame
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
    R,
    r1,
    r2,
    r3,
    rCore,
    blades,
    chords,
    ticks,
    dualPts,
    corePent,
    rings: [R, r1, r2] as const,
  };
}

export function IdentitySeal({
  fingerprint,
  size = 72,
  label,
}: {
  fingerprint: string;
  size?: number;
  label?: string;
}) {
  const g = useMemo(() => composePhiSeal(fingerprint), [fingerprint]);

  return (
    <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 100 100"
        role="img"
        aria-label={label || 'Identity seal'}
        style={{ filter: `drop-shadow(0 0 12px ${E.accent}40)` }}
      >
        {/* φ-cascade rings */}
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

        {/* Fibonacci / golden-angle ticks */}
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

        {/* Angular φ-blades */}
        {g.blades.map((d, i) => (
          <path
            key={`b${i}`}
            d={d}
            fill={E.accent}
            fillOpacity={0.07 + (i % 3) * 0.03}
            stroke={E.accent}
            strokeOpacity={0.55}
            strokeWidth="0.7"
          />
        ))}

        {/* Chord / pentagram lattice */}
        {g.chords.map((c, i) => (
          <line
            key={`c${i}`}
            x1={c.x1}
            y1={c.y1}
            x2={c.x2}
            y2={c.y2}
            stroke={E.accent}
            strokeOpacity={c.op}
            strokeWidth={c.w}
          />
        ))}

        {/* Dual pentagon at R/φ */}
        <polygon
          points={g.dualPts}
          fill="none"
          stroke={E.accent}
          strokeOpacity="0.4"
          strokeWidth="0.85"
        />

        {/* Core pentagon at R/φ³ */}
        <polygon
          points={g.corePent}
          fill={E.bg}
          stroke={E.accent}
          strokeOpacity="0.75"
          strokeWidth="1.05"
        />
        <circle cx="50" cy="50" r={g.rCore} fill={E.bg} stroke={E.accent} strokeWidth="1.1" />
        <circle cx="50" cy="50" r="1.8" fill={E.accent} />
      </svg>
      {label && (
        <span style={{ fontSize: 10, letterSpacing: '0.14em', textTransform: 'uppercase', color: E.muted, fontFamily: E.fontMono }}>
          {label}
        </span>
      )}
    </div>
  );
}
