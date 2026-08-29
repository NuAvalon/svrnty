'use client';

// Deterministic identity seals from fingerprint (I-6).
// Variants share the same fingerprint → different geometry grammars.
// Default production variant: `phi` (angular golden-ratio sigil).

import { useMemo } from 'react';
import { solarEmber as E } from '../recovery/solar-ember';

/** φ = (1 + √5) / 2 */
export const PHI = (1 + Math.sqrt(5)) / 2;
export const PHI_INV = PHI - 1;
export const GOLDEN_ANGLE = (2 * Math.PI) / (PHI * PHI);

export type SealVariant = 'phi' | 'rosette' | 'lattice' | 'ring' | 'none';

export const SEAL_VARIANTS: { id: SealVariant; title: string; blurb: string }[] = [
  { id: 'phi', title: 'φ sigil', blurb: 'Golden cascade · pentagram · angular blades' },
  { id: 'rosette', title: 'Rosette', blurb: 'Soft Bezier petals (earlier draft)' },
  { id: 'lattice', title: 'Lattice', blurb: 'φ rings + chords, no blades' },
  { id: 'ring', title: 'Ring', blurb: 'φ rings + ticks + core only' },
  { id: 'none', title: 'None', blurb: 'Empty mark — card without a seal' },
];

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

export function composePhiSeal(fingerprint: string) {
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

  const chords: { x1: number; y1: number; x2: number; y2: number; op: number; w: number }[] = [];
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
    chords.push({
      x1: mid[i].x, y1: mid[i].y, x2: outer[i].x, y2: outer[i].y,
      op: 0.28, w: 0.7,
    });
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
    rings: [R, r1, r2] as const,
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

function PhiLayers({
  g,
  blades,
}: {
  g: ReturnType<typeof composePhiSeal>;
  blades: boolean;
}) {
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
      {blades &&
        g.blades.map((d, i) => (
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
      <polygon points={g.dualPts} fill="none" stroke={E.accent} strokeOpacity="0.4" strokeWidth="0.85" />
      <polygon points={g.corePent} fill={E.bg} stroke={E.accent} strokeOpacity="0.75" strokeWidth="1.05" />
      <circle cx="50" cy="50" r={g.rCore} fill={E.bg} stroke={E.accent} strokeWidth="1.1" />
      <circle cx="50" cy="50" r="1.8" fill={E.accent} />
    </>
  );
}

function RingOnly({ g }: { g: ReturnType<typeof composePhiSeal> }) {
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
      <polygon points={g.corePent} fill={E.bg} stroke={E.accent} strokeOpacity="0.75" strokeWidth="1.05" />
      <circle cx="50" cy="50" r={g.rCore} fill={E.bg} stroke={E.accent} strokeWidth="1.1" />
      <circle cx="50" cy="50" r="1.8" fill={E.accent} />
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
          fill={E.accent}
          fillOpacity={0.08 + (i % 3) * 0.035}
          stroke={E.accent}
          strokeOpacity={0.5}
          strokeWidth="0.65"
        />
      ))}
      {g.arcs.map((a, i) => (
        <path key={`a${i}`} d={a.d} fill="none" stroke={E.accent} strokeOpacity={a.op} strokeWidth="0.7" />
      ))}
      <polygon points={g.hexPts} fill={E.bg} stroke={E.accent} strokeOpacity="0.7" strokeWidth="1" />
      <circle cx="50" cy="50" r={g.core} fill={E.bg} stroke={E.accent} strokeWidth="1.2" />
      <circle cx="50" cy="50" r="2" fill={E.accent} />
    </>
  );
}

export function IdentitySeal({
  fingerprint,
  size = 72,
  label,
  variant = 'phi',
}: {
  fingerprint: string;
  size?: number;
  label?: string;
  variant?: SealVariant;
}) {
  const phi = useMemo(
    () => (variant === 'rosette' || variant === 'none' ? null : composePhiSeal(fingerprint)),
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
        {variant === 'phi' && phi && <PhiLayers g={phi} blades />}
        {variant === 'lattice' && phi && <PhiLayers g={phi} blades={false} />}
        {variant === 'ring' && phi && <RingOnly g={phi} />}
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
