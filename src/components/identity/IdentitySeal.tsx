'use client';

// Deterministic identity seal from fingerprint (I-6 render-provenance).
// Same fingerprint ⇒ same seal. Never Math.random / decorative noise.
// Geometry leans toward Archie's sovereign-card rosette: concentric rings + lattice petals.

import { useMemo } from 'react';
import { solarEmber as E } from '../recovery/solar-ember';

function hexNibbles(fingerprint: string): number[] {
  const hex = fingerprint.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  const out: number[] = [];
  for (let i = 0; i < Math.min(hex.length, 32); i++) {
    out.push(parseInt(hex[i], 16));
  }
  while (out.length < 16) out.push(0);
  return out;
}

/** Simple FNV-1a over fingerprint for stable angles. */
function fnv(fp: string): number {
  let h = 2166136261;
  for (let i = 0; i < fp.length; i++) {
    h ^= fp.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
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
  const paths = useMemo(() => {
    const n = hexNibbles(fingerprint);
    const seed = fnv(fingerprint);
    const cx = 50;
    const cy = 50;
    const petals: string[] = [];
    const arcs: { d: string; op: number }[] = [];
    const count = 7 + (n[0] % 2); // 7–8 petals
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
    const ticks: { x1: number; y1: number; x2: number; y2: number }[] = [];
    const tickCount = 24;
    for (let i = 0; i < tickCount; i++) {
      const a = (i / tickCount) * Math.PI * 2 + ((seed % 17) * 0.01);
      const outer = 44;
      const inner = i % 3 === 0 ? 39 : 41;
      ticks.push({
        x1: cx + Math.cos(a) * inner,
        y1: cy + Math.sin(a) * inner,
        x2: cx + Math.cos(a) * outer,
        y2: cy + Math.sin(a) * outer,
      });
    }
    const ringR = 36 + (n[8] % 3);
    const hexR = 7 + (n[9] % 3);
    const hexPts = Array.from({ length: 6 }, (_, i) => {
      const a = (Math.PI / 6) + (i * Math.PI) / 3 + ((n[10] % 8) * 0.02);
      return `${(cx + Math.cos(a) * hexR).toFixed(1)},${(cy + Math.sin(a) * hexR).toFixed(1)}`;
    }).join(' ');
    return { petals, arcs, ticks, ringR, core: 4 + (n[9] % 3), hexPts };
  }, [fingerprint]);

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
        <circle cx="50" cy="50" r={paths.ringR + 6} fill="none" stroke={E.accent} strokeOpacity="0.22" strokeWidth="0.9" />
        <circle cx="50" cy="50" r={paths.ringR} fill="none" stroke={E.accent} strokeOpacity="0.45" strokeWidth="1.2" />
        <circle cx="50" cy="50" r={paths.ringR - 5} fill="none" stroke={E.accent2} strokeOpacity="0.18" strokeWidth="0.7" />
        {paths.ticks.map((t, i) => (
          <line
            key={`t${i}`}
            x1={t.x1}
            y1={t.y1}
            x2={t.x2}
            y2={t.y2}
            stroke={E.accent}
            strokeOpacity={0.35}
            strokeWidth={i % 3 === 0 ? 1.1 : 0.6}
          />
        ))}
        {paths.petals.map((d, i) => (
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
        {paths.arcs.map((a, i) => (
          <path key={`a${i}`} d={a.d} fill="none" stroke={E.accent} strokeOpacity={a.op} strokeWidth="0.7" />
        ))}
        <polygon
          points={paths.hexPts}
          fill={E.bg}
          stroke={E.accent}
          strokeOpacity="0.7"
          strokeWidth="1"
        />
        <circle cx="50" cy="50" r={paths.core} fill={E.bg} stroke={E.accent} strokeWidth="1.2" />
        <circle cx="50" cy="50" r="2" fill={E.accent} />
      </svg>
      {label && (
        <span style={{ fontSize: 10, letterSpacing: '0.14em', textTransform: 'uppercase', color: E.muted, fontFamily: E.fontMono }}>
          {label}
        </span>
      )}
    </div>
  );
}
