'use client';

// Deterministic identity seal from fingerprint (I-6 render-provenance).
// Same fingerprint ⇒ same seal. Never Math.random / decorative noise.

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
    const count = 6 + (n[0] % 3); // 6–8 petals
    for (let i = 0; i < count; i++) {
      const a0 = ((seed % 360) + i * (360 / count)) * (Math.PI / 180);
      const r1 = 18 + (n[i % n.length] % 8);
      const r2 = 28 + (n[(i + 3) % n.length] % 12);
      const x1 = cx + Math.cos(a0) * r1;
      const y1 = cy + Math.sin(a0) * r1;
      const x2 = cx + Math.cos(a0 + 0.35) * r2;
      const y2 = cy + Math.sin(a0 + 0.35) * r2;
      const x3 = cx + Math.cos(a0 - 0.35) * r2;
      const y3 = cy + Math.sin(a0 - 0.35) * r2;
      petals.push(`M ${cx} ${cy} L ${x3.toFixed(1)} ${y3.toFixed(1)} Q ${x2.toFixed(1)} ${y2.toFixed(1)} ${x1.toFixed(1)} ${y1.toFixed(1)} Z`);
    }
    const ringR = 34 + (n[8] % 4);
    return { petals, ringR, core: 6 + (n[9] % 4) };
  }, [fingerprint]);

  return (
    <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <svg
        width={size}
        height={size}
        viewBox="0 0 100 100"
        role="img"
        aria-label={label || 'Identity seal'}
        style={{ filter: `drop-shadow(0 0 10px ${E.accent}33)` }}
      >
        <circle cx="50" cy="50" r={paths.ringR} fill="none" stroke={E.accent} strokeOpacity="0.35" strokeWidth="1.2" />
        <circle cx="50" cy="50" r={paths.ringR - 4} fill="none" stroke={E.accent2} strokeOpacity="0.2" strokeWidth="0.8" />
        {paths.petals.map((d, i) => (
          <path key={i} d={d} fill={E.accent} fillOpacity={0.12 + (i % 3) * 0.04} stroke={E.accent} strokeOpacity="0.55" strokeWidth="0.7" />
        ))}
        <circle cx="50" cy="50" r={paths.core} fill={E.bg} stroke={E.accent} strokeWidth="1.4" />
        <circle cx="50" cy="50" r="2.2" fill={E.accent} />
      </svg>
      {label && (
        <span style={{ fontSize: 10, letterSpacing: '0.14em', textTransform: 'uppercase', color: E.muted, fontFamily: E.fontMono }}>
          {label}
        </span>
      )}
    </div>
  );
}
