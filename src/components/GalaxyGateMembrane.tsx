'use client';

/**
 * Galaxy membrane: U-bowl = your known sphere, black-hole well = Gate.
 * Fixed to the map viewport (does not pan with the camera). Waiting people
 * are not stars — they live as sparks on the accretion disk until Admit.
 */

import { solarEmber as E } from '@/components/recovery/solar-ember';
import { GATE_COPY } from '@/lib/trust/grow-gate';

type Props = {
  count: number;
  onOpen: () => void;
};

const SPARK_MAX = 12;

function diskSparks(count: number): { x: number; y: number }[] {
  const n = Math.min(Math.max(0, count), SPARK_MAX);
  if (n === 0) return [];
  const out: { x: number; y: number }[] = [];
  for (let i = 0; i < n; i++) {
    const t = (i / n) * Math.PI * 2 - Math.PI / 2;
    out.push({
      x: 120 + 82 * Math.cos(t),
      y: 54 + 20 * Math.sin(t),
    });
  }
  return out;
}

export function GalaxyGateMembrane({ count, onOpen }: Props) {
  const live = count > 0;
  const sparks = diskSparks(count);
  return (
    <button
      type="button"
      data-testid="galaxy-gate"
      data-count={count}
      aria-label={live ? `Gate, ${count} waiting` : 'Gate'}
      title={GATE_COPY.sphereHint}
      onClick={(e) => {
        e.stopPropagation();
        onOpen();
      }}
      style={{
        position: 'absolute',
        left: '50%',
        bottom: 2,
        transform: 'translateX(-50%)',
        zIndex: 8,
        width: 248,
        height: 96,
        padding: 0,
        border: 'none',
        background: 'transparent',
        cursor: 'pointer',
      }}
    >
      <svg viewBox="0 0 240 96" width="248" height="96" aria-hidden="true">
        <defs>
          <radialGradient id="galaxy-gate-well" cx="50%" cy="42%" r="70%">
            <stop offset="0%" stopColor="#000000" />
            <stop offset="55%" stopColor="#070504" />
            <stop offset="100%" stopColor="#1a0e06" />
          </radialGradient>
          <radialGradient id="galaxy-gate-photon" cx="50%" cy="50%" r="50%">
            <stop offset="70%" stopColor="transparent" />
            <stop offset="100%" stopColor={live ? E.accent : E.borderLit} />
          </radialGradient>
        </defs>
        {/* Known-sphere rim — faint U behind the hole */}
        <path
          d="M 52 34 L 50 58 Q 120 90 190 58 L 188 34"
          fill="none"
          stroke={E.accent}
          strokeOpacity={0.35}
          strokeWidth={1.4}
          strokeLinecap="round"
        />
        {/* Event horizon well */}
        <ellipse cx="120" cy="62" rx="74" ry="28" fill="url(#galaxy-gate-well)" />
        <ellipse
          cx="120"
          cy="62"
          rx="74"
          ry="28"
          fill="url(#galaxy-gate-photon)"
          opacity={live ? 0.55 : 0.28}
        />
        <ellipse cx="120" cy="66" rx="36" ry="12" fill="#000000" />
        {/* Accretion disk = Gate threshold */}
        <ellipse
          cx="120"
          cy="54"
          rx="82"
          ry="20"
          fill="none"
          stroke={live ? E.accent : E.borderLit}
          strokeWidth={live ? 1.8 : 1.15}
          strokeDasharray={live ? '5 4' : '3 4'}
          strokeLinecap="round"
          style={live ? { animation: 'tm-pulse 1.8s ease-in-out infinite' } : undefined}
        />
        {sparks.map((p, i) => (
          <circle
            key={`spark-${i}`}
            data-testid="galaxy-gate-spark"
            cx={p.x}
            cy={p.y}
            r={2.2}
            fill={E.accent}
            opacity={0.55}
          />
        ))}
        <text
          x="120"
          y="18"
          textAnchor="middle"
          fill={live ? E.accent : E.muted}
          fontSize="9"
          letterSpacing="2.8"
          fontFamily="inherit"
        >
          GATE
        </text>
      </svg>
    </button>
  );
}
