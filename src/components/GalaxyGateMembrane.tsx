'use client';

/**
 * Galaxy membrane: U-bowl = your known sphere, black-hole well = Gate.
 * Fixed to the map viewport (does not pan with the camera). Waiting people
 * are not stars — they live at the event horizon until Admit.
 * New arrivals spark into the well (animate-in), then settle as a count.
 */

import { solarEmber as E } from '@/components/recovery/solar-ember';
import { GATE_COPY } from '@/lib/trust/grow-gate';
import { hash32 } from '@/lib/trust/graph-forces';

type Props = {
  count: number;
  /** Fingerprints that just landed — spark once, then fade into the count. */
  sparkIds?: string[];
  onOpen: () => void;
};

function sparkPos(id: string, i: number): { cx: number; cy: number } {
  const h = hash32(id || String(i));
  const slot = ((h % 1000) / 1000 - 0.5) * 88;
  return { cx: 120 + slot, cy: 36 + ((h >> 8) % 10) };
}

export function GalaxyGateMembrane({ count, sparkIds = [], onOpen }: Props) {
  const live = count > 0;
  return (
    <button
      type="button"
      data-testid="galaxy-gate"
      data-count={count}
      data-sparks={sparkIds.length}
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
        <style>{`
          @keyframes tm-gate-spark {
            0% { opacity: 0; transform: translateY(-22px) scale(.15); }
            32% { opacity: 1; transform: translateY(2px) scale(1.2); }
            100% { opacity: .25; transform: translateY(18px) scale(.45); }
          }
          @media (prefers-reduced-motion: reduce) {
            .tm-gate-spark { animation: none; opacity: 0.7; }
          }
        `}</style>
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
        {sparkIds.map((id, i) => {
          const p = sparkPos(id, i);
          return (
            <g
              key={id}
              className="tm-gate-spark"
              data-testid="galaxy-gate-spark"
              style={{
                animation: 'tm-gate-spark 1.5s cubic-bezier(.16,1,.3,1) both',
                animationDelay: `${i * 0.08}s`,
                transformBox: 'fill-box',
                transformOrigin: 'center',
              }}
            >
              <circle cx={p.cx} cy={p.cy} r={5.5} fill="#fff8ee" opacity={0.22} />
              <circle cx={p.cx} cy={p.cy} r={2.4} fill="#fffef8" />
            </g>
          );
        })}
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
        {live ? (
          <text
            x="120"
            y="58"
            textAnchor="middle"
            fill={E.text}
            fontSize="12"
            fontFamily="inherit"
          >
            {count}
          </text>
        ) : null}
      </svg>
    </button>
  );
}
