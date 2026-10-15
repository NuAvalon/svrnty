'use client';

/**
 * Vivre — the paper that burns.
 * Top-right corner, Ace-style: the sheet itself is eaten. Irregular torn
 * edge along the top-right, dark char crust, small flame licks on the ridge.
 * The hole is the mark — not a glow blob, not a filled sawtooth sticker.
 * Renders a witnessed inbound Distress mark. Not a badge.
 */

import { solarEmber as E } from '@/components/recovery/solar-ember';
import { DISTRESS_COPY } from '@/lib/trust/distress';
import { useId } from 'react';

/**
 * Organic torn bite, percent of the card (0–100).
 * Walks the TOP edge (Ace), then turns the right corner — not a diagonal saw.
 * Depths and spacing vary so it reads as fire-eaten paper.
 */
const BITE: ReadonlyArray<readonly [number, number]> = [
  [70.5, 0.0],
  [72.4, 2.8],
  [74.6, 0.3],
  [75.8, 3.6],
  [78.2, 0.7],
  [79.4, 4.4],
  [81.8, 1.0],
  [83.2, 2.4],
  [85.0, 0.2],
  [86.4, 5.0],
  [88.8, 1.4],
  [90.0, 3.2],
  [91.8, 0.5],
  [93.2, 4.6],
  [95.4, 1.2],
  [96.4, 5.8],
  [98.0, 2.4],
  [97.2, 8.6],
  [99.2, 10.4],
  [97.6, 13.2],
  [99.6, 15.0],
  [98.4, 17.8],
  [100, 16.6],
];

function pct([x, y]: readonly [number, number]): string {
  return `${x}% ${y}%`;
}

/** Clip the card so the top-right corner is gone. Other corners stay on the rect. */
export const VIVRE_PAPER_CLIP = `polygon(0% 0%, ${BITE.map(pct).join(', ')}, 100% 100%, 0% 100%)`;

function ridgePath(): string {
  return BITE.map(([x, y], i) => `${i === 0 ? 'M' : 'L'} ${x} ${y}`).join(' ');
}

function inward([x, y]: readonly [number, number], n = 1.6): [number, number] {
  const dx = 42 - x;
  const dy = 48 - y;
  const len = Math.hypot(dx, dy) || 1;
  return [x + (dx / len) * n, y + (dy / len) * n];
}

function charBandPath(): string {
  const inner = BITE.map((p) => inward(p));
  const start = BITE[0];
  const end = BITE[BITE.length - 1];
  return [
    `M ${start[0]} ${start[1]}`,
    ...BITE.slice(1).map(([x, y]) => `L ${x} ${y}`),
    `L ${end[0]} ${end[1] + 0.01}`,
    ...inner.reverse().map(([x, y]) => `L ${x} ${y}`),
    'Z',
  ].join(' ');
}

/** Small tongues on the char peaks. Secondary to the eaten paper. */
const FLAMES = [
  { x: 74.6, y: 0.3, w: 1.7, h: 4.2, delay: '0s', dur: '1.45s' },
  { x: 85.0, y: 0.2, w: 1.55, h: 3.8, delay: '0.22s', dur: '1.2s' },
  { x: 91.8, y: 0.5, w: 1.4, h: 3.4, delay: '0.48s', dur: '1.35s' },
] as const;

export function VivreBurn({ compact: _unusedCompact }: { compact?: boolean } = {}) {
  void _unusedCompact;
  const uid = useId().replace(/:/g, '');
  const crust = `vivre-crust-${uid}`;
  const ash = `vivre-ash-${uid}`;
  const flame = `vivre-flame-${uid}`;
  const ridge = ridgePath();
  return (
    <div
      aria-hidden
      data-testid="vivre-burn"
      data-ace-vivre="corner"
      style={{
        position: 'absolute',
        inset: 0,
        pointerEvents: 'none',
        zIndex: 6,
      }}
    >
      <style>{`
        @keyframes svrnty-vivre-lick {
          0%, 100% { transform: translateY(0) scaleY(1); opacity: 0.92; }
          40% { transform: translateY(-0.6px) scaleY(1.08); opacity: 1; }
          70% { transform: translateY(0.25px) scaleY(0.94); opacity: 0.85; }
        }
        @media (prefers-reduced-motion: reduce) {
          .svrnty-vivre-lick { animation: none !important; }
        }
      `}</style>
      <svg
        viewBox="0 0 100 100"
        width="100%"
        height="100%"
        preserveAspectRatio="none"
        overflow="visible"
        style={{ display: 'block', overflow: 'visible' }}
      >
        <defs>
          <linearGradient id={ash} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#0a0402" />
            <stop offset="55%" stopColor="#2a1008" />
            <stop offset="100%" stopColor="#4a1a0a" />
          </linearGradient>
          <linearGradient id={crust} x1="0%" y1="0%" x2="80%" y2="80%">
            <stop offset="0%" stopColor="#1a0804" />
            <stop offset="60%" stopColor="#5a220c" />
            <stop offset="100%" stopColor="#7a3010" />
          </linearGradient>
          <linearGradient id={flame} x1="50%" y1="100%" x2="50%" y2="0%">
            <stop offset="0%" stopColor="#6a1600" />
            <stop offset="45%" stopColor={E.accent2} />
            <stop offset="80%" stopColor={E.accent} />
            <stop offset="100%" stopColor="#fff4c8" />
          </linearGradient>
        </defs>

        {/* Scorched band on the remaining paper — the burn, not a fill of the hole. */}
        <path
          data-testid="vivre-paper-bite"
          d={charBandPath()}
          fill={`url(#${ash})`}
        />

        {/* Jagged char ridge along the torn edge. */}
        <path
          data-testid="vivre-char-ridge"
          d={ridge}
          fill="none"
          stroke={`url(#${crust})`}
          strokeWidth="3.4"
          strokeLinejoin="miter"
          strokeMiterlimit="10"
          strokeLinecap="butt"
          vectorEffect="non-scaling-stroke"
        />
        <path
          d={ridge}
          fill="none"
          stroke={E.accent2}
          strokeWidth="0.7"
          strokeLinejoin="miter"
          opacity="0.45"
          vectorEffect="non-scaling-stroke"
        />

        {FLAMES.map((f, i) => (
          <g
            key={i}
            className="svrnty-vivre-lick"
            style={{
              animation: `svrnty-vivre-lick ${f.dur} ease-in-out ${f.delay} infinite`,
              transformOrigin: `${f.x}px ${f.y + f.h}px`,
            }}
          >
            <path
              d={`M ${f.x} ${f.y + f.h * 0.35}
                  C ${f.x - f.w} ${f.y + f.h * 0.15}, ${f.x - f.w * 0.35} ${f.y - f.h * 0.15}, ${f.x} ${f.y - f.h * 0.55}
                  C ${f.x + f.w * 0.35} ${f.y - f.h * 0.15}, ${f.x + f.w} ${f.y + f.h * 0.15}, ${f.x} ${f.y + f.h * 0.35}
                  Z`}
              fill={`url(#${flame})`}
            />
          </g>
        ))}
      </svg>
    </div>
  );
}

export function StarEmber({ x, y, r }: { x: number; y: number; r: number }) {
  const uid = useId().replace(/:/g, '');
  const char = `star-char-${uid}`;
  const flame = `star-flame-${uid}`;
  return (
    <g data-testid="star-ember" data-ace-vivre="star" style={{ pointerEvents: 'none' }}>
      <style>{`
        @keyframes svrnty-star-lick {
          0%, 100% { transform: translateY(0) scaleY(1); }
          40% { transform: translateY(-1px) scaleY(1.08); }
          75% { transform: translateY(0.4px) scaleY(0.94); }
        }
        @media (prefers-reduced-motion: reduce) {
          .svrnty-star-lick { animation: none !important; }
        }
      `}</style>
      <defs>
        <linearGradient id={char} x1="50%" y1="0%" x2="50%" y2="100%">
          <stop offset="0%" stopColor="#090302" />
          <stop offset="70%" stopColor="#4a1608" />
          <stop offset="100%" stopColor="#2a1008" />
        </linearGradient>
        <linearGradient id={flame} x1="50%" y1="100%" x2="50%" y2="0%">
          <stop offset="0%" stopColor={E.accent2} />
          <stop offset="100%" stopColor="#fff4c8" />
        </linearGradient>
      </defs>
      <path
        d={`M ${x + r * 0.15} ${y - r * 0.95}
            L ${x + r * 0.42} ${y - r * 0.62}
            L ${x + r * 0.28} ${y - r * 0.48}
            L ${x + r * 0.7} ${y - r * 0.38}
            L ${x + r * 0.55} ${y - r * 0.12}
            L ${x + r * 0.95} ${y - r * 0.18}
            L ${x + r * 0.92} ${y + r * 0.05}`}
        fill="none"
        stroke={`url(#${char})`}
        strokeWidth={Math.max(1.8, r * 0.22)}
        strokeLinejoin="miter"
        strokeMiterlimit="8"
      />
      <path
        className="svrnty-star-lick"
        d={`M ${x + r * 0.55} ${y - r * 0.55}
            C ${x + r * 0.42} ${y - r * 0.85}, ${x + r * 0.5} ${y - r * 1.12}, ${x + r * 0.58} ${y - r * 1.22}
            C ${x + r * 0.66} ${y - r * 1.12}, ${x + r * 0.7} ${y - r * 0.85}, ${x + r * 0.55} ${y - r * 0.55}
            Z`}
        fill={`url(#${flame})`}
        style={{
          animation: 'svrnty-star-lick 1.4s ease-in-out infinite',
          transformOrigin: `${x + r * 0.55}px ${y - r * 0.55}px`,
        }}
      />
    </g>
  );
}

export function VivreCaution() {
  return (
    <p
      data-testid="vivre-caution"
      style={{
        margin: '10px 0 0',
        fontSize: 13,
        lineHeight: 1.5,
        color: E.accent2,
        fontFamily: E.fontSans,
      }}
    >
      {DISTRESS_COPY.caution}
    </p>
  );
}
