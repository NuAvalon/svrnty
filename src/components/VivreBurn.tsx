'use client';

/**
 * Vivre — the paper that burns.
 * Top-right corner, Ace-style: jagged char eating the sheet.
 * The burnt paper is the mark. Small flame licks sit on the ridge — not embers.
 * Renders a witnessed inbound Distress mark. Not a badge.
 */

import { solarEmber as E } from '@/components/recovery/solar-ember';
import { DISTRESS_COPY } from '@/lib/trust/distress';
import { useId } from 'react';

/** Small tongues on the char peaks. Secondary to the burnt paper. */
const FLAMES = [
  { x: 168, y: 18, w: 7, h: 16, delay: '0s', dur: '1.45s' },
  { x: 132, y: 36, w: 6, h: 13, delay: '0.28s', dur: '1.2s' },
  { x: 188, y: 52, w: 5.5, h: 12, delay: '0.5s', dur: '1.35s' },
] as const;

export function VivreBurn({ compact }: { compact?: boolean }) {
  const uid = useId().replace(/:/g, '');
  const w = compact ? 96 : 168;
  const h = compact ? 84 : 148;
  const char = `vivre-char-${uid}`;
  const crust = `vivre-crust-${uid}`;
  const flame = `vivre-flame-${uid}`;
  return (
    <div
      aria-hidden
      data-testid="vivre-burn"
      data-ace-vivre="corner"
      style={{
        position: 'absolute',
        top: 0,
        right: 0,
        width: w,
        height: h,
        pointerEvents: 'none',
        zIndex: 6,
      }}
    >
      <style>{`
        @keyframes svrnty-vivre-lick {
          0%, 100% { transform: translateY(0) scaleY(1); opacity: 0.9; }
          40% { transform: translateY(-1.4px) scaleY(1.08); opacity: 1; }
          70% { transform: translateY(0.5px) scaleY(0.94); opacity: 0.85; }
        }
        @media (prefers-reduced-motion: reduce) {
          .svrnty-vivre-lick { animation: none !important; }
        }
      `}</style>
      <svg
        viewBox="0 0 200 180"
        width={w}
        height={h}
        preserveAspectRatio="xMaxYMin meet"
        style={{ display: 'block' }}
      >
        <defs>
          <linearGradient id={char} x1="100%" y1="0%" x2="20%" y2="85%">
            <stop offset="0%" stopColor="#090302" />
            <stop offset="28%" stopColor="#1a0804" />
            <stop offset="58%" stopColor="#3a1408" />
            <stop offset="82%" stopColor="#6a240c" />
            <stop offset="100%" stopColor="#2a1008" />
          </linearGradient>
          <linearGradient id={crust} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#0d0502" />
            <stop offset="45%" stopColor="#4a1a08" />
            <stop offset="100%" stopColor="#7a2c0c" />
          </linearGradient>
          <linearGradient id={flame} x1="50%" y1="100%" x2="50%" y2="0%">
            <stop offset="0%" stopColor="#8a2200" />
            <stop offset="40%" stopColor={E.accent2} />
            <stop offset="78%" stopColor={E.accent} />
            <stop offset="100%" stopColor="#fff4c8" />
          </linearGradient>
        </defs>

        {/* Consumed paper — jagged Ace bite in the top-right, not a smooth wedge. */}
        <path
          data-testid="vivre-paper-bite"
          d="M200 0
             L200 168
             L188 154 L176 162 L168 140
             L154 152 L148 128 L132 142
             L124 114 L108 130 L102 104
             L86 118 L80 90 L64 106
             L58 78 L42 92 L36 64
             L22 76 L16 48 L6 58
             L2 28 L0 34 L0 0
             Z"
          fill={`url(#${char})`}
        />

        {/* Deeper char pits — the paper is gone, not glowing. */}
        <path
          d="M200 0 L200 88 L176 70 L164 92 L148 58 L200 0 Z"
          fill="#050201"
          opacity="0.72"
        />
        <path
          d="M200 70 L200 140 L178 122 L166 138 L154 108 L176 92 Z"
          fill="#120804"
          opacity="0.55"
        />

        {/* Jagged char ridge — brown-black crust along the eaten edge. */}
        <path
          data-testid="vivre-char-ridge"
          d="M200 168
             L188 154 L176 162 L168 140
             L154 152 L148 128 L132 142
             L124 114 L108 130 L102 104
             L86 118 L80 90 L64 106
             L58 78 L42 92 L36 64
             L22 76 L16 48 L6 58
             L2 28 L0 34"
          fill="none"
          stroke={`url(#${crust})`}
          strokeWidth="5.5"
          strokeLinejoin="miter"
          strokeMiterlimit="8"
          strokeLinecap="butt"
        />
        {/* Hairline heat on the ridge only — not a glow blob. */}
        <path
          d="M198 164
             L188 154 L176 162 L168 140
             L154 152 L148 128 L132 142
             L124 114 L108 130 L102 104
             L86 118 L80 90 L64 106
             L58 78 L42 92 L36 64
             L22 76 L16 48 L6 58
             L2 28"
          fill="none"
          stroke={E.accent2}
          strokeWidth="1.15"
          strokeLinejoin="miter"
          opacity="0.7"
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
              d={`M ${f.x} ${f.y + f.h}
                  C ${f.x - f.w} ${f.y + f.h * 0.45}, ${f.x - f.w * 0.45} ${f.y + f.h * 0.12}, ${f.x} ${f.y}
                  C ${f.x + f.w * 0.45} ${f.y + f.h * 0.12}, ${f.x + f.w} ${f.y + f.h * 0.45}, ${f.x} ${f.y + f.h}
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
          <stop offset="100%" stopColor="transparent" />
        </linearGradient>
        <linearGradient id={flame} x1="50%" y1="100%" x2="50%" y2="0%">
          <stop offset="0%" stopColor={E.accent2} />
          <stop offset="100%" stopColor="#fff4c8" />
        </linearGradient>
      </defs>
      <path
        d={`M ${x - r * 0.85} ${y - r * 0.15}
            L ${x - r * 0.4} ${y - r * 0.55}
            L ${x - r * 0.15} ${y - r * 0.25}
            L ${x + r * 0.1} ${y - r * 0.62}
            L ${x + r * 0.35} ${y - r * 0.28}
            L ${x + r * 0.7} ${y - r * 0.5}
            L ${x + r * 0.9} ${y - r * 0.12}`}
        fill="none"
        stroke="#2a1008"
        strokeWidth={Math.max(1.6, r * 0.2)}
        strokeLinejoin="miter"
      />
      <path
        className="svrnty-star-lick"
        d={`M ${x} ${y - r * 0.35}
            C ${x - r * 0.22} ${y - r * 0.7}, ${x - r * 0.08} ${y - r * 1.05}, ${x} ${y - r * 1.2}
            C ${x + r * 0.08} ${y - r * 1.05}, ${x + r * 0.22} ${y - r * 0.7}, ${x} ${y - r * 0.35}
            Z`}
        fill={`url(#${flame})`}
        style={{
          animation: 'svrnty-star-lick 1.4s ease-in-out infinite',
          transformOrigin: `${x}px ${y - r * 0.35}px`,
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
