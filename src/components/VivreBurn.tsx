'use client';

/**
 * Vivre — the paper that burns.
 * Ace's card: the sheet itself is being eaten from the top edge.
 * Char ridge, then small flames sitting on that ridge. Not a badge.
 * Renders a witnessed inbound Distress mark.
 */

import { solarEmber as E } from '@/components/recovery/solar-ember';
import { DISTRESS_COPY } from '@/lib/trust/distress';
import { useId } from 'react';

const FLAMES = [
  { x: 26, y: 14, rx: 6, ry: 14, delay: '0s', dur: '1.35s' },
  { x: 74, y: 10, rx: 8, ry: 20, delay: '0.22s', dur: '1.55s' },
  { x: 146, y: 13, rx: 5.5, ry: 13, delay: '0.48s', dur: '1.2s' },
  { x: 212, y: 8, rx: 9, ry: 22, delay: '0.1s', dur: '1.7s' },
  { x: 284, y: 11, rx: 7, ry: 17, delay: '0.35s', dur: '1.4s' },
  { x: 350, y: 10, rx: 7.5, ry: 18, delay: '0.18s', dur: '1.5s' },
  { x: 386, y: 15, rx: 5, ry: 11, delay: '0.55s', dur: '1.25s' },
] as const;

export function VivreBurn({ compact }: { compact?: boolean }) {
  const uid = useId().replace(/:/g, '');
  const height = compact ? 48 : 72;
  const char = `vivre-char-${uid}`;
  const ridge = `vivre-ridge-${uid}`;
  const ember = `vivre-ember-${uid}`;
  const flame = `vivre-flame-${uid}`;
  return (
    <div
      aria-hidden
      data-testid="vivre-burn"
      data-ace-vivre="edge"
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        width: '100%',
        height,
        pointerEvents: 'none',
        zIndex: 6,
      }}
    >
      <style>{`
        @keyframes svrnty-vivre-lick {
          0%, 100% { opacity: 0.78; transform: translateY(0) scaleY(1); }
          35% { opacity: 1; transform: translateY(-1.6px) scaleY(1.08); }
          70% { opacity: 0.82; transform: translateY(0.6px) scaleY(0.94); }
        }
        @keyframes svrnty-vivre-glow {
          0%, 100% { opacity: 0.42; }
          50% { opacity: 0.78; }
        }
        @media (prefers-reduced-motion: reduce) {
          .svrnty-vivre-lick, .svrnty-vivre-glow { animation: none !important; }
        }
      `}</style>
      <svg
        viewBox="0 0 400 64"
        width="100%"
        height={height}
        preserveAspectRatio="none"
        style={{ display: 'block' }}
      >
        <defs>
          <linearGradient id={char} x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#140804" />
            <stop offset="38%" stopColor="#3a1608" />
            <stop offset="72%" stopColor="#6b2a0c" />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
          <linearGradient id={ridge} x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#1a0a06" />
            <stop offset="40%" stopColor="#5a220c" />
            <stop offset="100%" stopColor={E.accent2} />
          </linearGradient>
          <linearGradient id={ember} x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="#fff3c4" stopOpacity="0.85" />
            <stop offset="40%" stopColor={E.accent} stopOpacity="0.55" />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
          <linearGradient id={flame} x1="50%" y1="100%" x2="50%" y2="0%">
            <stop offset="0%" stopColor={E.accent2} />
            <stop offset="55%" stopColor={E.accent} />
            <stop offset="100%" stopColor="#fff6d6" />
          </linearGradient>
        </defs>
        {/* Paper eaten from the top — irregular Ace bite, not a corner wedge. */}
        <path
          data-testid="vivre-paper-bite"
          d="M0 0 H400 V18
             C388 22 378 10 368 16
             C356 24 346 8 332 14
             C318 22 308 6 292 12
             C274 20 262 7 248 13
             C232 22 220 5 204 11
             C188 20 176 6 160 14
             C144 24 130 8 116 15
             C100 24 88 7 72 13
             C56 22 42 8 28 16
             C16 22 8 10 0 18
             Z"
          fill={`url(#${char})`}
        />
        <path
          className="svrnty-vivre-glow"
          d="M0 0 H400 V14
             C370 20 340 6 310 12
             C280 20 250 5 220 12
             C190 20 160 6 130 13
             C100 22 70 6 40 14
             C22 18 8 8 0 14 Z"
          fill={`url(#${ember})`}
          style={{ animation: 'svrnty-vivre-glow 1.9s ease-in-out infinite' }}
        />
        {/* Char ridge — the brown/black crust along the eaten edge. */}
        <path
          d="M0 17
             C16 23 28 9 42 15
             C58 24 72 8 88 14
             C104 23 118 8 134 16
             C150 25 164 7 180 14
             C198 23 214 6 230 13
             C248 22 264 8 280 14
             C298 22 316 7 334 14
             C350 22 368 9 386 16
             C392 18 398 12 400 15"
          fill="none"
          stroke={`url(#${ridge})`}
          strokeWidth="3.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        {FLAMES.map((f, i) => (
          <g
            key={i}
            className="svrnty-vivre-lick"
            style={{
              animation: `svrnty-vivre-lick ${f.dur} ease-in-out ${f.delay} infinite`,
              transformOrigin: `${f.x}px ${f.y + f.ry}px`,
            }}
          >
            <ellipse cx={f.x} cy={f.y} rx={f.rx} ry={f.ry} fill={`url(#${flame})`} />
            <ellipse
              cx={f.x}
              cy={f.y + f.ry * 0.15}
              rx={f.rx * 0.42}
              ry={f.ry * 0.42}
              fill="#fff6d6"
              opacity="0.8"
            />
          </g>
        ))}
      </svg>
    </div>
  );
}

export function StarEmber({ x, y, r }: { x: number; y: number; r: number }) {
  const uid = useId().replace(/:/g, '');
  const glow = `star-ember-${uid}`;
  const flame = `star-flame-${uid}`;
  const tip = Math.max(3.2, r * 0.55);
  return (
    <g data-testid="star-ember" data-ace-vivre="star" style={{ pointerEvents: 'none' }}>
      <style>{`
        @keyframes svrnty-star-ember {
          0%, 100% { opacity: 0.6; }
          50% { opacity: 1; }
        }
        @keyframes svrnty-star-lick {
          0%, 100% { transform: translateY(0) scaleY(1); }
          40% { transform: translateY(-1px) scaleY(1.1); }
          75% { transform: translateY(0.4px) scaleY(0.92); }
        }
        @media (prefers-reduced-motion: reduce) {
          .svrnty-star-ember, .svrnty-star-lick { animation: none !important; }
        }
      `}</style>
      <defs>
        <radialGradient id={glow} cx="50%" cy="28%" r="55%">
          <stop offset="0%" stopColor="#fff6d6" />
          <stop offset="40%" stopColor={E.accent} />
          <stop offset="100%" stopColor="transparent" />
        </radialGradient>
        <linearGradient id={flame} x1="50%" y1="100%" x2="50%" y2="0%">
          <stop offset="0%" stopColor={E.accent2} />
          <stop offset="60%" stopColor={E.accent} />
          <stop offset="100%" stopColor="#fff6d6" />
        </linearGradient>
      </defs>
      <circle
        className="svrnty-star-ember"
        cx={x}
        cy={y - r * 0.2}
        r={r * 1.7}
        fill={`url(#${glow})`}
        style={{ animation: 'svrnty-star-ember 1.6s ease-in-out infinite' }}
      />
      <path
        d={`M ${x - r * 0.7} ${y - r * 0.55}
            Q ${x - r * 0.25} ${y - r * 0.15} ${x} ${y - r * 0.4}
            Q ${x + r * 0.28} ${y - r * 0.12} ${x + r * 0.72} ${y - r * 0.5}`}
        fill="none"
        stroke="#3a1608"
        strokeWidth={Math.max(1.4, r * 0.16)}
        strokeLinecap="round"
      />
      <ellipse
        className="svrnty-star-lick"
        cx={x}
        cy={y - r * 0.95}
        rx={tip * 0.42}
        ry={tip}
        fill={`url(#${flame})`}
        style={{
          animation: 'svrnty-star-lick 1.45s ease-in-out infinite',
          transformOrigin: `${x}px ${y - r * 0.55}px`,
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
