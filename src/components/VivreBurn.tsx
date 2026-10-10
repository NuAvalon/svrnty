'use client';

/**
 * Vivre — the paper that burns.
 * Top-right of a contact card, Ace-style: jagged char + licking flame.
 * Renders a witnessed inbound Distress mark. Not a badge. Not a send receipt.
 */

import { solarEmber as E } from '@/components/recovery/solar-ember';
import { DISTRESS_COPY } from '@/lib/trust/distress';
import { useId } from 'react';

export function VivreBurn({ compact }: { compact?: boolean }) {
  const uid = useId().replace(/:/g, '');
  const size = compact ? 56 : 120;
  const char = `vivre-char-${uid}`;
  const flame = `vivre-flame-${uid}`;
  const glow = `vivre-glow-${uid}`;
  return (
    <div
      aria-hidden
      data-testid="vivre-burn"
      style={{
        position: 'absolute',
        top: 0,
        right: 0,
        width: size,
        height: size,
        pointerEvents: 'none',
        zIndex: 3,
      }}
    >
      <style>{`
        @keyframes svrnty-vivre-lick {
          0%, 100% { opacity: 0.82; transform: translate(0, 0) scaleY(1); }
          35% { opacity: 1; transform: translate(-2px, -3px) scaleY(1.14); }
          65% { opacity: 0.78; transform: translate(1.5px, 1px) scaleY(0.9); }
        }
        @keyframes svrnty-vivre-lick-slow {
          0%, 100% { opacity: 0.58; transform: translate(0, 0) scale(1); }
          50% { opacity: 0.96; transform: translate(-3px, -4px) scale(1.1); }
        }
        @keyframes svrnty-vivre-spark {
          0% { opacity: 0; transform: translate(0, 0); }
          22% { opacity: 0.95; }
          100% { opacity: 0; transform: translate(-8px, -18px); }
        }
        @keyframes svrnty-vivre-glow {
          0%, 100% { opacity: 0.42; }
          50% { opacity: 0.88; }
        }
        @media (prefers-reduced-motion: reduce) {
          .svrnty-vivre-motion { animation: none !important; }
        }
      `}</style>
      <svg viewBox="0 0 120 120" width={size} height={size} style={{ display: 'block' }}>
        <defs>
          <linearGradient id={char} x1="100%" y1="0%" x2="18%" y2="88%">
            <stop offset="0%" stopColor="#0c0402" />
            <stop offset="22%" stopColor="#2a0c06" />
            <stop offset="48%" stopColor="#6a220a" />
            <stop offset="74%" stopColor={E.accent2} />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
          <radialGradient id={glow} cx="90%" cy="6%" r="62%">
            <stop offset="0%" stopColor="#fff6d0" />
            <stop offset="28%" stopColor={E.accent} />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>
          <linearGradient id={flame} x1="50%" y1="100%" x2="50%" y2="0%">
            <stop offset="0%" stopColor="#ff7a1a" />
            <stop offset="48%" stopColor="#f9a825" />
            <stop offset="100%" stopColor="#fff6d0" />
          </linearGradient>
        </defs>
        {/* Jagged char — paper eaten from the corner */}
        <path
          d="M120 0 L120 104 C108 94 102 88 94 78 C102 70 100 62 90 56 C100 46 108 34 104 22 C112 14 116 8 120 0 Z"
          fill={`url(#${char})`}
        />
        <path
          d="M120 0 L120 58 C110 44 104 26 120 0 Z"
          fill={`url(#${glow})`}
          className="svrnty-vivre-motion"
          style={{ animation: 'svrnty-vivre-glow 1.7s ease-in-out infinite' }}
        />
        {/* Burned paper edge */}
        <path
          d="M120 0 C108 22 100 40 90 56 C100 62 102 70 94 78 C86 70 78 62 68 52"
          fill="none"
          stroke="#140804"
          strokeWidth="2.4"
          strokeLinecap="round"
          opacity="0.62"
        />
        {/* Main flame tongue */}
        <path
          className="svrnty-vivre-motion"
          d="M118 6 C112 22 100 30 86 24 C96 14 106 6 116 2 C118 3 119 4 118 6 Z"
          fill={`url(#${flame})`}
          style={{ animation: 'svrnty-vivre-lick 1.1s ease-in-out infinite', transformOrigin: '110px 28px' }}
        />
        {/* Second tongue */}
        <path
          className="svrnty-vivre-motion"
          d="M102 8 C92 22 78 26 68 16 C80 10 92 4 102 8 Z"
          fill={E.accent2}
          opacity="0.92"
          style={{ animation: 'svrnty-vivre-lick-slow 1.5s ease-in-out infinite', transformOrigin: '90px 26px' }}
        />
        {/* Hot core */}
        <path
          d="M116 4 C112 12 106 16 100 12 C106 6 112 3 116 4 Z"
          fill="#fff8dc"
          opacity="0.94"
        />
        <circle
          className="svrnty-vivre-motion"
          cx="76"
          cy="14"
          r="1.7"
          fill="#fff3c4"
          style={{ animation: 'svrnty-vivre-spark 1.7s ease-out infinite' }}
        />
        <circle
          className="svrnty-vivre-motion"
          cx="92"
          cy="4"
          r="1.3"
          fill="#ffe08a"
          style={{ animation: 'svrnty-vivre-spark 2.1s ease-out 0.35s infinite' }}
        />
        <circle
          className="svrnty-vivre-motion"
          cx="84"
          cy="22"
          r="1.1"
          fill="#fff6d0"
          style={{ animation: 'svrnty-vivre-spark 1.9s ease-out 0.7s infinite' }}
        />
      </svg>
    </div>
  );
}

export function StarEmber({ x, y, r }: { x: number; y: number; r: number }) {
  const id = `ember-${Math.round(x)}-${Math.round(y)}`;
  return (
    <g data-testid="star-ember" style={{ pointerEvents: 'none' }}>
      <style>{`
        @keyframes svrnty-star-ember {
          0%, 100% { opacity: 0.55; }
          50% { opacity: 1; }
        }
        @media (prefers-reduced-motion: reduce) {
          .svrnty-star-ember { animation: none !important; }
        }
      `}</style>
      <defs>
        <radialGradient id={id} cx="50%" cy="40%" r="50%">
          <stop offset="0%" stopColor="#fff6d6" />
          <stop offset="40%" stopColor={E.accent} />
          <stop offset="100%" stopColor="transparent" />
        </radialGradient>
      </defs>
      <circle
        className="svrnty-star-ember"
        cx={x}
        cy={y - r * 0.15}
        r={r * 1.85}
        fill={`url(#${id})`}
        style={{ animation: 'svrnty-star-ember 1.6s ease-in-out infinite' }}
      />
      <circle cx={x} cy={y - r * 0.55} r={Math.max(2.2, r * 0.38)} fill={E.accent2} />
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
