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
  const size = compact ? 80 : 176;
  const flameA = `vivre-fa-${uid}`;
  const flameB = `vivre-fb-${uid}`;
  const char = `vivre-char-${uid}`;
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
        filter: 'drop-shadow(0 0 10px rgba(255,122,26,0.55))',
      }}
    >
      <style>{`
        @keyframes svrnty-vivre-lick {
          0%, 100% { transform: translate(0, 0) scaleY(1); }
          40% { transform: translate(-2px, -4px) scaleY(1.1); }
          70% { transform: translate(1px, 1px) scaleY(0.94); }
        }
        @keyframes svrnty-vivre-lick-b {
          0%, 100% { transform: translate(0, 0) scale(1); }
          50% { transform: translate(-3px, -3px) scale(1.08); }
        }
        @keyframes svrnty-vivre-spark {
          0% { opacity: 0; transform: translate(0, 0); }
          18% { opacity: 1; }
          100% { opacity: 0; transform: translate(-12px, -20px); }
        }
        @media (prefers-reduced-motion: reduce) {
          .svrnty-vivre-motion { animation: none !important; }
        }
      `}</style>
      <svg viewBox="0 0 176 176" width={size} height={size} style={{ display: 'block', overflow: 'visible' }}>
        <defs>
          <linearGradient id={char} x1="100%" y1="0%" x2="20%" y2="80%">
            <stop offset="0%" stopColor="#140804" />
            <stop offset="35%" stopColor="#4a1608" />
            <stop offset="70%" stopColor="#8a2c0c" />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
          <linearGradient id={flameA} x1="90%" y1="80%" x2="10%" y2="10%">
            <stop offset="0%" stopColor="#c43a00" />
            <stop offset="35%" stopColor="#ff7a1a" />
            <stop offset="70%" stopColor="#f9a825" />
            <stop offset="100%" stopColor="#fff4c8" />
          </linearGradient>
          <linearGradient id={flameB} x1="80%" y1="100%" x2="20%" y2="0%">
            <stop offset="0%" stopColor="#ff4d00" />
            <stop offset="55%" stopColor="#f9a825" />
            <stop offset="100%" stopColor="#fff8dc" />
          </linearGradient>
        </defs>

        {/* Consumed paper */}
        <path
          d="M176 0 L176 88 C160 78 150 70 138 58 C148 48 146 38 134 32 C146 20 158 10 176 0 Z"
          fill={`url(#${char})`}
        />

        {/* Down-left tongue — reaches into the card, not just the radius */}
        <path
          className="svrnty-vivre-motion"
          d="M176 8
             C168 36 150 62 118 78
             C128 58 132 46 124 34
             C140 28 156 18 176 8 Z"
          fill={`url(#${flameB})`}
          stroke="#6a1600"
          strokeWidth="1.4"
          style={{ animation: 'svrnty-vivre-lick-b 1.4s ease-in-out infinite', transformOrigin: '156px 48px' }}
        />

        {/* Main leftward tongue along the top */}
        <path
          className="svrnty-vivre-motion"
          d="M176 0
             L176 42
             C158 54 132 58 92 44
             C84 40 86 26 100 16
             C116 6 140 0 176 0 Z"
          fill={`url(#${flameA})`}
          stroke="#7a1c00"
          strokeWidth="1.5"
          style={{ animation: 'svrnty-vivre-lick 1.1s ease-in-out infinite', transformOrigin: '150px 28px' }}
        />

        {/* Yellow inner */}
        <path
          className="svrnty-vivre-motion"
          d="M176 0 L176 26 C160 36 138 38 110 28 C106 22 112 14 126 8 C142 2 160 0 176 0 Z"
          fill="#ffe08a"
          style={{ animation: 'svrnty-vivre-lick 0.95s ease-in-out 0.12s infinite', transformOrigin: '154px 20px' }}
        />

        {/* White-hot core */}
        <path
          d="M176 0 L176 14 C166 20 150 20 136 14 C134 10 140 5 152 2 C162 0 170 0 176 0 Z"
          fill="#fffceb"
        />

        {/* Small third tongue */}
        <path
          className="svrnty-vivre-motion"
          d="M168 20 C156 38 140 46 122 40 C132 30 146 22 168 20 Z"
          fill="#ff7a1a"
          stroke="#6a1600"
          strokeWidth="1"
          style={{ animation: 'svrnty-vivre-lick-b 1.25s ease-in-out 0.2s infinite', transformOrigin: '150px 36px' }}
        />

        <circle
          className="svrnty-vivre-motion"
          cx="88"
          cy="20"
          r="2.4"
          fill="#fff3c4"
          style={{ animation: 'svrnty-vivre-spark 1.55s ease-out infinite' }}
        />
        <circle
          className="svrnty-vivre-motion"
          cx="108"
          cy="8"
          r="1.8"
          fill="#ffe08a"
          style={{ animation: 'svrnty-vivre-spark 1.9s ease-out 0.35s infinite' }}
        />
        <circle
          className="svrnty-vivre-motion"
          cx="100"
          cy="52"
          r="1.6"
          fill="#fff6d0"
          style={{ animation: 'svrnty-vivre-spark 1.7s ease-out 0.6s infinite' }}
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
