'use client';

/**
 * Vivre — the paper that burns.
 * Top-right corner of a contact card. Ember in a Galaxy star.
 * Renders a witnessed inbound Distress mark. Not a badge.
 */

import { solarEmber as E } from '@/components/recovery/solar-ember';
import { DISTRESS_COPY } from '@/lib/trust/distress';
import { useId } from 'react';

export function VivreBurn({ compact }: { compact?: boolean }) {
  const uid = useId().replace(/:/g, '');
  const size = compact ? 56 : 96;
  const char = `vivre-char-${uid}`;
  const ember = `vivre-ember-${uid}`;
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
        zIndex: 2,
      }}
    >
      <style>{`
        @keyframes svrnty-vivre-lick {
          0%, 100% { opacity: 0.72; transform: translate(0, 0) scale(1); }
          40% { opacity: 1; transform: translate(-1px, 2px) scale(1.04); }
          70% { opacity: 0.8; transform: translate(1px, -1px) scale(0.98); }
        }
        @keyframes svrnty-vivre-glow {
          0%, 100% { opacity: 0.35; }
          50% { opacity: 0.7; }
        }
      `}</style>
      <svg viewBox="0 0 96 96" width={size} height={size} style={{ display: 'block' }}>
        <defs>
          <linearGradient id={char} x1="100%" y1="0%" x2="30%" y2="80%">
            <stop offset="0%" stopColor="#1a0804" />
            <stop offset="45%" stopColor="#4a1c08" />
            <stop offset="78%" stopColor={E.accent2} />
            <stop offset="100%" stopColor="transparent" />
          </linearGradient>
          <radialGradient id={ember} cx="82%" cy="12%" r="55%">
            <stop offset="0%" stopColor="#fff3c4" />
            <stop offset="35%" stopColor={E.accent} />
            <stop offset="100%" stopColor="transparent" />
          </radialGradient>
        </defs>
        <path
          d="M96 0 L96 78 Q72 62 58 48 Q80 28 96 0 Z"
          fill={`url(#${char})`}
        />
        <path
          d="M96 0 L96 42 Q88 22 96 0 Z"
          fill={`url(#${ember})`}
          style={{ animation: 'svrnty-vivre-glow 1.8s ease-in-out infinite' }}
        />
        <ellipse
          cx="88"
          cy="10"
          rx="7"
          ry="11"
          fill={E.accent}
          style={{ animation: 'svrnty-vivre-lick 1.4s ease-in-out infinite', transformOrigin: '88px 18px' }}
        />
        <ellipse cx="90" cy="6" rx="3.5" ry="5" fill="#fff6d6" opacity="0.85" />
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
      `}</style>
      <defs>
        <radialGradient id={id} cx="50%" cy="40%" r="50%">
          <stop offset="0%" stopColor="#fff6d6" />
          <stop offset="40%" stopColor={E.accent} />
          <stop offset="100%" stopColor="transparent" />
        </radialGradient>
      </defs>
      <circle
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
