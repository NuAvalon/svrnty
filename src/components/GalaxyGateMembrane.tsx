'use client';

/**
 * Galaxy membrane: U-bowl = your known sphere, arc above = Gate.
 * Fixed to the map viewport (does not pan with the camera). Waiting people
 * are not stars — they live behind this arc until Admit.
 */

import { solarEmber as E } from '@/components/recovery/solar-ember';
import { GATE_COPY } from '@/lib/trust/grow-gate';

type Props = {
  count: number;
  onOpen: () => void;
};

export function GalaxyGateMembrane({ count, onOpen }: Props) {
  const live = count > 0;
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
        bottom: 4,
        transform: 'translateX(-50%)',
        zIndex: 8,
        width: 228,
        height: 78,
        padding: 0,
        border: 'none',
        background: 'transparent',
        cursor: 'pointer',
      }}
    >
      <svg viewBox="0 0 220 78" width="220" height="78" aria-hidden="true">
        {/* Arc = Gate (threshold, not a star) */}
        <path
          d="M 22 32 Q 110 4 198 32"
          fill="none"
          stroke={live ? E.accent : E.borderLit}
          strokeWidth={live ? 1.9 : 1.2}
          strokeDasharray={live ? '5 4' : '3 4'}
          strokeLinecap="round"
          style={
            live
              ? { animation: 'tm-pulse 1.8s ease-in-out infinite' }
              : undefined
          }
        />
        <text
          x="110"
          y="18"
          textAnchor="middle"
          fill={live ? E.accent : E.muted}
          fontSize="9"
          letterSpacing="2.6"
          fontFamily="inherit"
        >
          GATE
        </text>
        {live ? (
          <text
            x="110"
            y="30"
            textAnchor="middle"
            fill={E.text}
            fontSize="11"
            fontFamily="inherit"
          >
            {count}
          </text>
        ) : null}
        {/* U-bowl = known sphere rim — vertical stems, not a smile */}
        <path
          d="M 64 20 L 62 44 Q 110 72 158 44 L 156 20"
          fill="color-mix(in srgb, var(--se-accent) 10%, transparent)"
          stroke={E.accent}
          strokeWidth={1.7}
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </button>
  );
}
