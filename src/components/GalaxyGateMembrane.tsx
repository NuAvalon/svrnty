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
        bottom: 6,
        transform: 'translateX(-50%)',
        zIndex: 8,
        width: 196,
        height: 64,
        padding: 0,
        border: 'none',
        background: 'transparent',
        cursor: 'pointer',
      }}
    >
      <svg viewBox="0 0 200 64" width="196" height="64" aria-hidden="true">
        {/* Arc = Gate (threshold, not a star) */}
        <path
          d="M 28 26 Q 100 2 172 26"
          fill="none"
          stroke={live ? E.accent : E.borderLit}
          strokeWidth={live ? 1.8 : 1.15}
          strokeDasharray={live ? '5 4' : '3 4'}
          strokeLinecap="round"
          style={
            live
              ? { animation: 'tm-pulse 1.8s ease-in-out infinite' }
              : undefined
          }
        />
        {/* U-bowl = known sphere rim */}
        <path
          d="M 46 20 Q 100 56 154 20"
          fill="color-mix(in srgb, var(--se-accent) 8%, transparent)"
          stroke={E.accent}
          strokeWidth={1.5}
          strokeLinecap="round"
        />
        <text
          x="100"
          y="38"
          textAnchor="middle"
          fill={E.accent}
          fontSize="9"
          letterSpacing="2.4"
          fontFamily="inherit"
        >
          GATE
        </text>
        {live ? (
          <text
            x="100"
            y="50"
            textAnchor="middle"
            fill={E.text}
            fontSize="11"
            fontFamily="inherit"
          >
            {count}
          </text>
        ) : null}
      </svg>
    </button>
  );
}
