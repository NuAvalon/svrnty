"use client";

/**
 * Inactive device-unlock chrome — not a button, not "on".
 * Shown only while isBiometricSeamLive() is false.
 */

import type { CSSProperties } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { DEVICE_UNLOCK_COMING_SOON } from './device-unlock-presentation';

export type DeviceUnlockComingSoonProps = {
  compact?: boolean;
};

const shell: CSSProperties = {
  width: '100%',
  borderRadius: 8,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  gap: 8,
  background: 'rgba(249, 168, 37, 0.03)',
  border: `1px dashed ${E.border}`,
  color: E.dim,
  fontFamily: E.fontSans,
  fontWeight: 500,
  letterSpacing: '1.5px',
  textTransform: 'uppercase',
  cursor: 'default',
  opacity: 0.72,
  pointerEvents: 'none',
  userSelect: 'none',
};

export function DeviceUnlockComingSoon({ compact }: DeviceUnlockComingSoonProps) {
  return (
    <div
      data-testid="device-unlock-coming-soon"
      role="status"
      aria-label={DEVICE_UNLOCK_COMING_SOON}
      style={{
        ...shell,
        marginTop: compact ? 0 : 12,
        padding: compact ? '10px 14px' : '14px 20px',
        fontSize: compact ? 11 : 12,
      }}
    >
      <svg
        width="16"
        height="16"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden
      >
        <path d="M12 11c1.66 0 3-1.2 3-2.67V6.67C15 5.2 13.66 4 12 4S9 5.2 9 6.67v1.66C9 9.8 10.34 11 12 11z" />
        <path d="M8 14.5c0 2.5 1.8 4.5 4 4.5s4-2 4-4.5" />
        <path d="M6 11.5c0 4.2 2.7 7.5 6 7.5" />
        <path d="M18 11.5c0 4.2-2.7 7.5-6 7.5" />
      </svg>
      {DEVICE_UNLOCK_COMING_SOON}
    </div>
  );
}
