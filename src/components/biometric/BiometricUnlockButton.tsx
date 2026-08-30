"use client";

/**
 * CUR-6 — lock-screen "Unlock with device" control.
 * Calls fleet `unlockWithBiometric`; never derives keys in the glass.
 */

import { useState, type CSSProperties } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  unlockWithBiometric,
  type UnlockWithBiometricResult,
} from './biometric-seam';

export type BiometricUnlockButtonProps = {
  fingerprint: string;
  /** When false, button is hidden (capability probe or not opted-in). */
  visible: boolean;
  disabled?: boolean;
  /** Called only after fleet seam returns ok:true (session key ready). */
  onUnlocked: () => void | Promise<void>;
  /** Optional: surface stub/error so passphrase form stays primary. */
  onFallbackMessage?: (message: string) => void;
};

const btnBase: CSSProperties = {
  width: '100%',
  borderRadius: '8px',
  padding: '14px 20px',
  fontSize: '12px',
  fontWeight: 500,
  fontFamily: E.fontSans,
  letterSpacing: '2px',
  textTransform: 'uppercase',
  cursor: 'pointer',
  marginTop: '12px',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  gap: 8,
};

export function BiometricUnlockButton({
  fingerprint,
  visible,
  disabled,
  onUnlocked,
  onFallbackMessage,
}: BiometricUnlockButtonProps) {
  const [busy, setBusy] = useState(false);

  if (!visible) return null;

  const handleClick = async () => {
    if (busy || disabled) return;
    setBusy(true);
    try {
      const result: UnlockWithBiometricResult = await unlockWithBiometric(fingerprint);
      if (result.ok) {
        await onUnlocked();
        return;
      }
      const msg =
        result.message ||
        (result.reason === 'stub-not-live'
          ? 'Device unlock is not live yet. Enter your passphrase to unlock.'
          : result.reason === 'cancelled'
            ? 'Device unlock cancelled.'
            : 'Device unlock failed. Enter your passphrase.');
      onFallbackMessage?.(msg);
    } catch {
      onFallbackMessage?.('Device unlock failed. Enter your passphrase.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <button
      type="button"
      data-testid="biometric-unlock-btn"
      onClick={handleClick}
      disabled={busy || disabled}
      aria-label="Unlock with device"
      style={{
        ...btnBase,
        background: 'rgba(249, 168, 37, 0.08)',
        border: `1px solid ${E.borderLit}`,
        color: E.accent,
        opacity: busy || disabled ? 0.55 : 1,
        cursor: busy || disabled ? 'default' : 'pointer',
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
      {busy ? 'Checking device…' : 'Unlock with device'}
    </button>
  );
}
