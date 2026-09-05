"use client";

/**
 * CUR-6 — settings panel: enable / disable device unlock (passkey UX).
 * Enrollment calls fleet `enrollBiometric` (PRF wrap = Flint). Glass never invents wrap.
 */

import { useEffect, useState, type CSSProperties } from 'react';
import { solarEmber as E } from '@/components/recovery/solar-ember';
import { DeviceUnlockComingSoon } from './DeviceUnlockComingSoon';
import { settingsDeviceUnlockLook } from './device-unlock-presentation';
import {
  biometricStatusLine,
  disableBiometric,
  enrollBiometric,
  getBiometricEnrollment,
  isBiometricSeamLive,
  probeBiometricCapability,
  readEnrollPreference,
  writeEnrollPreference,
  type BiometricCapability,
  type BiometricEnrollmentState,
} from './biometric-seam';

export type BiometricSettingsPanelProps = {
  fingerprint: string;
  /** Compact embed under Set Passphrase / identity tools. */
  compact?: boolean;
};

const inputStyle: CSSProperties = {
  width: '100%',
  background: E.inputBg,
  border: `1px solid ${E.border}`,
  borderRadius: 8,
  padding: '12px 14px',
  color: E.text,
  fontSize: 14,
  fontFamily: E.fontSans,
  outline: 'none',
  marginBottom: 8,
  boxSizing: 'border-box',
};

export function BiometricSettingsPanel({
  fingerprint,
  compact,
}: BiometricSettingsPanelProps) {
  const [capability, setCapability] = useState<BiometricCapability | null>(null);
  const [enrollment, setEnrollment] = useState<BiometricEnrollmentState>({
    enrolled: false,
  });
  const [wantEnable, setWantEnable] = useState(false);
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const seamLive = isBiometricSeamLive();

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const cap = await probeBiometricCapability();
      const enr = await getBiometricEnrollment(fingerprint);
      if (cancelled) return;
      setCapability(cap);
      setEnrollment(enr);
      setWantEnable(readEnrollPreference(fingerprint) || enr.enrolled);
    })();
    return () => {
      cancelled = true;
    };
  }, [fingerprint]);

  const status =
    capability == null
      ? 'Checking this device…'
      : biometricStatusLine({ capability, enrollment, seamLive });

  const look = settingsDeviceUnlockLook({
    seamLive,
    enrolled: enrollment.enrolled,
    capabilityAvailable: capability?.status === 'available',
  });

  const handleEnable = async () => {
    setError(null);
    setMessage(null);
    if (!passphrase || passphrase.length < 12) {
      setError('Confirm your unlock passphrase (min 12 characters) to enable device unlock.');
      return;
    }
    setBusy(true);
    try {
      writeEnrollPreference(fingerprint, true);
      setWantEnable(true);
      const result = await enrollBiometric({ fingerprint, passphrase });
      if (result.ok) {
        setEnrollment({
          enrolled: true,
          credentialIdHint: result.credentialIdHint,
          enrolledAt: new Date().toISOString(),
        });
        setPassphrase('');
        setMessage('Device unlock is on for this identity on this device.');
        return;
      }
      setError(
        result.message ||
          (result.reason === 'stub-not-live'
            ? 'Device unlock is not live yet — passphrase remains your unlock.'
            : 'Could not enable device unlock.')
      );
    } catch {
      setError('Could not enable device unlock.');
    } finally {
      setBusy(false);
    }
  };

  const handleDisable = async () => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await disableBiometric(fingerprint);
      setEnrollment({ enrolled: false });
      setWantEnable(false);
      setPassphrase('');
      setMessage('Device unlock turned off. Passphrase unlock is unchanged.');
    } catch {
      setError('Could not turn off device unlock.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section
      data-testid="biometric-settings"
      aria-label="Device unlock"
      style={{
        marginTop: compact ? 16 : 24,
        padding: compact ? '14px 16px' : '18px 20px',
        background: E.surface,
        border: `1px solid ${E.border}`,
        borderRadius: 12,
        backdropFilter: 'blur(16px)',
        maxWidth: 420,
        marginLeft: 'auto',
        marginRight: 'auto',
        textAlign: 'left',
      }}
    >
      <h3
        style={{
          margin: '0 0 6px',
          fontFamily: E.fontSans,
          fontSize: 13,
          fontWeight: 600,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          color: E.accent,
        }}
      >
        Device unlock
      </h3>
      <p
        style={{
          margin: '0 0 12px',
          fontFamily: E.fontSans,
          fontSize: 13,
          lineHeight: 1.45,
          color: E.muted,
        }}
      >
        {status}
      </p>
      <p
        style={{
          margin: '0 0 14px',
          fontFamily: E.fontSans,
          fontSize: 11,
          lineHeight: 1.4,
          color: E.dim,
        }}
      >
        Keys stay on this device. Device unlock never sends your passphrase or keys to a server.
      </p>

      {look === 'disable' ? (
        <button
          type="button"
          data-testid="biometric-disable-btn"
          disabled={busy}
          onClick={handleDisable}
          style={{
            width: '100%',
            background: 'transparent',
            border: `1px solid ${E.border}`,
            borderRadius: 8,
            padding: '10px 14px',
            color: E.muted,
            fontSize: 12,
            fontFamily: E.fontSans,
            letterSpacing: '1px',
            cursor: busy ? 'default' : 'pointer',
          }}
        >
          Turn off device unlock
        </button>
      ) : look === 'coming-soon' ? (
        <DeviceUnlockComingSoon compact />
      ) : look === 'enable' ? (
        <>
          {!wantEnable ? (
            <button
              type="button"
              data-testid="biometric-enable-start"
              disabled={busy}
              onClick={() => setWantEnable(true)}
              style={{
                width: '100%',
                background: 'rgba(249, 168, 37, 0.1)',
                border: `1px solid ${E.borderLit}`,
                borderRadius: 8,
                padding: '12px 14px',
                color: E.accent,
                fontSize: 12,
                fontFamily: E.fontSans,
                letterSpacing: '1.5px',
                textTransform: 'uppercase',
                cursor: 'pointer',
              }}
            >
              Enable device unlock
            </button>
          ) : (
            <div>
              <label
                htmlFor="biometric-enroll-passphrase"
                style={{
                  display: 'block',
                  fontFamily: E.fontSans,
                  fontSize: 11,
                  color: E.dim,
                  marginBottom: 6,
                  letterSpacing: '0.04em',
                }}
              >
                Confirm unlock passphrase
              </label>
              <input
                id="biometric-enroll-passphrase"
                data-testid="biometric-enroll-passphrase"
                type="password"
                autoComplete="current-password"
                placeholder="Unlock passphrase"
                value={passphrase}
                onChange={(e) => {
                  setPassphrase(e.target.value);
                  setError(null);
                }}
                style={inputStyle}
              />
              <button
                type="button"
                data-testid="biometric-enroll-confirm"
                disabled={busy || !passphrase}
                onClick={handleEnable}
                style={{
                  width: '100%',
                  background: passphrase
                    ? 'rgba(249, 168, 37, 0.14)'
                    : 'rgba(249, 168, 37, 0.04)',
                  border: `1px solid ${passphrase ? E.borderLit : E.border}`,
                  borderRadius: 8,
                  padding: '12px 14px',
                  color: passphrase ? E.accent : E.dim,
                  fontSize: 12,
                  fontFamily: E.fontSans,
                  letterSpacing: '1.5px',
                  textTransform: 'uppercase',
                  cursor: passphrase ? 'pointer' : 'default',
                  marginTop: 4,
                }}
              >
                {busy ? 'Working…' : 'Confirm & enable'}
              </button>
              <button
                type="button"
                onClick={() => {
                  setWantEnable(false);
                  setPassphrase('');
                  setError(null);
                  writeEnrollPreference(fingerprint, false);
                }}
                style={{
                  width: '100%',
                  background: 'none',
                  border: 'none',
                  color: E.dim,
                  fontSize: 12,
                  fontFamily: E.fontSans,
                  marginTop: 8,
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
            </div>
          )}
        </>
      ) : null}

      {error && (
        <p
          role="alert"
          style={{
            marginTop: 10,
            fontFamily: E.fontSans,
            fontSize: 12,
            color: E.danger,
          }}
        >
          {error}
        </p>
      )}
      {message && !error && (
        <p
          style={{
            marginTop: 10,
            fontFamily: E.fontSans,
            fontSize: 12,
            color: E.ok,
          }}
        >
          {message}
        </p>
      )}
    </section>
  );
}
