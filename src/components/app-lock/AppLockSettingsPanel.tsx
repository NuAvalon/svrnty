'use client';

import { solarEmber as E } from '@/components/recovery/solar-ember';
import {
  type AppLockPrefs,
  IDLE_TIMEOUT_OPTIONS,
  appLockStatusLine,
} from './app-lock-prefs';

type Props = {
  prefs: AppLockPrefs;
  onChange: (next: AppLockPrefs) => void;
  onLockNow?: () => void;
};

/**
 * Signal-model lock settings — idle timeout + lock-on-hide.
 * Prefs are localStorage only; locking still goes through fleet `lockSession`.
 */
export function AppLockSettingsPanel({ prefs, onChange, onLockNow }: Props) {
  return (
    <section
      data-testid="app-lock-settings"
      aria-label="App lock"
      style={{
        marginTop: 16,
        padding: '16px 18px',
        background: E.surface,
        border: `1px solid ${E.border}`,
        borderRadius: 12,
        backdropFilter: 'blur(16px)',
        WebkitBackdropFilter: 'blur(16px)',
        maxWidth: 420,
        marginLeft: 'auto',
        marginRight: 'auto',
        textAlign: 'left' as const,
      }}
    >
      <h3
        style={{
          margin: '0 0 4px',
          fontFamily: E.fontSans,
          fontSize: 13,
          fontWeight: 600,
          letterSpacing: '0.08em',
          textTransform: 'uppercase' as const,
          color: E.accent,
        }}
      >
        App lock
      </h3>
      <p
        style={{
          margin: '0 0 14px',
          fontFamily: E.fontSans,
          fontSize: 12,
          lineHeight: 1.45,
          color: E.muted,
        }}
      >
        Like Signal: lock clears keys from this tab&apos;s memory. Unlock again with
        your passphrase
        {/* Biometric path lands with CUR-6 — do not claim it here until live. */}
        . Nothing about lock timing leaves this device.
      </p>

      <label
        style={{
          display: 'block',
          fontFamily: E.fontSans,
          fontSize: 11,
          letterSpacing: '0.06em',
          textTransform: 'uppercase' as const,
          color: E.dim,
          marginBottom: 6,
        }}
      >
        Idle auto-lock
      </label>
      <select
        data-testid="app-lock-idle-select"
        value={prefs.idleTimeoutMinutes}
        onChange={(e) =>
          onChange({
            ...prefs,
            idleTimeoutMinutes: Number(e.target.value) as AppLockPrefs['idleTimeoutMinutes'],
          })
        }
        style={{
          width: '100%',
          background: E.inputBg,
          border: `1px solid ${E.border}`,
          borderRadius: 8,
          padding: '10px 12px',
          color: E.text,
          fontFamily: E.fontSans,
          fontSize: 13,
          marginBottom: 12,
          outline: 'none',
        }}
      >
        {IDLE_TIMEOUT_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>

      <label
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 10,
          cursor: 'pointer',
          marginBottom: 12,
        }}
      >
        <input
          data-testid="app-lock-on-hide"
          type="checkbox"
          checked={prefs.lockOnHide}
          onChange={(e) => onChange({ ...prefs, lockOnHide: e.target.checked })}
          style={{ marginTop: 2, accentColor: E.accent }}
        />
        <span style={{ fontFamily: E.fontSans, fontSize: 13, color: E.text, lineHeight: 1.4 }}>
          Lock when I leave this tab
          <span style={{ display: 'block', fontSize: 11, color: E.dim, marginTop: 2 }}>
            Fires on tab hide / background — same idea as Signal&apos;s screen lock.
          </span>
        </span>
      </label>

      <p
        style={{
          margin: '0 0 12px',
          fontFamily: E.fontSans,
          fontSize: 11,
          color: E.dim,
          lineHeight: 1.4,
        }}
      >
        {appLockStatusLine(prefs)}
      </p>

      {onLockNow && (
        <button
          type="button"
          data-testid="app-lock-settings-lock-now"
          onClick={onLockNow}
          style={{
            width: '100%',
            background: 'rgba(249, 168, 37, 0.08)',
            border: `1px solid ${E.borderLit}`,
            borderRadius: 8,
            padding: '10px 14px',
            color: E.accent,
            fontFamily: E.fontSans,
            fontSize: 12,
            fontWeight: 500,
            letterSpacing: '0.08em',
            textTransform: 'uppercase' as const,
            cursor: 'pointer',
          }}
        >
          Lock now
        </button>
      )}
    </section>
  );
}
