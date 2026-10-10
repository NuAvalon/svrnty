/**
 * CUR-7 · P0.5 app-lock preferences — UI-only (localStorage).
 *
 * ⛔ PRF / wrapping-key unwrap = Flint (CUR-6 seam). This module never
 * derives keys, stores wrap material, or touches session crypto.
 * Locking calls fleet `lockSession()` from the shell; unlock stays
 * `initSessionKey(passphrase)` (and biometric when CUR-6 is live).
 */

export const APP_LOCK_PREFS_KEY = 'svrnty.app-lock';

/** Minutes of inactivity before auto-lock. `0` = idle auto-lock off. */
export type IdleTimeoutMinutes = 0 | 1 | 5 | 15 | 30 | 60;

export type AppLockPrefs = {
  idleTimeoutMinutes: IdleTimeoutMinutes;
  /** Lock when the tab/app is hidden (Signal-model "lock when leaving"). */
  lockOnHide: boolean;
};

export const DEFAULT_APP_LOCK_PREFS: AppLockPrefs = {
  idleTimeoutMinutes: 0,
  lockOnHide: false,
};

export const IDLE_TIMEOUT_OPTIONS: ReadonlyArray<{
  value: IdleTimeoutMinutes;
  label: string;
}> = [
  { value: 0, label: 'Off' },
  { value: 1, label: '1 minute' },
  { value: 5, label: '5 minutes' },
  { value: 15, label: '15 minutes' },
  { value: 30, label: '30 minutes' },
  { value: 60, label: '1 hour' },
];

const VALID_IDLE = new Set<IdleTimeoutMinutes>([0, 1, 5, 15, 30, 60]);

export function parseAppLockPrefs(raw: string | null): AppLockPrefs {
  if (!raw) return { ...DEFAULT_APP_LOCK_PREFS };
  try {
    const parsed = JSON.parse(raw) as Partial<AppLockPrefs>;
    const idle = parsed.idleTimeoutMinutes;
    const idleTimeoutMinutes =
      typeof idle === 'number' && VALID_IDLE.has(idle as IdleTimeoutMinutes)
        ? (idle as IdleTimeoutMinutes)
        : DEFAULT_APP_LOCK_PREFS.idleTimeoutMinutes;
    const lockOnHide =
      typeof parsed.lockOnHide === 'boolean'
        ? parsed.lockOnHide
        : DEFAULT_APP_LOCK_PREFS.lockOnHide;
    return { idleTimeoutMinutes, lockOnHide };
  } catch {
    return { ...DEFAULT_APP_LOCK_PREFS };
  }
}

export function readAppLockPrefs(): AppLockPrefs {
  if (typeof localStorage === 'undefined') return { ...DEFAULT_APP_LOCK_PREFS };
  try {
    return parseAppLockPrefs(localStorage.getItem(APP_LOCK_PREFS_KEY));
  } catch {
    return { ...DEFAULT_APP_LOCK_PREFS };
  }
}

export function writeAppLockPrefs(prefs: AppLockPrefs): void {
  if (typeof localStorage === 'undefined') return;
  try {
    localStorage.setItem(APP_LOCK_PREFS_KEY, JSON.stringify(prefs));
  } catch {
    /* ignore quota / private mode */
  }
}

/** Claim-honest one-liner for the settings panel. */
export function appLockStatusLine(prefs: AppLockPrefs): string {
  const parts: string[] = [];
  if (prefs.idleTimeoutMinutes === 0) {
    parts.push('Idle auto-lock is off');
  } else {
    const opt = IDLE_TIMEOUT_OPTIONS.find((o) => o.value === prefs.idleTimeoutMinutes);
    parts.push(`Locks after ${opt?.label ?? `${prefs.idleTimeoutMinutes} minutes`} idle`);
  }
  if (prefs.lockOnHide) {
    parts.push('locks when you leave this tab');
  }
  parts.push('Lock Now always clears keys from memory');
  return parts.join(' · ') + '.';
}
