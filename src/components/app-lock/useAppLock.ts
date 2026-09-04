'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  type AppLockPrefs,
  readAppLockPrefs,
  writeAppLockPrefs,
} from './app-lock-prefs';

const ACTIVITY_EVENTS: ReadonlyArray<keyof WindowEventMap> = [
  'pointerdown',
  'keydown',
  'touchstart',
  'mousemove',
  'scroll',
  'wheel',
];

export type UseAppLockArgs = {
  /** When false, timers are paused (e.g. already locked / no encrypted vault). */
  enabled: boolean;
  /** Called when idle timeout or hide-policy fires. Must be stable or wrapped. */
  onAutoLock: () => void;
};

/**
 * Signal-model app-lock timers — UI only.
 * Does not touch crypto; caller invokes fleet `lockSession()` in onAutoLock / Lock Now.
 */
export function useAppLock({ enabled, onAutoLock }: UseAppLockArgs) {
  const [prefs, setPrefsState] = useState<AppLockPrefs>(() => readAppLockPrefs());
  const prefsRef = useRef(prefs);
  const onAutoLockRef = useRef(onAutoLock);
  const idleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    prefsRef.current = prefs;
  }, [prefs]);

  useEffect(() => {
    onAutoLockRef.current = onAutoLock;
  }, [onAutoLock]);

  const setPrefs = useCallback((next: AppLockPrefs) => {
    setPrefsState(next);
    writeAppLockPrefs(next);
  }, []);

  const clearIdleTimer = useCallback(() => {
    if (idleTimerRef.current !== null) {
      clearTimeout(idleTimerRef.current);
      idleTimerRef.current = null;
    }
  }, []);

  const armIdleTimer = useCallback(() => {
    clearIdleTimer();
    if (!enabled) return;
    const minutes = prefsRef.current.idleTimeoutMinutes;
    if (minutes <= 0) return;
    idleTimerRef.current = setTimeout(() => {
      onAutoLockRef.current();
    }, minutes * 60 * 1000);
  }, [clearIdleTimer, enabled]);

  // Idle activity listeners
  useEffect(() => {
    if (!enabled) {
      clearIdleTimer();
      return;
    }
    armIdleTimer();
    const onActivity = () => armIdleTimer();
    for (const ev of ACTIVITY_EVENTS) {
      window.addEventListener(ev, onActivity, { passive: true });
    }
    return () => {
      for (const ev of ACTIVITY_EVENTS) {
        window.removeEventListener(ev, onActivity);
      }
      clearIdleTimer();
    };
  }, [enabled, prefs.idleTimeoutMinutes, armIdleTimer, clearIdleTimer]);

  // Lock when tab/app is hidden (visibility + pagehide)
  useEffect(() => {
    if (!enabled) return;

    const maybeLockOnHide = () => {
      if (!prefsRef.current.lockOnHide) return;
      if (document.visibilityState === 'hidden') {
        onAutoLockRef.current();
      }
    };

    const onPageHide = () => {
      if (!prefsRef.current.lockOnHide) return;
      onAutoLockRef.current();
    };

    document.addEventListener('visibilitychange', maybeLockOnHide);
    window.addEventListener('pagehide', onPageHide);
    return () => {
      document.removeEventListener('visibilitychange', maybeLockOnHide);
      window.removeEventListener('pagehide', onPageHide);
    };
  }, [enabled]);

  return { prefs, setPrefs, armIdleTimer };
}
