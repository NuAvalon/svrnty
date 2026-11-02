'use client';

import { useCallback, useRef, useState } from 'react';

export type EmberFlash = 'idle' | 'busy' | 'ok';

/** Press class + a short done flash so a click is visible without inventing a new dialog. */
export function useActionFlash(holdMs = 1600) {
  const [flash, setFlash] = useState<EmberFlash>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearTimer = () => {
    if (timer.current) {
      clearTimeout(timer.current);
      timer.current = null;
    }
  };

  const markOk = useCallback(() => {
    clearTimer();
    setFlash('ok');
    timer.current = setTimeout(() => setFlash('idle'), holdMs);
  }, [holdMs]);

  const run = useCallback(
    async (fn: () => void | Promise<void>) => {
      clearTimer();
      setFlash('busy');
      try {
        await fn();
        markOk();
      } catch {
        setFlash('idle');
        throw new Error('action failed');
      }
    },
    [markOk],
  );

  return {
    flash,
    markOk,
    run,
    className: 'ember-act',
    flashAttr: flash === 'idle' ? undefined : flash,
  };
}
