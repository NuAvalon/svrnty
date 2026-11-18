// src/components/export/slow-notice.ts
// Shows a "still working" line only if the work is STILL running `afterMs` after it started, and hides it when the work ends. Pure over the timer functions it is given (default: the page's own).
// Run: npx tsx --test src/components/export/vault-export-slow.test.ts
export interface Timers {
  set(fn: () => void, ms: number): unknown;
  clear(id: unknown): void;
}

const pageTimers: Timers = { set: (fn, ms) => setTimeout(fn, ms), clear: (id) => clearTimeout(id as ReturnType<typeof setTimeout>) };

/** Start the clock: `show(true)` runs once, `afterMs` later, unless the returned `stop` runs first. `stop` cancels a pending show and hides the line; calling it twice is harmless. */
export function startSlowNotice(show: (on: boolean) => void, afterMs: number, timers: Timers = pageTimers): () => void {
  const id = timers.set(() => show(true), afterMs);
  let stopped = false;
  return () => {
    if (stopped) return;
    stopped = true;
    timers.clear(id);
    show(false);
  };
}
