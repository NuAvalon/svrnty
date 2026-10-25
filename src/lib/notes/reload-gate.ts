// src/lib/notes/reload-gate.ts
// The Notes-inbox reload gate (D-N8 / task #700).
//
// WHY: every note arrival used to fire a full listThreads() + listNotesForThread() reload (each decrypts every row), unguarded, so a backlog of N
// arrivals into a store of M rows cost O(N x M) decrypts and starved the main thread. The inbox now routes every reload request (an arrival, the
// periodic re-read tick, a tab becoming visible) through this gate.
//
// THE GUARANTEES (each pinned by reload-gate.test.ts with an injected clock, and the three that matter are checked against the legacy per-arrival
// behaviour as a control):
//   G1 NEVER OVERLAPS: at most one task run is in flight.
//   G2 AT MOST ONE START PER WINDOW: two run STARTS are always >= windowMs apart, so a burst of any size costs at most one reload per window.
//   G3 THE LAST REQUEST IS ALWAYS SERVED: a request made at any time, including mid-run, is followed by a run that STARTS at or after it, so the view
//      never ends stale after a burst.
//   G4 BOUNDED STALENESS: a request waits at most max(windowMs, the remaining time of the run already in flight) before its run starts; an isolated
//      request after a quiet period starts IMMEDIATELY (leading edge), so the common single arrival is not delayed at all.
// A task that throws does not wedge the gate. dispose() cancels the pending timer and starts nothing further (a run already in flight finishes).

export interface ReloadGate {
  /** Ask for a reload. Cheap and idempotent: any number of calls before the next run collapse into that one run. */
  request(): void;
  /** Cancel the pending timer; nothing further starts. */
  dispose(): void;
}

/** Injectable time so the guarantees can be tested deterministically, without sleeping. */
export interface GateClock {
  now(): number;
  setTimer(fn: () => void, ms: number): unknown;
  clearTimer(id: unknown): void;
}

const realClock: GateClock = {
  now: () => Date.now(),
  setTimer: (fn, ms) => setTimeout(fn, ms),
  clearTimer: (id) => clearTimeout(id as ReturnType<typeof setTimeout>),
};

export function createReloadGate(task: () => Promise<void>, windowMs = 250, clock: GateClock = realClock): ReloadGate {
  let timer: unknown = null;
  let running = false;
  let pending = false;
  let disposed = false;
  let lastStart = Number.NEGATIVE_INFINITY;

  const tryStart = (): void => {
    if (disposed || running || !pending) return;
    const wait = lastStart + windowMs - clock.now();
    if (wait > 0) {
      // Inside the window: one trailing timer for the whole burst.
      if (timer === null) {
        timer = clock.setTimer(() => {
          timer = null;
          tryStart();
        }, wait);
      }
      return;
    }
    pending = false;
    running = true;
    lastStart = clock.now();
    void (async () => {
      try {
        await task();
      } catch {
        // the task owns its error handling; a throw must not wedge the gate
      } finally {
        running = false;
        tryStart(); // a request that landed mid-run is served now, still honouring the window
      }
    })();
  };

  return {
    request() {
      if (disposed) return;
      pending = true;
      tryStart();
    },
    dispose() {
      disposed = true;
      if (timer !== null) {
        clock.clearTimer(timer);
        timer = null;
      }
    },
  };
}
