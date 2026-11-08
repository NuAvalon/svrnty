// src/lib/sync/hold-backoff.ts
// #720 T2b (Flint #186298, T2): a HELD ratchet-desync envelope is retried on EVERY poll for its first hour, then HOURLY.
//
// A desync frame stays on the relay while we hold it, so without this every poll would re-run the ratchet open on it, for as long as
// the hold lasts (<= 7 days). The retry is only useful while the sessions might heal (the first hour: a resync, a later frame), and a
// failed open must stay cheap and side-effect-free (T1). After the first hour the frame is left alone between hourly tries.
//
// Memory only, by design (like the receipt outbox): losing it on a reload only means one extra retry, never a lost frame. A skipped
// envelope is NOT undecided: the caller still counts it as held with its recorded reason + fingerprint, so the keep bound and the
// dead-letter record behave exactly as if it had been tried and failed again.
//
//   due(id, now)            true when this held envelope should be tried now.
//   attempted(id, fp, now)  the try ended HELD again: remember first sight (kept) and this attempt.
//   forget(id)              the envelope opened / was consumed / is no longer a desync hold.
//   keepOnly(ids)           drop every entry whose envelope is gone from the relay (acked, expired, released).

export const FIRST_WINDOW_MS = 60 * 60_000;
export const SLOW_EVERY_MS = 60 * 60_000;
export const MAX_TRACKED = 1000; // beyond this an envelope is simply not tracked: it is retried every poll, the status quo

export interface HoldBackoff {
  due(id: string, nowMs: number): boolean;
  attempted(id: string, fp: string | undefined, nowMs: number): void;
  fpOf(id: string): string | undefined;
  forget(id: string): void;
  keepOnly(ids: ReadonlySet<string>): void;
  clear(): void;
  /** For tests / diagnostics only. */
  size(): number;
}

export function createHoldBackoff(): HoldBackoff {
  const m = new Map<string, { first: number; last: number; fp?: string }>();
  return {
    due(id, nowMs) {
      const e = m.get(id);
      if (!e) return true; // never seen as a desync hold: try it
      if (nowMs - e.first < FIRST_WINDOW_MS) return true; // first hour: every poll
      return nowMs - e.last >= SLOW_EVERY_MS; // then hourly
    },
    attempted(id, fp, nowMs) {
      const e = m.get(id);
      if (e) {
        e.last = nowMs;
        if (fp !== undefined) e.fp = fp;
      } else if (m.size < MAX_TRACKED) {
        m.set(id, { first: nowMs, last: nowMs, fp });
      }
    },
    fpOf: (id) => m.get(id)?.fp,
    forget: (id) => void m.delete(id),
    keepOnly(ids) {
      for (const id of [...m.keys()]) if (!ids.has(id)) m.delete(id);
    },
    clear: () => m.clear(),
    size: () => m.size,
  };
}

/** The tab's one instance. Cleared on session lock / identity switch (live-book-poll.ts): it belongs to the identity that was unlocked. */
export const holdBackoff: HoldBackoff = createHoldBackoff();
