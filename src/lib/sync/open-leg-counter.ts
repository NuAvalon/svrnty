// src/lib/sync/open-leg-counter.ts
// #720 / Archie #2032 + Flint #2031: "how many notes opened via the CLASSICAL leg?" is unknowable from what we record, so the fallback of
// dualReadOpener cannot be removed on evidence. This counts, per poll, which leg of an opener produced the result. COUNTS ONLY: no id,
// no sender, no blob text. A count is of OPENS, not distinct envelopes (an envelope that opens but is retried is counted again); for the
// removal decision only "0 for every active sender over 7 days" matters, which a re-count cannot hide.

export type OpenLeg = 'hybrid' | 'classical';

export interface OpenLegCounter {
  /** Return the counts since the last take() and reset them. consume calls it at the start (discard) and end (report) of a poll. */
  take(): { hybrid: number; classical: number };
  bump(leg: OpenLeg): void;
}

export function createOpenLegCounter(): OpenLegCounter {
  let hybrid = 0;
  let classical = 0;
  return {
    bump: (leg) => {
      if (leg === 'hybrid') hybrid++;
      else classical++;
    },
    take: () => {
      const out = { hybrid, classical };
      hybrid = 0;
      classical = 0;
      return out;
    },
  };
}

/**
 * Wrap an opener so every NON-NULL result is counted on `leg`. The result, and any throw, pass through untouched: counting can never change
 * what opens. With no counter (unit tests, legacy callers) the opener is returned as is. Wrap the CLASSICAL opener too when it is used
 * alone (an owner with no ML-KEM secret): every open there is a classical open.
 */
export function counted<T>(open: (blob: string) => Promise<T | null>, leg: OpenLeg, counter?: OpenLegCounter): (blob: string) => Promise<T | null> {
  if (!counter) return open;
  return async (blob: string) => {
    const out = await open(blob);
    if (out != null) {
      try {
        counter.bump(leg);
      } catch {
        /* a counter fault must never change what opens */
      }
    }
    return out;
  };
}
