// src/lib/crypto/beacon-generation.ts
// #588 D3 (Flint's ruling, 11-09; DARK): the beacon key generation. Seeded from the clock so "later = higher" holds with no shared state (a restored or
// second device that cannot know the highest generation it ever published still mints a higher one), and BOUNDED so a wrong clock cannot make itself
// durable: a build-time FLOOR (no honest clock is earlier than this file), and a FUTURE bound (the receiver's own clock + 1 day) applied by the sender AND the
// receiver. The "accept a LOWER generation after an in-person re-share" path is REFUSED: the code cannot tell in-person from a pasted replay.
// No import of beacon-wire here on purpose: identity-card-sign imports this statically (main bundle).

/** 2026-11-01T00:00:00Z, in seconds. A generation below it is 'past': no honest clock produced it. */
export const GENERATION_FLOOR = 1793491200;
export const FUTURE_SLACK_SECONDS = 86400;
export const MAX_KEY_GENERATION = 2 ** 31 - 1;

export type GenerationProblem = 'generation' | 'past' | 'future';

/** null when `g` is acceptable at the checker's clock `nowSeconds`; else a fixed word. Order: malformed, past, future. */
export function generationProblem(g: unknown, nowSeconds: number): GenerationProblem | null {
  if (typeof g !== 'number' || !Number.isInteger(g) || g < 1 || g > MAX_KEY_GENERATION) return 'generation';
  if (g < GENERATION_FLOOR) return 'past';
  if (g > nowSeconds + FUTURE_SLACK_SECONDS) return 'future';
  return null;
}

/** The generation for a NEW key: whole seconds since the epoch, but never below `previous + 1`. Refuses (throws) when the clock is before the floor, when
 * `previous` is already beyond the future bound (the clock cannot catch up), or when the result would exceed the cap. */
export function generationFromClock(nowMs: number, previous?: number): number {
  if (typeof nowMs !== 'number' || !Number.isFinite(nowMs)) throw new Error('generation: clock must be a finite number');
  const nowS = Math.floor(nowMs / 1000);
  if (nowS < GENERATION_FLOOR) throw new Error('generation: the clock is before the build floor; refusing to mint a key that sorts below its past');
  let g = nowS;
  if (previous !== undefined) {
    if (!Number.isInteger(previous) || previous < 0) throw new Error('generation: previous must be a non-negative integer');
    if (previous > nowS + FUTURE_SLACK_SECONDS - 1) throw new Error('generation: the previous generation is ahead of the clock by more than the future bound');
    g = Math.max(nowS, previous + 1);
  }
  if (g > MAX_KEY_GENERATION) throw new Error('generation: result exceeds the cap');
  return g;
}
