// src/lib/crypto/beacon-generation.test.ts
// #588 D3 (Flint 11-09): the key generation is seeded from the CLOCK so "later = higher" holds without shared state, and BOUNDED so a wrong clock cannot
// make itself durable: a build-time FLOOR (no honest clock is earlier), and a FUTURE bound (now + 1 day) on both the sender and the receiver.
// The "accept a lower generation after an in-person re-share" path is REFUSED (the code cannot tell in-person from a replay): regenerating later is the fix.
// Run: npx tsx --test src/lib/crypto/beacon-generation.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GENERATION_FLOOR, FUTURE_SLACK_SECONDS, MAX_KEY_GENERATION, generationFromClock, generationProblem } from './beacon-generation';

const NOW_S = GENERATION_FLOOR + 40 * 86400; // a plausible "now": 40 days after the floor
const NOW_MS = NOW_S * 1000;

test('G1 the floor is 2026-11-01T00:00:00Z and the cap is below 2^31', () => {
  assert.equal(GENERATION_FLOOR, Date.UTC(2026, 10, 1) / 1000);
  assert.equal(MAX_KEY_GENERATION, 2 ** 31 - 1);
  assert.equal(FUTURE_SLACK_SECONDS, 86400);
});

test('G2 generationFromClock = whole seconds since the epoch, for a first key', () => {
  assert.equal(generationFromClock(NOW_MS + 999), NOW_S);
});

test('G3 it never goes BACKWARD: with a previous generation at or above the clock it returns previous + 1', () => {
  assert.equal(generationFromClock(NOW_MS, NOW_S), NOW_S + 1);
  assert.equal(generationFromClock(NOW_MS, NOW_S + 500), NOW_S + 501);
  assert.equal(generationFromClock(NOW_MS, NOW_S - 500), NOW_S, 'a previous below the clock does not hold it back');
});

test('G4 a clock BEFORE the floor refuses to mint (a wrongly-slow clock must not create a key that sorts below its past)', () => {
  assert.throws(() => generationFromClock((GENERATION_FLOOR - 1) * 1000), /floor/i);
  assert.throws(() => generationFromClock(0), /floor/i);
});

test('G5 a previous generation beyond the future bound refuses to mint (the clock cannot catch up, so it must not pretend)', () => {
  assert.throws(() => generationFromClock(NOW_MS, NOW_S + FUTURE_SLACK_SECONDS + 1), /ahead|future/i);
  assert.equal(generationFromClock(NOW_MS, NOW_S + FUTURE_SLACK_SECONDS - 5), NOW_S + FUTURE_SLACK_SECONDS - 4);
});

test('G6 the result never exceeds MAX_KEY_GENERATION; a non-finite clock refuses', () => {
  assert.throws(() => generationFromClock(Number.NaN), /clock/i);
  assert.throws(() => generationFromClock(Infinity), /clock/i);
  assert.throws(() => generationFromClock((MAX_KEY_GENERATION + 10) * 1000), /cap|range|max/i);
});

test('G7 generationProblem: null for a good value; fixed words for a bad one, in a fixed order (malformed, past, future)', () => {
  assert.equal(generationProblem(NOW_S, NOW_S), null);
  assert.equal(generationProblem(GENERATION_FLOOR, NOW_S), null, 'the floor itself is allowed');
  assert.equal(generationProblem(NOW_S + FUTURE_SLACK_SECONDS, NOW_S), null, 'exactly now + slack is allowed');
  assert.equal(generationProblem(GENERATION_FLOOR - 1, NOW_S), 'past');
  assert.equal(generationProblem(NOW_S + FUTURE_SLACK_SECONDS + 1, NOW_S), 'future');
  for (const bad of [0, -1, 1.5, Number.NaN, '5' as any, null as any, undefined as any, MAX_KEY_GENERATION + 1, Number.MAX_SAFE_INTEGER]) {
    assert.equal(generationProblem(bad, NOW_S), 'generation', String(bad));
  }
});

test('G8 the receiver uses ITS OWN clock: the same generation is fine for a receiver whose clock agrees and "future" for one a week behind', () => {
  const g = NOW_S + 3 * 86400;
  assert.equal(generationProblem(g, NOW_S + 3 * 86400), null);
  assert.equal(generationProblem(g, NOW_S - 4 * 86400), 'future');
});
