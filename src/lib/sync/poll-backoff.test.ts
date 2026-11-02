// Idle poll cadence policy (pure). Run: npx tsx --test src/lib/sync/poll-backoff.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  nextPollDelayMs,
  jitterDelayMs,
  burstStartDelayMs,
  DEFAULT_POLL_INTERVAL_MS as I,
  MAX_IDLE_POLL_INTERVAL_MS as MAX,
  BURST_POLL_INTERVAL_MS as B,
  IDLE_TICKS_BEFORE_BACKOFF as N,
  IDLE_JITTER_FRACTION as JF,
  BURST_START_JITTER_MS as BSJ,
} from './live-book-poll';

const d = (idleTicks: number, over: { bursting?: boolean; steady?: boolean } = {}) =>
  nextPollDelayMs({ idleTicks, bursting: over.bursting ?? false, steady: over.steady, intervalMs: I, maxIdleMs: MAX });

test('full speed for the first N empty polls, then doubles, capped at MAX', () => {
  assert.equal(d(0), I);
  assert.equal(d(N), I);
  assert.equal(d(N + 1), I * 2);
  assert.equal(d(N + 2), I * 4);
  assert.equal(d(N + 3), I * 8);
  assert.equal(d(N + 4), MAX); // 16 x 1.5 s = 24 s, held to the cap
  assert.equal(d(1000), MAX);
});

test('a burst always polls at the burst cadence, however idle the loop was', () => {
  assert.equal(d(0, { bursting: true }), B);
  assert.equal(d(1000, { bursting: true }), B);
});

test('steady (the Notes tab is open) disables the backoff: the steady interval at any idleness', () => {
  assert.equal(d(1000, { steady: true }), I);
  assert.equal(d(N + 3, { steady: true }), I);
  assert.equal(d(1000, { steady: true, bursting: true }), B, 'a burst still wins over steady');
});

test('the worst-case wait for an idle arrival is bounded by MAX, and never below the steady interval', () => {
  for (let k = 0; k < 200; k++) {
    assert.ok(d(k) <= MAX);
    assert.ok(d(k) >= I);
  }
});

test('an interval already above the cap is never shortened by the cap', () => {
  assert.equal(nextPollDelayMs({ idleTicks: 50, bursting: false, intervalMs: 20_000, maxIdleMs: MAX }), 20_000);
});

test('jitterDelayMs: random 0 -> -25%, 0.5 -> exact, ~1 -> +25%, always inside the band', () => {
  assert.equal(jitterDelayMs(1000, () => 0), 750);
  assert.equal(jitterDelayMs(1000, () => 0.5), 1000);
  assert.equal(jitterDelayMs(1000, () => 0.999999), 1250);
  for (let i = 0; i <= 100; i++) {
    const v = jitterDelayMs(MAX, () => i / 100);
    assert.ok(v >= MAX * (1 - JF) - 1 && v <= MAX * (1 + JF) + 1, `${v} outside the band`);
  }
});

test('burstStartDelayMs: 0 <= delay < 1000 for any random in [0,1)', () => {
  assert.equal(burstStartDelayMs(() => 0), 0);
  assert.equal(burstStartDelayMs(() => 0.999999), BSJ - 1);
  for (let i = 0; i < 100; i++) {
    const v = burstStartDelayMs(() => i / 100);
    assert.ok(v >= 0 && v < BSJ);
  }
});
