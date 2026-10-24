// N-backoff — idle poll cadence policy. Run: npx tsx --test src/lib/sync/poll-backoff.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  nextPollDelayMs,
  DEFAULT_POLL_INTERVAL_MS as I,
  MAX_IDLE_POLL_INTERVAL_MS as MAX,
  BURST_POLL_INTERVAL_MS,
  IDLE_TICKS_BEFORE_BACKOFF as N,
} from './live-book-poll';

const d = (idleTicks: number, bursting = false) => nextPollDelayMs({ idleTicks, bursting, intervalMs: I, maxIdleMs: MAX });

test('full speed until N empty polls, then doubles, capped at MAX', () => {
  assert.equal(d(0), I);
  assert.equal(d(N), I);
  assert.equal(d(N + 1), I * 2);
  assert.equal(d(N + 2), I * 4);
  assert.equal(d(N + 3), I * 8 > MAX ? MAX : I * 8);
  assert.equal(d(1000), MAX);
});

test('burst always wins, and activity (idleTicks=0) restores full speed', () => {
  assert.equal(d(1000, true), BURST_POLL_INTERVAL_MS);
  assert.equal(d(0), I);
});

test('worst-case added latency for an idle arrival is bounded by MAX', () => {
  for (let k = 0; k < 50; k++) assert.ok(d(k) <= MAX);
});

// ── Flint #276: pure jitter helpers ──
import { jitterDelayMs, burstStartDelayMs, IDLE_JITTER_FRACTION as JF, BURST_START_JITTER_MS as BSJ } from './live-book-poll';

test('jitterDelayMs: random 0 -> -25%, 0.5 -> exact, ~1 -> +25%; always within the band', () => {
  assert.equal(jitterDelayMs(1000, () => 0), 750);
  assert.equal(jitterDelayMs(1000, () => 0.5), 1000);
  assert.equal(jitterDelayMs(1000, () => 0.999999), 1250);
  for (let i = 0; i <= 100; i++) {
    const d = jitterDelayMs(15_000, () => i / 100);
    assert.ok(d >= 15_000 * (1 - JF) - 1 && d <= 15_000 * (1 + JF) + 1);
  }
});

test('burstStartDelayMs: 0 <= delay < 1000 for any random in [0,1)', () => {
  assert.equal(burstStartDelayMs(() => 0), 0);
  assert.equal(burstStartDelayMs(() => 0.999999), BSJ - 1);
  assert.ok(burstStartDelayMs() >= 0 && burstStartDelayMs() < BSJ);
});
