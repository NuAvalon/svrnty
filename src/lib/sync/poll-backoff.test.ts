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
