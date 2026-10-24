// Idle-backoff SCHEDULER (not just the pure policy): the loop must self-reschedule with growing delays when
// idle, and burst() must snap it back. Identity is null so each tick no-ops (no IDB/relay) but still counts as idle.
// Run: npx tsx --test src/lib/sync/poll-scheduler.test.ts
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { startLiveBookPolling, DEFAULT_POLL_INTERVAL_MS as I, MAX_IDLE_POLL_INTERVAL_MS as MAX, BURST_POLL_INTERVAL_MS as B } from './live-book-poll';

const flush = async () => { for (let i = 0; i < 20; i++) await new Promise<void>((r) => setImmediate(r)); };

test('idle loop backs off 1.5s x4 -> 3s -> 6s -> 12s -> 15s cap, and burst() snaps it back', async () => {
  mock.timers.enable({ apis: ['setTimeout'] });
  const delays: number[] = [];
  const mocked = globalThis.setTimeout;
  (globalThis as { setTimeout: unknown }).setTimeout = ((fn: () => void, ms?: number, ...a: unknown[]) => {
    if ((ms ?? 0) < 100_000) delays.push(ms ?? 0); // the burst's own window timer is long; filter it out
    return (mocked as unknown as (f: () => void, m?: number, ...r: unknown[]) => unknown)(fn, ms, ...a);
  }) as unknown as typeof setTimeout;
  try {
    const h = startLiveBookPolling(null);
    await flush();
    for (let i = 0; i < 9; i++) { mock.timers.tick(delays[delays.length - 1]); await flush(); }
    assert.deepEqual(delays.slice(0, 9), [I, I, I, I, I * 2, I * 4, I * 8, MAX, MAX].map((d) => Math.min(d, MAX)));
    const before = delays.length;
    h.burst(1_000_000); // long window so it stays in burst for the assertion
    await flush();
    assert.equal(delays[delays.length - 1], B, 'burst reschedules at the burst cadence');
    assert.ok(delays.length > before);
    h.stop();
  } finally {
    (globalThis as { setTimeout: unknown }).setTimeout = mocked;
    mock.timers.reset();
  }
});
