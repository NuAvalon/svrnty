// Idle-backoff SCHEDULER (not just the pure policy): the loop must self-reschedule with growing delays when
// idle, and burst() must snap it back. Identity is null so each tick no-ops (no IDB/relay) but still counts as idle.
// Run: npx tsx --test src/lib/sync/poll-scheduler.test.ts
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { startLiveBookPolling, DEFAULT_POLL_INTERVAL_MS as I, MAX_IDLE_POLL_INTERVAL_MS as MAX, BURST_POLL_INTERVAL_MS as B, IDLE_JITTER_FRACTION as J, BURST_START_JITTER_MS as BS } from './live-book-poll';

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
    const h = startLiveBookPolling(null, { random: () => 0.5 }); // 0.5 => zero jitter: exact policy delays
    await flush();
    for (let i = 0; i < 9; i++) { mock.timers.tick(delays[delays.length - 1]); await flush(); }
    assert.deepEqual(delays.slice(0, 9), [I, I, I, I, I * 2, I * 4, I * 8, MAX, MAX].map((d) => Math.min(d, MAX)));
    const before = delays.length;
    h.burst(1_000_000); // long window so it stays in burst for the assertion
    await flush();
    assert.equal(delays[delays.length - 1], Math.floor(0.5 * BS), 'the first poll after a wake waits 0-1 s (here random=0.5 -> 500 ms)');
    mock.timers.tick(delays[delays.length - 1]); await flush(); // that poll runs, then the loop continues at burst cadence
    assert.equal(delays[delays.length - 1], B, 'then it reschedules at the burst cadence');
    assert.ok(delays.length > before);
    h.stop();
  } finally {
    (globalThis as { setTimeout: unknown }).setTimeout = mocked;
    mock.timers.reset();
  }
});

// ── Flint #276: relay-visible timing gets jitter ──
function recordDelays() {
  mock.timers.enable({ apis: ['setTimeout'] });
  const delays: number[] = [];
  const mocked = globalThis.setTimeout;
  (globalThis as { setTimeout: unknown }).setTimeout = ((fn: () => void, ms?: number, ...a: unknown[]) => {
    if ((ms ?? 0) < 100_000) delays.push(ms ?? 0);
    return (mocked as unknown as (f: () => void, m?: number, ...r: unknown[]) => unknown)(fn, ms, ...a);
  }) as unknown as typeof setTimeout;
  return { delays, restore: () => { (globalThis as { setTimeout: unknown }).setTimeout = mocked; mock.timers.reset(); } };
}

test('idle delays are jittered: every delay within +-25% of the policy delay, and they are NOT constant', async () => {
  const { delays, restore } = recordDelays();
  try {
    // deterministic spread over [0,1): 0, .13, .26, ... so we exercise the whole band without relying on Math.random
    let n = 0;
    const h = startLiveBookPolling(null, { random: () => ((n++ * 0.13) % 1) });
    await flush();
    for (let i = 0; i < 9; i++) { mock.timers.tick(delays[delays.length - 1]); await flush(); }
    const policy = [I, I, I, I, I * 2, I * 4, I * 8, MAX, MAX].map((d) => Math.min(d, MAX));
    delays.slice(0, 9).forEach((d, i) => {
      assert.ok(d >= Math.round(policy[i] * (1 - J)) && d <= Math.round(policy[i] * (1 + J)), `delay ${i} (${d}) outside +-${J * 100}% of ${policy[i]}`);
    });
    assert.ok(new Set(delays.slice(0, 4)).size > 1, 'the first four equal-policy delays are not all the same number');
    h.stop();
  } finally { restore(); }
});

test('burst: the first poll waits a random 0..1000 ms (never exact, never longer than 1 s); the burst cadence itself stays exact', async () => {
  for (const r of [0, 0.37, 0.999]) {
    const { delays, restore } = recordDelays();
    try {
      const h = startLiveBookPolling(null, { random: () => r });
      await flush();
      h.burst(1_000_000);
      await flush();
      const startDelay = delays[delays.length - 1];
      assert.equal(startDelay, Math.floor(r * BS));
      assert.ok(startDelay >= 0 && startDelay < BS);
      mock.timers.tick(startDelay); await flush();
      assert.equal(delays[delays.length - 1], B, 'cadence after the first poll is the exact burst interval');
      h.stop();
    } finally { restore(); }
  }
});
