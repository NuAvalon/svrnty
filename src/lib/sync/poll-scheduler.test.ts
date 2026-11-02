// The idle-backoff SCHEDULER, not just the pure policy: the loop must reschedule itself with growing delays when idle, and
// a burst, a non-empty poll or keepSteady must snap it back. Every test drives the REAL startLiveBookPolling tick -> consume path
// with a signing owner and an injected relay (only the IndexedDB deps builder and the timers are injected). Locked and
// refused polls are asserted on purpose: they must not be mistaken for "idle".
//
// Run: npx tsx --test src/lib/sync/poll-scheduler.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import type { ConsumeDeps } from './consume-mailbox';
import {
  startLiveBookPolling,
  type PollTimers,
  DEFAULT_POLL_INTERVAL_MS as I,
  MAX_IDLE_POLL_INTERVAL_MS as MAX,
  BURST_POLL_INTERVAL_MS as B,
  IDLE_JITTER_FRACTION as JF,
  BURST_START_JITTER_MS as BS,
} from './live-book-poll';
import { __resetPollStatusForTest } from '@/lib/notes/poll-status-events';

let owner: ConsumeDeps['owner'];

before(async () => {
  const passphrase = 'pw-alice';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name: 'alice', email: 'alice@x.test' }],
    passphrase,
    format: 'armored',
  });
  const fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint().toUpperCase();
  owner = { fingerprint, publicKeyArmored: publicKey, privateKeyArmored: privateKey, passphrase };
});

const LONG = 100_000; // a timer longer than this is a burst WINDOW, not a poll delay

type Fake = { ms: number; fn: () => void; live: boolean };
function fakeTimers() {
  const all: Fake[] = [];
  const timers: PollTimers = {
    set: (fn, ms) => {
      const t: Fake = { ms, fn, live: true };
      all.push(t);
      return t;
    },
    clear: (h) => {
      (h as Fake).live = false;
    },
  };
  const polls = () => all.filter((t) => t.ms < LONG);
  const live = () => all.filter((t) => t.live);
  const livePoll = () => polls().filter((t) => t.live);
  const nap = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
  /** Wait (real time) until `cond` holds; fail loudly instead of hanging. */
  const until = async (cond: () => boolean, what: string) => {
    for (let i = 0; i < 1000; i++) {
      if (cond()) return;
      await nap(5);
    }
    assert.fail(`timed out waiting for ${what}`);
  };
  /** Run the most recent live poll timer, then wait for the poll it starts to schedule the next one. */
  const fire = async () => {
    const t = livePoll().at(-1);
    assert.ok(t, 'a live poll timer to fire');
    const before = polls().length;
    t.live = false;
    t.fn();
    await until(() => polls().length > before, 'the next poll to be scheduled');
  };
  return { timers, all, polls, live, livePoll, fire, until, nap, delays: () => polls().map((t) => t.ms) };
}

const emptyRelay: typeof fetch = async () => new Response('[]', { status: 200 });
const refusedRelay: typeof fetch = async () => new Response('{"error":"unauthorized"}', { status: 401 });

function depsWith(fetchImpl: typeof fetch) {
  return async (): Promise<ConsumeDeps> => ({
    owner,
    decrypt: async () => null,
    store: { lookup: async () => null, persist: async () => {} },
    relayBase: 'http://relay.test/api/relay',
    fetchImpl,
  });
}

const EXACT = () => 0.5; // zero jitter: the delays are exactly the policy's

function start(f: ReturnType<typeof fakeTimers>, buildDeps: ReturnType<typeof depsWith> | (() => Promise<null>), random: () => number = EXACT) {
  __resetPollStatusForTest();
  return startLiveBookPolling({}, { timers: f.timers, random, buildDeps: buildDeps as never });
}

test('an idle loop backs off 1.5 s x4, then 3 s, 6 s, 12 s, then holds the 15 s cap', async () => {
  const f = fakeTimers();
  const h = start(f, depsWith(emptyRelay));
  await f.until(() => f.polls().length >= 1, 'the first poll');
  for (let i = 0; i < 8; i++) await f.fire();
  assert.deepEqual(f.delays().slice(0, 9), [I, I, I, I, I * 2, I * 4, I * 8, MAX, MAX]);
  h.stop();
});

test('a LOCKED poll is not idle: locked ticks never advance the backoff, and the first poll after unlock is not 15 s away', async () => {
  const f = fakeTimers();
  let locked = true;
  const real = depsWith(emptyRelay);
  const h = start(f, async () => (locked ? null : real()) as never);
  await f.until(() => f.polls().length >= 1, 'the first poll');
  for (let i = 0; i < 10; i++) await f.fire();
  assert.deepEqual(f.delays().slice(0, 11), Array(11).fill(I), 'ten locked polls in a row: still the steady interval');
  locked = false; // unlock
  const before = f.delays().length;
  for (let i = 0; i < 5; i++) await f.fire();
  assert.deepEqual(f.delays().slice(before - 1, before + 5), [I, I, I, I, I, I * 2], 'after unlock the backoff starts from zero: 4 free polls, then it doubles');
  h.stop();
});

test('a REFUSED poll (relay answers non-2xx) counts as idle: a refusing relay is backed off from', async () => {
  const f = fakeTimers();
  const h = start(f, depsWith(refusedRelay));
  await f.until(() => f.polls().length >= 1, 'the first poll');
  for (let i = 0; i < 6; i++) await f.fire();
  assert.deepEqual(f.delays().slice(0, 7), [I, I, I, I, I * 2, I * 4, I * 8]);
  h.stop();
});

test('a thrown poll counts as idle and never wedges the loop', async () => {
  const f = fakeTimers();
  const boom: typeof fetch = async () => {
    throw new Error('network down');
  };
  const orig = console.error;
  console.error = () => {};
  try {
    const h = start(f, depsWith(boom));
    await f.until(() => f.polls().length >= 1, 'the first poll');
    for (let i = 0; i < 5; i++) await f.fire();
    assert.deepEqual(f.delays().slice(0, 6), [I, I, I, I, I * 2, I * 4]);
    h.stop();
  } finally {
    console.error = orig;
  }
});

test('burst(): resets the backoff; the first poll waits 0-1 s (not exact), then the burst cadence is exact; when the window ends the loop goes back to 4 free polls', async () => {
  for (const r of [0, 0.37, 0.999]) {
    const f = fakeTimers();
    const h = start(f, depsWith(emptyRelay), () => r);
    await f.until(() => f.polls().length >= 1, 'the first poll');
    for (let i = 0; i < 8; i++) await f.fire(); // well into the backoff
    h.burst(1_000_000);
    const startTimer = f.livePoll().at(-1)!;
    assert.equal(startTimer.ms, Math.floor(r * BS), `the first poll after a wake waits floor(${r} x 1000) ms`);
    assert.ok(startTimer.ms >= 0 && startTimer.ms < BS);
    await f.fire();
    await f.fire();
    assert.equal(f.delays().at(-1), B, 'then the exact burst cadence');
    assert.equal(f.delays().at(-2), B);
    const window = f.live().find((t) => t.ms === 1_000_000)!;
    assert.ok(window, 'the burst window timer is armed');
    window.live = false;
    window.fn(); // the window ends
    const j = (x: number) => Math.round(x * (1 + (r * 2 - 1) * JF));
    await f.fire(); // the pending 350 ms poll runs: the 1st empty poll since the window ended
    assert.equal(f.delays().at(-1), j(I), 'back at the (jittered) steady interval');
    for (let i = 0; i < 3; i++) await f.fire(); // empty polls 2, 3, 4
    assert.equal(f.delays().at(-1), j(I), 'the 4th empty poll is still free');
    await f.fire(); // the 5th empty poll
    assert.equal(f.delays().at(-1), j(I * 2), 'the 5th doubles');
    h.stop();
  }
});

test('burst() while a poll is IN FLIGHT does not start a second poll; the running poll reschedules at the burst cadence', async () => {
  const f = fakeTimers();
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let calls = 0;
  const slow: typeof fetch = async () => {
    calls++;
    if (calls === 1) await gate;
    return new Response('[]', { status: 200 });
  };
  const h = start(f, depsWith(slow));
  await f.until(() => calls === 1, 'the first poll to be in flight');
  h.burst(1_000_000);
  assert.equal(f.polls().length, 0, 'no start-delay timer while a poll is in flight');
  release();
  await f.until(() => f.polls().length >= 1, 'the in-flight poll to reschedule');
  assert.equal(f.delays()[0], B, 'rescheduled at the burst cadence');
  assert.equal(calls, 1, 'exactly one poll ran');
  h.stop();
});

test('keepSteady(true) disables the backoff at once (even from the 15 s cap) and keepSteady(false) restarts it from zero', async () => {
  const f = fakeTimers();
  const h = start(f, depsWith(emptyRelay));
  await f.until(() => f.polls().length >= 1, 'the first poll');
  for (let i = 0; i < 9; i++) await f.fire();
  assert.equal(f.delays().at(-1), MAX, 'backed off to the cap');
  h.keepSteady(true);
  assert.equal(f.livePoll().at(-1)!.ms, I, 'the pending long wait is replaced by the steady interval now');
  for (let i = 0; i < 12; i++) await f.fire();
  assert.deepEqual(f.delays().slice(-12), Array(12).fill(I), 'twelve idle polls in a row, all at the steady interval');
  h.keepSteady(false);
  for (let i = 0; i < 5; i++) await f.fire();
  assert.deepEqual(f.delays().slice(-6), [I, I, I, I, I, I * 2], 'leaving the Notes tab: 4 free polls, then it doubles again');
  h.stop();
});

test('idle delays are jittered: every delay within +-25% of the policy delay, and they are not constant', async () => {
  const f = fakeTimers();
  let n = 0;
  const h = start(f, depsWith(emptyRelay), () => (n++ * 0.13) % 1);
  await f.until(() => f.polls().length >= 1, 'the first poll');
  for (let i = 0; i < 8; i++) await f.fire();
  const policy = [I, I, I, I, I * 2, I * 4, I * 8, MAX, MAX];
  f.delays().slice(0, 9).forEach((d, i) => {
    assert.ok(d >= Math.round(policy[i] * (1 - JF)) && d <= Math.round(policy[i] * (1 + JF)), `delay ${i} (${d}) outside +-25% of ${policy[i]}`);
  });
  assert.ok(new Set(f.delays().slice(0, 4)).size > 1, 'the first four equal-policy delays are not all the same number');
  h.stop();
});

test('stop() cancels the pending poll and an in-flight poll does not reschedule afterwards', async () => {
  const f = fakeTimers();
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let calls = 0;
  const slow: typeof fetch = async () => {
    calls++;
    if (calls === 2) await gate;
    return new Response('[]', { status: 200 });
  };
  const h = start(f, depsWith(slow));
  await f.until(() => f.polls().length >= 1, 'the first poll');
  assert.equal(f.livePoll().length, 1);
  h.stop();
  assert.equal(f.livePoll().length, 0, 'the pending poll timer is cancelled');
  // a second loop: stop while a poll is in flight
  const g = fakeTimers();
  calls = 0;
  const h2 = start(g, depsWith(slow));
  await g.until(() => g.polls().length >= 1, 'the first poll');
  const t = g.livePoll().at(-1)!;
  t.live = false;
  t.fn(); // second poll starts and blocks on the gate
  await g.until(() => calls === 2, 'the second poll to be in flight');
  h2.stop();
  release();
  await g.nap(100);
  assert.equal(g.livePoll().length, 0, 'nothing was rescheduled after stop()');
});

test('a poll that FINDS something resets the backoff: the next delay is the steady interval and the 4 free polls start over', async () => {
  const f = fakeTimers();
  let queueCalls = 0;
  let arrive = false;
  const relay: typeof fetch = async (input) => {
    const url = String(input);
    if (!url.includes('/queue')) return new Response('{}', { status: 200 }); // ack / delete: accepted
    queueCalls++;
    if (arrive) {
      arrive = false;
      return new Response(JSON.stringify([{ envelope_id: 'env-1', encrypted_blob: 'AAAA' }]), { status: 200 });
    }
    return new Response('[]', { status: 200 });
  };
  const orig = console.error;
  console.error = () => {};
  try {
    const h = start(f, depsWith(relay));
    await f.until(() => f.polls().length >= 1, 'the first poll');
    for (let i = 0; i < 7; i++) await f.fire(); // idle: 7 empty polls so far plus the first
    assert.ok(f.delays().at(-1)! >= I * 4, 'backed off before the arrival');
    arrive = true;
    await f.fire(); // this poll finds one envelope
    assert.equal(queueCalls, 9);
    assert.equal(f.delays().at(-1), I, 'a non-empty poll resets the backoff: the next delay is the steady interval');
    for (let i = 0; i < 3; i++) await f.fire(); // empty polls 1..3 after the arrival
    assert.equal(f.delays().at(-1), I);
    await f.fire(); // the 4th
    assert.equal(f.delays().at(-1), I, 'the 4th empty poll after the arrival is still free');
    await f.fire(); // the 5th
    assert.equal(f.delays().at(-1), I * 2, 'the 5th doubles');
    h.stop();
  } finally {
    console.error = orig;
  }
});
