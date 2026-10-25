// The Notes-inbox reload gate (D-N8 / #700). Run: npx --no-install tsx --test src/lib/notes/reload-gate.test.ts
// Deterministic: an injected clock, no sleeping. The guarantees G1-G4 are stated in reload-gate.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createReloadGate, type GateClock, type ReloadGate } from './reload-gate';

const flush = async () => {
  for (let i = 0; i < 25; i++) await Promise.resolve();
};

class FakeClock implements GateClock {
  t = 0;
  private timers: Array<{ id: number; at: number; fn: () => void }> = [];
  private nextId = 1;
  now() {
    return this.t;
  }
  setTimer(fn: () => void, ms: number) {
    const id = this.nextId++;
    this.timers.push({ id, at: this.t + ms, fn });
    return id;
  }
  clearTimer(id: unknown) {
    this.timers = this.timers.filter((x) => x.id !== id);
  }
  /** Move time forward, firing due timers in order and draining microtasks after each. */
  async advance(ms: number) {
    // Drain microtasks queued by the caller's synchronous work BEFORE time moves: in real life a run's completion (and the gate's "serve the pending
    // request" step) happens before the clock gets to the next timer. Without this the harness jumps the clock first and the gate sees a later "now".
    await flush();
    const end = this.t + ms;
    for (;;) {
      const due = [...this.timers].filter((x) => x.at <= end).sort((a, b) => a.at - b.at || a.id - b.id)[0];
      if (!due) break;
      this.t = Math.max(this.t, due.at);
      this.timers = this.timers.filter((x) => x !== due);
      due.fn();
      await flush();
    }
    this.t = end;
    await flush();
  }
  get pendingTimers() {
    return this.timers.length;
  }
}

/** Records every request / run start / run end with a global sequence number so "served AFTER the request" is exact even within one millisecond. */
function harness(clock: FakeClock, durationOf: (runIndex: number) => number, throwOn: number[] = []) {
  let seq = 0;
  const log = {
    requests: [] as Array<{ t: number; seq: number; inflightEnd: number | null }>,
    starts: [] as Array<{ t: number; seq: number }>,
    ends: [] as Array<{ t: number }>,
    inFlight: 0,
    maxInFlight: 0,
    currentEnd: null as number | null,
  };
  const task = async () => {
    const i = log.starts.length;
    log.starts.push({ t: clock.now(), seq: seq++ });
    log.inFlight++;
    log.maxInFlight = Math.max(log.maxInFlight, log.inFlight);
    const d = durationOf(i);
    log.currentEnd = clock.now() + d;
    await new Promise<void>((resolve) => {
      if (d === 0) resolve();
      else clock.setTimer(resolve, d);
    });
    log.inFlight--;
    log.currentEnd = null;
    log.ends.push({ t: clock.now() });
    if (throwOn.includes(i)) throw new Error('task failed');
  };
  const request = (gate: Pick<ReloadGate, 'request'>) => {
    log.requests.push({ t: clock.now(), seq: seq++, inflightEnd: log.currentEnd });
    gate.request();
  };
  return { log, task, request };
}

/** The four guarantees as one checker, used on the real gate AND on the legacy control. Returns the violations (empty = all hold). */
function violations(log: ReturnType<typeof harness>['log'], windowMs: number): string[] {
  const v: string[] = [];
  if (log.maxInFlight > 1) v.push(`G1 overlap: ${log.maxInFlight} runs in flight at once`);
  for (let i = 1; i < log.starts.length; i++) {
    if (log.starts[i].t - log.starts[i - 1].t < windowMs) v.push(`G2 starts ${log.starts[i - 1].t} and ${log.starts[i].t} are < ${windowMs} ms apart`);
  }
  for (const r of log.requests) {
    const s = log.starts.find((x) => x.seq > r.seq);
    if (!s) {
      v.push(`G3 request at ${r.t} never served by a later run`);
      continue;
    }
    const bound = Math.max(r.t + windowMs, r.inflightEnd ?? r.t);
    if (s.t > bound) v.push(`G4 request at ${r.t} served at ${s.t}, bound ${bound}`);
  }
  return [...new Set(v)];
}

test('G1-G4: a 200-request burst costs ONE run now plus ONE trailing run, never 200 (the O(N x M) storm)', async () => {
  const clock = new FakeClock();
  const h = harness(clock, () => 10);
  const gate = createReloadGate(h.task, 250, clock);
  for (let i = 0; i < 200; i++) h.request(gate);
  await clock.advance(2000);
  assert.deepEqual(h.log.starts.map((s) => s.t), [0, 250], 'a leading run, then exactly one trailing run that serves the other 199');
  assert.deepEqual(violations(h.log, 250), []);
  assert.equal(clock.pendingTimers, 0, 'nothing left armed');
});

test('CONTROL (the bug): the legacy per-arrival behaviour violates the same checker, so a green result above is not vacuous', async () => {
  const clock = new FakeClock();
  const h = harness(clock, () => 10);
  // dev's NotesInbox: every arrival runs the reload immediately, unguarded.
  for (let i = 0; i < 200; i++) {
    h.log.requests.push({ t: clock.now(), seq: -1, inflightEnd: null });
    void h.task();
  }
  await clock.advance(2000);
  assert.equal(h.log.starts.length, 200, 'dev reloads once PER arrival');
  const v = violations(h.log, 250);
  assert.ok(v.some((x) => x.startsWith('G1')), `overlap detected: ${v.join(' | ')}`);
  assert.ok(v.some((x) => x.startsWith('G2')), 'spacing violation detected');
});

test('an isolated request after a quiet period starts IMMEDIATELY (leading edge): the common single arrival is not delayed', async () => {
  const clock = new FakeClock();
  const h = harness(clock, () => 5);
  const gate = createReloadGate(h.task, 250, clock);
  h.request(gate);
  await clock.advance(5000);
  h.request(gate);
  assert.deepEqual(h.log.starts.map((s) => s.t), [0, 5000], 'zero added staleness for a lone arrival');
  await clock.advance(1000);
  assert.deepEqual(violations(h.log, 250), []);
});

test('a request that lands MID-RUN is served by a later run and the last arrival is never lost (fast run and slow run)', async () => {
  for (const dur of [100, 600]) {
    const clock = new FakeClock();
    const h = harness(clock, () => dur);
    const gate = createReloadGate(h.task, 250, clock);
    h.request(gate);
    await clock.advance(50);
    h.request(gate); // mid-run
    await clock.advance(5000);
    assert.equal(h.log.starts.length, 2, `dur ${dur}: one run + exactly one follow-up`);
    assert.ok(h.log.starts[1].t - h.log.starts[0].t >= 250, 'follow-up honours the window');
    assert.equal(h.log.starts[1].t, Math.max(dur, 250), 'and starts as soon as both the run and the window allow');
    assert.deepEqual(violations(h.log, 250), [], `dur ${dur}`);
  }
});

test('PROPERTY: 40 seeded random schedules (bursts, quiet gaps, task durations 0 ms - 700 ms) never violate G1-G4, and nothing is left pending', async () => {
  let seed = 0x9e3779b9;
  const rnd = () => ((seed = (Math.imul(seed ^ (seed >>> 15), 0x85ebca6b) + 0x7f4a7c15) >>> 0) / 0x100000000);
  let totalRequests = 0;
  for (let round = 0; round < 40; round++) {
    const clock = new FakeClock();
    const durations = [0, 1, 5, 50, 300, 700];
    const h = harness(clock, () => durations[Math.floor(rnd() * durations.length)]);
    const gate = createReloadGate(h.task, 250, clock);
    for (let step = 0; step < 60; step++) {
      const burst = 1 + Math.floor(rnd() * 12);
      for (let k = 0; k < burst; k++) {
        h.request(gate);
        totalRequests++;
      }
      await clock.advance(Math.floor(rnd() * 420));
    }
    await clock.advance(10_000);
    assert.deepEqual(violations(h.log, 250), [], `round ${round}`);
    assert.equal(clock.pendingTimers, 0, `round ${round}: a timer was left armed`);
    assert.equal(h.log.inFlight, 0, `round ${round}: a run was left in flight`);
    const last = h.log.requests[h.log.requests.length - 1];
    assert.ok(h.log.starts.some((s) => s.seq > last.seq), `round ${round}: the LAST request was never served`);
  }
  assert.ok(totalRequests > 2000, `covered ${totalRequests} requests`);
});

test('dispose() cancels the pending trailing run and starts nothing further; a run already in flight finishes', async () => {
  const clock = new FakeClock();
  const h = harness(clock, () => 100);
  const gate = createReloadGate(h.task, 250, clock);
  h.request(gate);
  h.request(gate); // pending trailing run, timer armed once the first finishes
  await clock.advance(120);
  assert.equal(clock.pendingTimers, 1);
  gate.dispose();
  assert.equal(clock.pendingTimers, 0, 'the timer is cancelled');
  await clock.advance(5000);
  assert.equal(h.log.starts.length, 1, 'no trailing run after dispose');
  h.request(gate);
  await clock.advance(1000);
  assert.equal(h.log.starts.length, 1, 'a request after dispose is ignored');
  // in-flight completion: dispose DURING a run lets it finish
  const c2 = new FakeClock();
  const h2 = harness(c2, () => 100);
  const g2 = createReloadGate(h2.task, 250, c2);
  h2.request(g2);
  await c2.advance(10);
  g2.dispose();
  await c2.advance(500);
  assert.equal(h2.log.ends.length, 1, 'the in-flight run finished');
});

test('a task that THROWS does not wedge the gate: the next request still runs', async () => {
  const clock = new FakeClock();
  const h = harness(clock, () => 5, [0]);
  const gate = createReloadGate(h.task, 250, clock);
  h.request(gate);
  await clock.advance(300);
  h.request(gate);
  await clock.advance(1000);
  assert.deepEqual(h.log.starts.map((s) => s.t), [0, 300]);
});

test('the default window is 250 ms', async () => {
  const clock = new FakeClock();
  const h = harness(clock, () => 1);
  const gate = createReloadGate(h.task, undefined, clock);
  h.request(gate);
  h.request(gate);
  await clock.advance(1000);
  assert.deepEqual(h.log.starts.map((s) => s.t), [0, 250]);
});
