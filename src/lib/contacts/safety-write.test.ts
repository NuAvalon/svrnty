// The per-contact lock that keeps a poll-driven write from beating a write that protects the owner. The lock manager is a small fake with the
// semantics used here (exclusive, FIFO queue, ifAvailable, abort while waiting, released when the callback settles or throws). Whether the real
// Web Locks API behaves the same ACROSS TABS is the Chromium run, e2e/contact-cas.spec.ts.
//
// Run: npx tsx --test src/lib/contacts/safety-write.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  withSafetyWrite, pollWriteUnlessSafety, safetyLockName, SafetyLockTimeout, resetSafetyWriteFallbackForTests,
  type LockManagerLike,
} from './safety-write';
import { casUpdateWith, ContactConflictError, CAS_MAX_ATTEMPTS } from '../identity/contact-cas';
import { world, type Rec } from '../identity/contact-cas-testkit';

class FakeLocks implements LockManagerLike {
  private held = new Set<string>();
  private waiters = new Map<string, Array<() => void>>();
  requests: string[] = [];
  async request(name: string, options: { ifAvailable?: boolean; signal?: AbortSignal }, callback: (lock: unknown) => Promise<unknown> | unknown): Promise<unknown> {
    this.requests.push(name);
    if (options.ifAvailable) {
      if (this.held.has(name)) return callback(null);
      return this.run(name, callback);
    }
    if (!this.held.has(name)) return this.run(name, callback);
    await new Promise<void>((resolve, reject) => {
      const q = this.waiters.get(name) ?? [];
      const go = () => resolve();
      q.push(go);
      this.waiters.set(name, q);
      options.signal?.addEventListener('abort', () => {
        const i = q.indexOf(go);
        if (i >= 0) q.splice(i, 1);
        reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
      });
    });
    return this.run(name, callback);
  }
  private async run(name: string, callback: (lock: unknown) => Promise<unknown> | unknown): Promise<unknown> {
    this.held.add(name);
    try {
      return await callback({ name });
    } finally {
      this.held.delete(name);
      const next = this.waiters.get(name)?.shift();
      if (next) { this.held.add(name); next(); this.held.delete(name); } // hand over: the waiter's run() re-adds it synchronously
    }
  }
  isHeld(name: string) { return this.held.has(name); }
}
const tick = () => new Promise<void>((r) => setTimeout(r, 0));

test('the lock name is per contact', () => {
  assert.equal(safetyLockName('abc'), 'svrnty-contact:abc');
});

// ── the lock ────────────────────────────────────────────────────────────────────────────────────────────────

test('while a safety write holds a contact, the poll DEFERS that contact (its write does not run) and still applies another', async () => {
  const locks = new FakeLocks();
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const safety = withSafetyWrite('x', async () => { await gate; return 'blocked-x'; }, locks);
  await tick();
  const ran: string[] = [];
  const x = await pollWriteUnlessSafety('x', async () => { ran.push('x'); }, locks);
  const y = await pollWriteUnlessSafety('y', async () => { ran.push('y'); return 1; }, locks);
  assert.deepEqual(x, { deferred: true });
  assert.deepEqual(y, { deferred: false, value: 1 });
  assert.deepEqual(ran, ['y'], "X's poll write did not run; Y's did");
  release();
  assert.equal(await safety, 'blocked-x');
});

test('once the safety write is done, the deferred contact\'s change applies on the next tick', async () => {
  const locks = new FakeLocks();
  await withSafetyWrite('x', async () => undefined, locks);
  const ran: string[] = [];
  const r = await pollWriteUnlessSafety('x', async () => { ran.push('x'); return 'applied'; }, locks);
  assert.deepEqual(r, { deferred: false, value: 'applied' });
  assert.deepEqual(ran, ['x']);
});

test('a safety write waits for a poll write that is already in flight, then runs', async () => {
  const locks = new FakeLocks();
  const order: string[] = [];
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const poll = pollWriteUnlessSafety('x', async () => { order.push('poll-start'); await gate; order.push('poll-end'); }, locks);
  await tick();
  const safety = withSafetyWrite('x', async () => { order.push('safety'); }, locks);
  await tick();
  assert.deepEqual(order, ['poll-start'], 'the safety write has not run while the poll write holds the lock');
  release();
  await Promise.all([poll, safety]);
  assert.deepEqual(order, ['poll-start', 'poll-end', 'safety']);
});

test('two safety writes on one contact run one after the other; on different contacts they do not wait on each other', async () => {
  const locks = new FakeLocks();
  const order: string[] = [];
  let r1!: () => void;
  const g1 = new Promise<void>((r) => { r1 = r; });
  const a = withSafetyWrite('x', async () => { order.push('a-start'); await g1; order.push('a-end'); }, locks);
  const b = withSafetyWrite('x', async () => { order.push('b'); }, locks);
  const c = withSafetyWrite('z', async () => { order.push('c'); }, locks);
  await tick();
  assert.deepEqual(order.sort(), ['a-start', 'c']);
  r1();
  await Promise.all([a, b, c]);
  assert.deepEqual(order.filter((s) => s !== 'c'), ['a-start', 'a-end', 'b']);
});

test('a safety write that throws releases the lock: the contact is not deferred forever', async () => {
  const locks = new FakeLocks();
  await assert.rejects(() => withSafetyWrite('x', async () => { throw new Error('block failed'); }, locks), /block failed/);
  assert.equal(locks.isHeld(safetyLockName('x')), false);
  const r = await pollWriteUnlessSafety('x', async () => 'ok', locks);
  assert.deepEqual(r, { deferred: false, value: 'ok' });
});

test('a poll write that throws releases the lock and the error reaches the caller', async () => {
  const locks = new FakeLocks();
  await assert.rejects(() => pollWriteUnlessSafety('x', async () => { throw new Error('poll write failed'); }, locks), /poll write failed/);
  assert.equal(locks.isHeld(safetyLockName('x')), false);
});

test('a frozen holder does not hang a safety write: it gives up with SafetyLockTimeout and never runs', async () => {
  const locks = new FakeLocks();
  const hold = locks.request(safetyLockName('x'), {}, () => new Promise(() => undefined)); // never settles
  void hold;
  await tick();
  let ran = false;
  await assert.rejects(() => withSafetyWrite('x', async () => { ran = true; }, locks, 20), SafetyLockTimeout);
  assert.equal(ran, false);
});

test('once the lock is granted the write is not on the wait clock: a slow write still completes', async () => {
  const locks = new FakeLocks();
  const r = await withSafetyWrite('x', async () => { await new Promise((res) => setTimeout(res, 60)); return 'slow-ok'; }, locks, 20);
  assert.equal(r, 'slow-ok');
});

// ── the fallback where there are no Web Locks ───────────────────────────────────────────────────────────────

test('FALLBACK: with no lock manager the in-memory count defers the poll while a safety write is in flight in this context', async () => {
  resetSafetyWriteFallbackForTests();
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  const safety = withSafetyWrite('x', async () => { await gate; }, null);
  await tick();
  assert.deepEqual(await pollWriteUnlessSafety('x', async () => 1, null), { deferred: true });
  assert.deepEqual(await pollWriteUnlessSafety('y', async () => 2, null), { deferred: false, value: 2 });
  release();
  await safety;
  assert.deepEqual(await pollWriteUnlessSafety('x', async () => 3, null), { deferred: false, value: 3 });
});

test('FALLBACK: a throwing safety write clears the count; overlapping safety writes keep it until the last finishes', async () => {
  resetSafetyWriteFallbackForTests();
  await assert.rejects(() => withSafetyWrite('x', async () => { throw new Error('boom'); }, null), /boom/);
  assert.deepEqual(await pollWriteUnlessSafety('x', async () => 1, null), { deferred: false, value: 1 });
  let r1!: () => void; let r2!: () => void;
  const a = withSafetyWrite('x', () => new Promise<void>((r) => { r1 = r; }), null);
  const b = withSafetyWrite('x', () => new Promise<void>((r) => { r2 = r; }), null);
  await tick();
  r1(); await a;
  assert.deepEqual(await pollWriteUnlessSafety('x', async () => 1, null), { deferred: true }, 'the second one is still in flight');
  r2(); await b;
  assert.deepEqual(await pollWriteUnlessSafety('x', async () => 1, null), { deferred: false, value: 1 });
});

test('with no navigator in the runtime the default is the fallback (the headless store path)', async () => {
  resetSafetyWriteFallbackForTests();
  assert.equal((globalThis as { navigator?: { locks?: unknown } }).navigator?.locks, undefined);
  assert.deepEqual(await pollWriteUnlessSafety('x', async () => 'v'), { deferred: false, value: 'v' });
});

// ── the property this exists for: a block lands while a rival writes the same record on every attempt ───────

const blockPatch = (e: Rec): Rec => ({ ...e, trust: 'blocked', tags: [...e.tags, 'blocked'] });

test('WITHOUT the lock a rival that writes on every attempt makes the block lose its comparison until it gives up (the hazard)', async () => {
  const w = world('a');
  const rival = w.io();
  const hooks = Array.from({ length: CAS_MAX_ATTEMPTS }, () => async () => { await casUpdateWith(rival, 'a', (e) => ({ ...e, n: e.n + 1 })); });
  await assert.rejects(() => casUpdateWith(w.io(hooks), 'a', blockPatch), ContactConflictError);
  assert.equal(w.get('a').trust, undefined, 'the block was NOT saved');
});

test('WITH the lock the same rival is deferred, the block lands on its first attempt, and the rival\'s change applies on the next tick', async () => {
  const locks = new FakeLocks();
  const w = world('a');
  const rival = w.io();
  const outcomes: boolean[] = [];
  const hooks = Array.from({ length: CAS_MAX_ATTEMPTS }, () => async () => {
    // the rival "poll" tries to write the same record just before the block commits
    const r = await pollWriteUnlessSafety('a', () => casUpdateWith(rival, 'a', (e) => ({ ...e, n: e.n + 1 })), locks);
    outcomes.push(r.deferred);
  });
  const result = await withSafetyWrite('a', () => casUpdateWith(w.io(hooks), 'a', blockPatch), locks);
  assert.equal(result.attempts, 1, 'the block landed on its first attempt');
  assert.equal(w.get('a').trust, 'blocked');
  assert.deepEqual(outcomes, [true], 'the rival was deferred, not run');
  assert.equal(w.get('a').n, 0, 'the rival has not written yet');
  const next = await pollWriteUnlessSafety('a', () => casUpdateWith(rival, 'a', (e) => ({ ...e, n: e.n + 1 })), locks);
  assert.equal(next.deferred, false);
  assert.equal(w.get('a').n, 1, "the rival's change applied on the next tick");
  assert.equal(w.get('a').trust, 'blocked', 'and the block is still there');
  assert.equal(w.manifestConsistent(), true);
});
