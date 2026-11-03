// The locks that keep a poll-driven write from beating a write that protects the owner. The lock manager is a small fake with the semantics
// used here: exclusive and shared modes, a FIFO queue (a request is granted only if nothing conflicts AND no earlier request is waiting),
// ifAvailable, abort while waiting, and release when the callback settles or throws. Whether the real Web Locks API behaves the same ACROSS
// TABS is the Chromium run, e2e/contact-cas.spec.ts.
//
// Run: npx tsx --test src/lib/contacts/safety-write.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  withSafetyWrite, pollWriteUnlessSafety, safetyLockName, describeSafetyWriteFailure, SafetyLockTimeout,
  SAFETY_BOOK_LOCK, resetSafetyWriteFallbackForTests, type LockManagerLike,
} from './safety-write';
import { casUpdateWith, ContactConflictError, CAS_MAX_ATTEMPTS } from '../identity/contact-cas';
import { world, type Rec } from '../identity/contact-cas-testkit';

type Mode = 'shared' | 'exclusive';
interface Waiter { mode: Mode; grant: () => void }

class FakeLocks implements LockManagerLike {
  private held = new Map<string, Mode[]>();
  private queue = new Map<string, Waiter[]>();
  private modes(name: string) { return this.held.get(name) ?? []; }
  private waiting(name: string) { return this.queue.get(name) ?? []; }
  private conflicts(name: string, mode: Mode) {
    const h = this.modes(name);
    return mode === 'exclusive' ? h.length > 0 : h.includes('exclusive');
  }
  private grantable(name: string, mode: Mode) { return this.waiting(name).length === 0 && !this.conflicts(name, mode); }
  private take(name: string, mode: Mode) { this.held.set(name, [...this.modes(name), mode]); }
  private release(name: string, mode: Mode) {
    const h = [...this.modes(name)];
    h.splice(h.indexOf(mode), 1);
    this.held.set(name, h);
    this.pump(name);
  }
  private pump(name: string) {
    const q = this.waiting(name);
    while (q.length && !this.conflicts(name, q[0].mode)) {
      const w = q.shift()!;
      this.take(name, w.mode);
      w.grant();
    }
  }
  async request(name: string, options: { mode?: Mode; ifAvailable?: boolean; signal?: AbortSignal }, callback: (lock: unknown) => Promise<unknown> | unknown): Promise<unknown> {
    const mode: Mode = options.mode ?? 'exclusive';
    if (options.ifAvailable) {
      if (!this.grantable(name, mode)) return callback(null);
      this.take(name, mode);
      return this.run(name, mode, callback);
    }
    if (this.grantable(name, mode)) {
      this.take(name, mode);
      return this.run(name, mode, callback);
    }
    await new Promise<void>((resolve, reject) => {
      const w: Waiter = { mode, grant: resolve };
      this.queue.set(name, [...this.waiting(name), w]);
      options.signal?.addEventListener('abort', () => {
        const q = this.waiting(name);
        const i = q.indexOf(w);
        if (i >= 0) { q.splice(i, 1); this.pump(name); reject(Object.assign(new Error('aborted'), { name: 'AbortError' })); }
      });
    });
    return this.run(name, mode, callback);
  }
  private async run(name: string, mode: Mode, callback: (lock: unknown) => Promise<unknown> | unknown): Promise<unknown> {
    try { return await callback({ name }); } finally { this.release(name, mode); }
  }
  isHeld(name: string) { return this.modes(name).length > 0; }
}
const tick = () => new Promise<void>((r) => setTimeout(r, 0));
const gateOf = () => { let release!: () => void; const gate = new Promise<void>((r) => { release = r; }); return { gate, release }; };

test('the lock names: one for the book, one per contact', () => {
  assert.equal(SAFETY_BOOK_LOCK, 'svrnty-contact-book');
  assert.equal(safetyLockName('abc'), 'svrnty-contact:abc');
});

// ── the book lock ───────────────────────────────────────────────────────────────────────────────────────────

test('while a safety write is held, the poll DEFERS (its write does not run), for ANY contact of the book', async () => {
  const locks = new FakeLocks();
  const { gate, release } = gateOf();
  const safety = withSafetyWrite('x', async () => { await gate; return 'protected-x'; }, locks);
  await tick();
  const ran: string[] = [];
  const forX = await pollWriteUnlessSafety(async () => { ran.push('x'); }, locks);
  const forY = await pollWriteUnlessSafety(async () => { ran.push('y'); }, locks);
  assert.deepEqual(forX, { deferred: true });
  assert.deepEqual(forY, { deferred: true }, 'a different contact is deferred too: the conflict domain is the whole book');
  assert.deepEqual(ran, []);
  release();
  assert.equal(await safety, 'protected-x');
});

test('once the safety write is done, the deferred change applies on the next tick', async () => {
  const locks = new FakeLocks();
  await withSafetyWrite('x', async () => undefined, locks);
  const ran: string[] = [];
  const r = await pollWriteUnlessSafety(async () => { ran.push('x'); return 'applied'; }, locks);
  assert.deepEqual(r, { deferred: false, value: 'applied' });
  assert.deepEqual(ran, ['x']);
});

test('a safety write waits for a poll write that is already in flight, then runs', async () => {
  const locks = new FakeLocks();
  const order: string[] = [];
  const { gate, release } = gateOf();
  const poll = pollWriteUnlessSafety(async () => { order.push('poll-start'); await gate; order.push('poll-end'); }, locks);
  await tick();
  const safety = withSafetyWrite('x', async () => { order.push('safety'); }, locks);
  await tick();
  assert.deepEqual(order, ['poll-start'], 'the safety write has not run while the poll write holds the book');
  release();
  await Promise.all([poll, safety]);
  assert.deepEqual(order, ['poll-start', 'poll-end', 'safety']);
});

test('a safety write that is QUEUED behind an in-flight poll write already defers the next poll (nothing can slip in ahead of it)', async () => {
  const locks = new FakeLocks();
  const order: string[] = [];
  const { gate, release } = gateOf();
  const poll1 = pollWriteUnlessSafety(async () => { order.push('poll1'); await gate; }, locks);
  await tick();
  const safety = withSafetyWrite('x', async () => { order.push('safety'); }, locks);
  await tick();
  const poll2 = await pollWriteUnlessSafety(async () => { order.push('poll2'); }, locks);
  assert.deepEqual(poll2, { deferred: true }, 'the waiting safety write blocks a later poll');
  release();
  await Promise.all([poll1, safety]);
  assert.deepEqual(order, ['poll1', 'safety']);
});

test('safety writes do not wait on each other across contacts; on one contact they run one after the other', async () => {
  const locks = new FakeLocks();
  const order: string[] = [];
  const g1 = gateOf();
  const a = withSafetyWrite('x', async () => { order.push('a-start'); await g1.gate; order.push('a-end'); }, locks);
  const b = withSafetyWrite('x', async () => { order.push('b'); }, locks);
  const c = withSafetyWrite('z', async () => { order.push('c'); }, locks);
  await tick();
  assert.deepEqual([...order].sort(), ['a-start', 'c'], 'z ran alongside x; the second x write waits for the first');
  g1.release();
  await Promise.all([a, b, c]);
  assert.deepEqual(order.filter((s) => s !== 'c'), ['a-start', 'a-end', 'b']);
});

test('a safety write that throws releases both locks: the book is not deferred forever', async () => {
  const locks = new FakeLocks();
  await assert.rejects(() => withSafetyWrite('x', async () => { throw new Error('block failed'); }, locks), /block failed/);
  assert.equal(locks.isHeld(SAFETY_BOOK_LOCK), false);
  assert.equal(locks.isHeld(safetyLockName('x')), false);
  assert.deepEqual(await pollWriteUnlessSafety(async () => 'ok', locks), { deferred: false, value: 'ok' });
});

test('a poll write that throws releases the book and the error reaches the caller', async () => {
  const locks = new FakeLocks();
  await assert.rejects(() => pollWriteUnlessSafety(async () => { throw new Error('poll write failed'); }, locks), /poll write failed/);
  assert.equal(locks.isHeld(SAFETY_BOOK_LOCK), false);
});

test('a frozen holder does not hang a safety write: SafetyLockTimeout, the write never runs (book lock held)', async () => {
  const locks = new FakeLocks();
  void locks.request(SAFETY_BOOK_LOCK, { mode: 'exclusive' }, () => new Promise(() => undefined)); // never settles
  await tick();
  let ran = false;
  await assert.rejects(() => withSafetyWrite('x', async () => { ran = true; }, locks, 20), SafetyLockTimeout);
  assert.equal(ran, false);
});

test('a frozen holder of the CONTACT lock times out too, and the book lock it had taken is given back', async () => {
  const locks = new FakeLocks();
  void locks.request(safetyLockName('x'), { mode: 'exclusive' }, () => new Promise(() => undefined)); // never settles
  await tick();
  await assert.rejects(() => withSafetyWrite('x', async () => undefined, locks, 20), SafetyLockTimeout);
  assert.equal(locks.isHeld(SAFETY_BOOK_LOCK), false, 'the failed safety write does not leave the book deferred');
  assert.deepEqual(await pollWriteUnlessSafety(async () => 1, locks), { deferred: false, value: 1 });
});

test('once the locks are granted the write is not on the wait clock: a slow write still completes', async () => {
  const locks = new FakeLocks();
  assert.equal(await withSafetyWrite('x', async () => { await new Promise((res) => setTimeout(res, 60)); return 'slow-ok'; }, locks, 20), 'slow-ok');
});

// ── the fallback where there are no Web Locks ───────────────────────────────────────────────────────────────

test('FALLBACK: with no lock manager the in-memory count defers the poll while a safety write is in flight in this context', async () => {
  resetSafetyWriteFallbackForTests();
  const { gate, release } = gateOf();
  const safety = withSafetyWrite('x', async () => { await gate; }, null);
  await tick();
  assert.deepEqual(await pollWriteUnlessSafety(async () => 1, null), { deferred: true });
  release();
  await safety;
  assert.deepEqual(await pollWriteUnlessSafety(async () => 3, null), { deferred: false, value: 3 });
});

test('FALLBACK: a throwing safety write clears the count; overlapping safety writes keep it until the last finishes', async () => {
  resetSafetyWriteFallbackForTests();
  await assert.rejects(() => withSafetyWrite('x', async () => { throw new Error('boom'); }, null), /boom/);
  assert.deepEqual(await pollWriteUnlessSafety(async () => 1, null), { deferred: false, value: 1 });
  let r1!: () => void; let r2!: () => void;
  const a = withSafetyWrite('x', () => new Promise<void>((r) => { r1 = r; }), null);
  const b = withSafetyWrite('y', () => new Promise<void>((r) => { r2 = r; }), null);
  await tick();
  r1(); await a;
  assert.deepEqual(await pollWriteUnlessSafety(async () => 1, null), { deferred: true }, 'the second one is still in flight');
  r2(); await b;
  assert.deepEqual(await pollWriteUnlessSafety(async () => 1, null), { deferred: false, value: 1 });
});

test('with no navigator in the runtime the default is the fallback (the headless store path)', async () => {
  resetSafetyWriteFallbackForTests();
  assert.equal((globalThis as { navigator?: { locks?: unknown } }).navigator?.locks, undefined);
  assert.deepEqual(await pollWriteUnlessSafety(async () => 'v'), { deferred: false, value: 'v' });
});

// ── the words for a protecting write that could not be saved ────────────────────────────────────────────────

test('describeSafetyWriteFailure: contention is told in plain words, any other error is left to the caller', () => {
  assert.equal(describeSafetyWriteFailure(new SafetyLockTimeout('x'), 'Block'), 'Block not saved. Try again.');
  assert.equal(describeSafetyWriteFailure(new ContactConflictError('x', 5), 'Unblock'), 'Unblock not saved. Try again.');
  assert.equal(describeSafetyWriteFailure(new Error('Session locked'), 'Block'), null);
  assert.equal(describeSafetyWriteFailure('boom', 'Block'), null);
  assert.equal(describeSafetyWriteFailure(undefined, 'Block'), null);
});

// ── the property this exists for ────────────────────────────────────────────────────────────────────────────

const blockPatch = (e: Rec): Rec => ({ ...e, trust: 'blocked', tags: [...e.tags, 'blocked'] });
const bumpVersion = (e: Rec): Rec => ({ ...e, version: (e.version ?? 0) + 1 });

test('WITHOUT any lock a rival that writes the same record on every attempt makes the block lose 5 comparisons and not save (the hazard)', async () => {
  const w = world('a');
  const rival = w.io();
  const hooks = Array.from({ length: CAS_MAX_ATTEMPTS }, () => async () => { await casUpdateWith(rival, 'a', (e) => ({ ...e, n: e.n + 1 })); });
  await assert.rejects(() => casUpdateWith(w.io(hooks), 'a', blockPatch), ContactConflictError);
  assert.equal(w.get('a').trust, undefined, 'the block was NOT saved');
});

test('a lock PER CONTACT alone is not enough: a different contact whose updates bump its version changes the manifest and still starves the block', async () => {
  const locks = new FakeLocks();
  const w = world('a', 'b');
  const otherIo = w.io();
  const deferred: boolean[] = [];
  const hooks = Array.from({ length: CAS_MAX_ATTEMPTS }, () => async () => {
    // the pre-fix poll: it took only the lock of the contact it writes ('b'), never the block target's ('a')
    const r = (await locks.request(safetyLockName('b'), { mode: 'exclusive', ifAvailable: true }, async (lock) =>
      lock ? (await casUpdateWith(otherIo, 'b', bumpVersion), false) : true)) as boolean;
    deferred.push(r);
  });
  await assert.rejects(
    () => locks.request(safetyLockName('a'), { mode: 'exclusive' }, () => casUpdateWith(w.io(hooks), 'a', blockPatch)),
    ContactConflictError,
  );
  assert.deepEqual(deferred, [false, false, false, false, false], 'the other contact was never deferred');
  assert.equal(w.get('a').trust, undefined, 'the block was NOT saved');
});

test('WITH the book lock the same other contact is deferred, the block lands on its first attempt, and the other contact\'s change applies on the next tick', async () => {
  const locks = new FakeLocks();
  const w = world('a', 'b');
  const otherIo = w.io();
  const deferred: boolean[] = [];
  const hooks = Array.from({ length: CAS_MAX_ATTEMPTS }, () => async () => {
    const r = await pollWriteUnlessSafety(() => casUpdateWith(otherIo, 'b', bumpVersion), locks);
    deferred.push(r.deferred);
  });
  const result = await withSafetyWrite('a', () => casUpdateWith(w.io(hooks), 'a', blockPatch), locks);
  assert.equal(result.attempts, 1, 'the block landed on its first attempt');
  assert.equal(w.get('a').trust, 'blocked');
  assert.deepEqual(deferred, [true], 'the other contact was deferred, not run');
  assert.equal(w.get('b').version, 0, 'the other contact has not written yet');
  const next = await pollWriteUnlessSafety(() => casUpdateWith(otherIo, 'b', bumpVersion), locks);
  assert.equal(next.deferred, false);
  assert.equal(w.get('b').version, 1, "the other contact's change applied on the next tick");
  assert.equal(w.get('a').trust, 'blocked', 'and the block is still there');
  assert.equal(w.manifestConsistent(), true);
});

test('WITH the book lock a rival that writes the SAME record is deferred too, and applies after', async () => {
  const locks = new FakeLocks();
  const w = world('a');
  const rival = w.io();
  const outcomes: boolean[] = [];
  const hooks = Array.from({ length: CAS_MAX_ATTEMPTS }, () => async () => {
    const r = await pollWriteUnlessSafety(() => casUpdateWith(rival, 'a', (e) => ({ ...e, n: e.n + 1 })), locks);
    outcomes.push(r.deferred);
  });
  const result = await withSafetyWrite('a', () => casUpdateWith(w.io(hooks), 'a', blockPatch), locks);
  assert.equal(result.attempts, 1);
  assert.equal(w.get('a').trust, 'blocked');
  assert.deepEqual(outcomes, [true]);
  assert.equal(w.get('a').n, 0);
  assert.equal((await pollWriteUnlessSafety(() => casUpdateWith(rival, 'a', (e) => ({ ...e, n: e.n + 1 })), locks)).deferred, false);
  assert.equal(w.get('a').n, 1);
  assert.equal(w.get('a').trust, 'blocked');
  assert.equal(w.manifestConsistent(), true);
});
