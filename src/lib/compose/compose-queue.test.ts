// Run: npx tsx --test src/lib/compose/compose-queue.test.ts
// The pending-card queue: one at a time, cap 5, expired dropped, never sign late, a replayed nonce never makes a second card, and a hostile-text
// refusal is a Close-only card that can never be signed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { current, emptyQueue, enqueue, prune, QUEUE_CAP, REFUSAL_TTL_MS, resolve, SEEN_CAP, type QueueState } from './compose-queue';

const T0 = new Date('2026-10-25T07:20:00.000Z');
const at = (sec: number) => new Date(T0.getTime() + sec * 1000);
const nonceN = (n: number) => n.toString(16).padStart(32, '0');
function post(n: number, over: Record<string, string> = {}): Record<string, string> {
  return {
    purpose: 'svrnty-loom-post-v1', fleet: 'autobots', thread: 'lane:ops', body: `hello ${n}`, nonce: nonceN(n),
    issued_at: '2026-10-25T07:20:00.000Z', expires_at: '2026-10-25T07:25:00.000Z', origin: 'noosphere.nuavalon.com', ...over,
  };
}
const add = (s: QueueState, raw: unknown, now = T0) => enqueue(s, raw, now);

test('a valid request becomes ONE sign card; current() shows it; FIFO order', () => {
  let s = emptyQueue();
  const a = add(s, post(1)); assert.deepEqual(a.result, { outcome: 'queued', kind: 'sign' }); s = a.state;
  const b = add(s, post(2)); s = b.state;
  const c = current(s, T0)!;
  assert.equal(c.kind, 'sign');
  assert.equal(c.kind === 'sign' && c.request.object.body, 'hello 1');
  assert.equal(s.pending.length, 2);
});

test('exactly ONE card is ever current, and resolving it advances to the next', () => {
  let s = add(add(emptyQueue(), post(1)).state, post(2)).state;
  const first = current(s, T0)!;
  s = resolve(s, first);
  const second = current(s, T0)!;
  assert.notEqual(second, first);
  assert.equal(second.kind === 'sign' && second.request.object.body, 'hello 2');
  assert.equal(current(resolve(s, second), T0), null);
});

test('REPLAY: the same nonce never makes a second card, whether the first is still queued OR already resolved', () => {
  let s = add(emptyQueue(), post(1)).state;
  assert.deepEqual(add(s, post(1)).result, { outcome: 'duplicate' });
  s = resolve(s, current(s, T0)!);
  assert.equal(s.pending.length, 0);
  const again = add(s, post(1));
  assert.deepEqual(again.result, { outcome: 'duplicate' });
  assert.equal(again.state.pending.length, 0, 'a resolved card cannot be re-raised by replaying the same request');
});

test('CAP: the 6th request is refused as full and the first five are untouched (a flood cannot evict a real request)', () => {
  let s = emptyQueue();
  for (let i = 1; i <= QUEUE_CAP; i++) s = add(s, post(i)).state;
  const before = s.pending.map((p) => p.nonce);
  const sixth = add(s, post(99));
  assert.deepEqual(sixth.result, { outcome: 'full' });
  assert.deepEqual(sixth.state.pending.map((p) => p.nonce), before);
});

test('CAP applies to REFUSAL cards too: with five cards waiting, a hostile-text request is refused as full and shows nothing', () => {
  let s = emptyQueue();
  for (let i = 1; i <= QUEUE_CAP; i++) s = add(s, post(i)).state;
  const r = add(s, post(50, { body: 'a\u202eb' }));
  assert.deepEqual(r.result, { outcome: 'full' });
  assert.equal(r.state.pending.length, QUEUE_CAP);
  assert.ok(r.state.pending.every((p) => p.kind === 'sign'));
});

test('NEVER SIGN LATE: current() never returns an expired item, and prune drops it', () => {
  const s = add(emptyQueue(), post(1)).state;
  assert.ok(current(s, at(299)), 'still valid at 299 s');
  assert.equal(current(s, at(300)), null, 'expired exactly at expires_at (300 s)');
  assert.equal(current(s, at(301)), null);
  assert.equal(prune(s, at(301)).pending.length, 0);
});

test('an expired request is not queued at all; a request issued in the future is not either; both are DROPPED with a code, nothing shown', () => {
  const e = add(emptyQueue(), post(1), at(400));
  assert.deepEqual(e.result, { outcome: 'dropped', code: 'expired' });
  assert.equal(e.state.pending.length, 0);
  const f = add(emptyQueue(), post(2, { issued_at: '2026-10-25T07:22:00.000Z', expires_at: '2026-10-25T07:25:00.000Z' }));
  assert.equal(f.result.outcome, 'dropped');
  assert.equal(f.state.pending.length, 0);
});

test('expired items ahead in the queue do not block a newer valid one: the valid one becomes current', () => {
  let s = add(emptyQueue(), post(1)).state;
  s = add(s, post(2, { issued_at: '2026-10-25T07:23:00.000Z', expires_at: '2026-10-25T07:28:00.000Z' }), at(180)).state;
  const c = current(s, at(310))!; // #1 expired at 300 s, #2 valid until 07:28
  assert.equal(c.kind === 'sign' && c.request.object.body, 'hello 2');
});

test('HOSTILE TEXT: a body with a bidi override becomes a REFUSAL card (Close only), never a sign card', () => {
  const r = add(emptyQueue(), post(1, { body: 'pay now ‮ txt.exe' }));
  assert.deepEqual(r.result, { outcome: 'queued', kind: 'refusal' });
  const it = current(r.state, T0)!;
  assert.equal(it.kind, 'refusal');
  assert.equal(it.kind === 'refusal' && it.refusal.code, 'refused-characters');
  assert.ok(!('request' in it) && !('raw' in it), 'a refusal item carries nothing that could be signed');
});

test('a refusal card goes away after its TTL even if never closed, and closing it remembers the nonce (no re-raise)', () => {
  let s = add(emptyQueue(), post(1, { body: 'x​x' })).state;
  assert.ok(current(s, at(REFUSAL_TTL_MS / 1000 - 1)));
  assert.equal(current(s, at(REFUSAL_TTL_MS / 1000 + 1)), null);
  s = resolve(s, current(s, T0)!);
  assert.deepEqual(add(s, post(1, { body: 'x​x' })).result, { outcome: 'duplicate' });
});

test('every OTHER refusal is dropped with its code and shows nothing (no copy exists for them): unknown field, wrong origin, bad nonce, empty body', () => {
  const cases: Array<[Record<string, unknown>, string]> = [
    [{ ...post(1), extra: 'x' }, 'unknown-field'], [post(2, { origin: 'evil.example' }), 'bad-origin'],
    [post(3, { nonce: 'short' }), 'bad-nonce'], [post(4, { body: '' }), 'empty'], ['not an object' as never, 'not-an-object'],
  ];
  for (const [raw, code] of cases) {
    const r = add(emptyQueue(), raw);
    assert.deepEqual(r.result, { outcome: 'dropped', code }, code);
    assert.equal(r.state.pending.length, 0);
  }
});

test('IMMUTABLE: no function changes the state it was given', () => {
  const s0 = add(emptyQueue(), post(1)).state;
  const frozen = JSON.stringify(s0);
  Object.freeze(s0); Object.freeze(s0.pending); Object.freeze(s0.seen);
  add(s0, post(2)); add(s0, post(1)); prune(s0, at(999)); current(s0, T0); resolve(s0, s0.pending[0]);
  assert.equal(JSON.stringify(s0), frozen);
});

test('the seen-set is bounded (a flood cannot grow memory) and drops the OLDEST nonce first', () => {
  let s = emptyQueue();
  for (let i = 1; i <= SEEN_CAP + 10; i++) { s = add(s, post(i)).state; s = resolve(s, current(s, T0)!); }
  assert.equal(s.seen.length, SEEN_CAP);
  assert.ok(!s.seen.includes(nonceN(1)), 'the oldest is forgotten');
  assert.ok(s.seen.includes(nonceN(SEEN_CAP + 10)), 'the newest is kept');
});

test('a "sign" item keeps the raw request for the signer AND the validated object that is SHOWN (shown === signed is the signer\'s job; both are present)', () => {
  const raw = post(1);
  const it = current(add(emptyQueue(), raw).state, T0)!;
  assert.ok(it.kind === 'sign');
  assert.equal(it.raw, raw);
  assert.deepEqual(it.request.object, raw);
  assert.equal(it.expiresAtMs, Date.parse(raw.expires_at));
});
