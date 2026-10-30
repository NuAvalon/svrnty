// src/lib/sync/receipt-outbox.test.ts
// S62 slice 3 R3-1/R3-2/R3-3 (Flint #2094). Fake clock, no timers. Run: npx tsx --test src/lib/sync/receipt-outbox.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createReceiptOutbox } from './receipt-outbox';

const clock = () => { let t = 1_000_000; return { now: () => t, advance: (ms: number) => { t += ms; } }; };
const OWNER = 'ab'.repeat(32);

test('O1 R3-2: one receipt per (owner, note); another owner is separate; clear() forgets, so the note can be answered again in a NEW session', () => {
  const sent: string[] = [];
  const ob = createReceiptOutbox({ maxPerWindow: 100 });
  const mk = (tag: string) => async () => { sent.push(tag); };
  ob.enqueue(OWNER, 'n1', mk('a')); ob.enqueue(OWNER, 'n1', mk('b')); ob.enqueue(OWNER, 'n1', mk('c'));
  ob.enqueue('cd'.repeat(32), 'n1', mk('other-owner'));
  ob.enqueue(OWNER, 'n2', mk('n2'));
  assert.deepEqual(sent, ['a', 'other-owner', 'n2']);
  ob.clear();
  ob.enqueue(OWNER, 'n1', mk('after-clear'));
  assert.deepEqual(sent.slice(3), ['after-clear']);
});

test('O2 R3-1: a send that never returns, rejects, or throws synchronously never blocks, never throws out of enqueue, and does not stop later receipts', () => {
  const ob = createReceiptOutbox({ maxPerWindow: 100 });
  const sent: string[] = [];
  assert.doesNotThrow(() => ob.enqueue(OWNER, 'hang', () => new Promise(() => {})));
  assert.doesNotThrow(() => ob.enqueue(OWNER, 'rej', () => Promise.reject(new Error('relay down'))));
  assert.doesNotThrow(() => ob.enqueue(OWNER, 'throw', () => { throw new Error('sync'); }));
  ob.enqueue(OWNER, 'ok', async () => { sent.push('ok'); });
  assert.deepEqual(sent, ['ok']);
});

test('O3 R3-3 (Flint\'s gate): 12 receipts at once => at most 4 start in the first 60 s, in order; the rest start as the window slides', () => {
  const c = clock();
  const ob = createReceiptOutbox({ now: c.now });
  const started: number[] = [];
  for (let i = 0; i < 12; i++) ob.enqueue(OWNER, `n${i}`, async () => { started.push(i); });
  assert.deepEqual(started, [0, 1, 2, 3], 'only 4 in the first window');
  c.advance(59_000); ob.pump();
  assert.deepEqual(started, [0, 1, 2, 3], 'still inside the window at 59 s');
  c.advance(1_000); ob.pump();
  assert.deepEqual(started, [0, 1, 2, 3, 4, 5, 6, 7], 'the window slid at 60 s: 4 more, in order');
  c.advance(60_000); ob.pump();
  assert.deepEqual(started, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  assert.equal(ob.stats().queued, 0);
});

test('O4 the queue is BOUNDED; overflow is dropped and NOT marked seen, so a later redelivery can still be answered once there is room', () => {
  const c = clock();
  const ob = createReceiptOutbox({ now: c.now, maxPerWindow: 1, maxQueue: 2 });
  const started: string[] = [];
  const mk = (id: string) => async () => { started.push(id); };
  for (const id of ['a', 'b', 'c', 'd', 'e']) ob.enqueue(OWNER, id, mk(id));
  assert.deepEqual(started, ['a']);
  assert.equal(ob.stats().queued, 2, 'b and c queued; d and e dropped');
  c.advance(60_000); ob.pump(); c.advance(60_000); ob.pump();
  assert.deepEqual(started, ['a', 'b', 'c']);
  ob.enqueue(OWNER, 'd', mk('d')); // the dropped one is redelivered later: not remembered as answered, so it gets its receipt
  c.advance(60_000); ob.pump();
  assert.deepEqual(started, ['a', 'b', 'c', 'd']);
});

test('O5 the dedupe set is bounded FIFO (a hostile sender of endless note ids cannot grow it without limit)', () => {
  const ob = createReceiptOutbox({ maxPerWindow: 1000, maxSeen: 3 });
  const sent: string[] = [];
  for (const id of ['1', '2', '3', '4']) ob.enqueue(OWNER, id, async () => { sent.push(id); });
  assert.equal(ob.stats().seen, 3);
  ob.enqueue(OWNER, '1', async () => { sent.push('1-again'); }); // evicted (oldest) => answerable again
  ob.enqueue(OWNER, '4', async () => { sent.push('4-again'); }); // still remembered => ignored
  assert.deepEqual(sent, ['1', '2', '3', '4', '1-again']);
});

test('O6 clear() drops queued receipts and resets the window (a locked session sends nothing later)', () => {
  const c = clock();
  const ob = createReceiptOutbox({ now: c.now, maxPerWindow: 1 });
  const sent: string[] = [];
  for (const id of ['a', 'b', 'c']) ob.enqueue(OWNER, id, async () => { sent.push(id); });
  ob.clear();
  c.advance(120_000); ob.pump();
  assert.deepEqual(sent, ['a']);
  assert.deepEqual(ob.stats(), { queued: 0, seen: 0, startedInWindow: 0 });
});

test('O7 static wiring: every poll tick pumps the outbox (else queued receipts strand until the next accepted note), and a session lock clears it', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('./live-book-poll.ts', import.meta.url), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
  const body = src.slice(src.indexOf('export async function buildConsumeDeps('));
  assert.match(body.slice(0, 600), /receiptOutbox\.pump\(\)/, 'buildConsumeDeps (run every tick) must pump the outbox');
  assert.match(src, /onSessionLock\(\(\) => receiptOutbox\.clear\(\)\)/);
  assert.doesNotMatch(src, /await sendReceipt\(/, 'the receipt must never be awaited on the note path');
});
