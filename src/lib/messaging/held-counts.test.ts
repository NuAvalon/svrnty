// src/lib/messaging/held-counts.test.ts: the PURE rules of the held-count row (held-counts.ts). No storage here; store.ts's use of them is pinned by held-counts-wiring.test.ts and proved in a real browser
// by e2e/freeze-counter.spec.ts.
// Run: npx tsx --test src/lib/messaging/held-counts.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HELD_COUNTS_BUCKET, applyChange, countFrom, countsFromNotes, heldInboundSender, parseHeldCounts, sealedShape, type HeldCounts } from './held-counts';
import type { NoteRecord } from './types';

const A = 'ab'.repeat(32);
const B = 'cd'.repeat(32);
const note = (id: string, from: string, over: Record<string, unknown> = {}): NoteRecord =>
  ({ note_id: id, thread_id: 'T', direction: 'inbound', from_fingerprint: from, to_fingerprints: [], sent_at: '2026-01-02T00:00:00.000Z', body: 'x', participant_kind: 'human', retention: { expires_at: null }, wire_type: 'svrnty-note-v0', ...over }) as unknown as NoteRecord;
const map = (...pairs: Array<[string, number]>): HeldCounts => new Map(pairs);
const sizeOf = (c: HeldCounts): number => JSON.stringify(sealedShape({ state: 'ok', counts: c })).length;

test('H1 a note counts for a sender only when it is HELD (exactly true) and INBOUND; the sender is lower-cased', () => {
  assert.equal(heldInboundSender(note('1', A.toUpperCase(), { held: true })), A);
  assert.equal(heldInboundSender(note('2', A, { held: true, direction: 'outbound' })), null, 'a held OUTBOUND row is not a held note from anyone');
  assert.equal(heldInboundSender(note('3', A)), null, 'an ordinary inbound note does not count');
  for (const loose of ['true', 1, 'yes', {}, []]) assert.equal(heldInboundSender(note('4', A, { held: loose })), null, `held: ${JSON.stringify(loose)} is not held`);
});

test('H2 applyChange moves one row between senders, never goes below 1 or keeps a 0, and never changes its input', () => {
  const start = map([A, 2]);
  assert.deepEqual([...applyChange(start, null, A)], [[A, 3]]);
  assert.deepEqual([...applyChange(start, null, B)].sort(), [[A, 2], [B, 1]]);
  assert.deepEqual([...applyChange(map([A, 1]), A, null)], [], 'at 1, a removal deletes the entry (no stored 0)');
  assert.deepEqual([...applyChange(map(), B, null)], [], 'removing from a sender that is not there stays absent, never negative');
  assert.deepEqual([...applyChange(start, A, B)].sort(), [[A, 1], [B, 1]], 'a row that moves from one sender to another');
  assert.deepEqual([...applyChange(start, A, A)], [[A, 2]], 'no change when before and after agree');
  assert.deepEqual([...start], [[A, 2]], 'the input is untouched');
});

test('H3 countsFromNotes agrees, sender by sender, with the rule the full scan applies (held AND inbound AND the same sender, case-insensitively)', () => {
  const notes = [
    note('1', A, { held: true }), note('2', A.toUpperCase(), { held: true }), note('3', B, { held: true }), note('4', A), note('5', B),
    note('6', A, { held: true, direction: 'outbound' }), note('7', B, { held: 'true' }), note('8', B, { held: true }),
  ];
  const got = countsFromNotes(notes);
  for (const who of [A, B, 'ef'.repeat(32)]) {
    const scan = notes.filter((n) => (n as unknown as { held?: unknown }).held === true && n.direction === 'inbound' && n.from_fingerprint.toLowerCase() === who).length;
    assert.equal(got.get(who) ?? 0, scan, `sender ${who.slice(0, 4)}`);
  }
  assert.deepEqual([...got].sort(), [[A, 2], [B, 2]]);
});

test('H4 the sealed payload is padded to a whole number of buckets: its size does not say how many senders are frozen', () => {
  const many = (k: number): HeldCounts => map(...Array.from({ length: k }, (_, i): [string, number] => [i.toString(16).padStart(64, '0'), 1 + (i % 400)]));
  assert.equal(sizeOf(map()), HELD_COUNTS_BUCKET, 'nobody frozen');
  assert.equal(sizeOf(map([A, 1])), HELD_COUNTS_BUCKET, 'one sender');
  assert.equal(sizeOf(many(30)), HELD_COUNTS_BUCKET, 'thirty senders: same size');
  assert.equal(sizeOf(many(30)), sizeOf(map()), 'so zero and thirty cannot be told apart by size');
  for (const k of [60, 120, 300]) assert.equal(sizeOf(many(k)) % HELD_COUNTS_BUCKET, 0, `${k} senders: a whole number of buckets`);
  assert.ok(sizeOf(many(300)) > HELD_COUNTS_BUCKET, 'and it grows by whole buckets when it must');
  assert.equal(JSON.stringify(sealedShape(null)).length, HELD_COUNTS_BUCKET, 'a dirty marker is the same size too');
});

test('H5 what sealedShape writes, parseHeldCounts reads back exactly (ok and dirty)', () => {
  const ok = parseHeldCounts(JSON.parse(JSON.stringify(sealedShape({ state: 'ok', counts: map([B, 7], [A, 3]) }))));
  assert.ok(ok && ok.state === 'ok');
  assert.deepEqual([...ok.counts].sort(), [[A, 3], [B, 7]]);
  assert.deepEqual(parseHeldCounts(JSON.parse(JSON.stringify(sealedShape({ state: 'dirty' })))), { state: 'dirty' });
  assert.deepEqual(parseHeldCounts(JSON.parse(JSON.stringify(sealedShape({ state: 'ok', counts: map() })))), { state: 'ok', counts: new Map() }, 'an empty, usable row is "nobody frozen", not "unknown"');
});

test('H6 the reader is STRICT: anything the writer never writes is "not understood", never a count', () => {
  const good = (): Record<string, unknown> => JSON.parse(JSON.stringify(sealedShape({ state: 'ok', counts: map([A, 2]) })));
  const bad: Array<[string, unknown]> = [
    ['null', null], ['a string', 'x'], ['an array', []], ['a number', 5],
    ['version 2', { ...good(), v: 2 }], ['no pad', (() => { const g = good(); delete g.pad; return g; })()], ['pad not a string', { ...good(), pad: 7 }],
    ['an extra key', { ...good(), extra: 1 }], ['c not an array', { ...good(), c: {} }], ['unknown state', { ...good(), s: 'maybe' }],
    ['count 0', { ...good(), c: [[A, 0]] }], ['count -1', { ...good(), c: [[A, -1]] }], ['count 1.5', { ...good(), c: [[A, 1.5]] }], ['count huge', { ...good(), c: [[A, 2_000_000]] }],
    ['count a string', { ...good(), c: [[A, '2']] }], ['a duplicate sender', { ...good(), c: [[A, 1], [A, 2]] }], ['an upper-case sender', { ...good(), c: [[A.toUpperCase(), 1]] }],
    ['a sender with a space', { ...good(), c: [['a b', 1]] }], ['an empty sender', { ...good(), c: [['', 1]] }], ['a pair of 3', { ...good(), c: [[A, 1, 2]] }], ['a pair that is not an array', { ...good(), c: ['x'] }],
    ['a dirty marker that carries counts', { ...good(), s: 'dirty' }],
  ];
  for (const [name, raw] of bad) assert.equal(parseHeldCounts(raw), null, name);
});

test('H7 a sender named like an object property is just a sender: nothing reaches the prototype', () => {
  const read = parseHeldCounts({ v: 1, s: 'ok', c: [['__proto__', 2], ['constructor', 1]], pad: '' });
  assert.ok(read && read.state === 'ok');
  assert.equal(read.counts.get('__proto__'), 2);
  assert.equal(read.counts.get('constructor'), 1);
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
  assert.equal(Object.keys({}).length, 0);
});

test('H8 countFrom: a usable row answers (0 for a sender it does not list); absent, dirty and unreadable are FALLBACK reasons, never a number', () => {
  const ok = { state: 'ok', counts: map([A, 5]) } as const;
  assert.deepEqual(countFrom(ok, A), { count: 5 });
  assert.deepEqual(countFrom(ok, A.toUpperCase()), { count: 5 }, 'case-insensitive');
  assert.deepEqual(countFrom(ok, B), { count: 0 }, 'a usable row is the whole truth: not listed = none held');
  assert.deepEqual(countFrom('absent', A), { fallback: 'absent' });
  assert.deepEqual(countFrom({ state: 'dirty' }, A), { fallback: 'dirty' });
  assert.deepEqual(countFrom(null, A), { fallback: 'unreadable' });
  for (const r of ['absent', { state: 'dirty' }, null] as const) assert.ok(!('count' in countFrom(r, A)), 'never a count, so never 0 and never "full"');
});

test('H9 the sealed size is the same for nobody, one sender and the LARGEST count a bucket holds; one more rolls to the next bucket deterministically; only a few distinct sizes ever exist', () => {
  const senders = (k: number): HeldCounts => map(...Array.from({ length: k }, (_, i): [string, number] => [i.toString(16).padStart(64, '0'), 1]));   // canonical-length fingerprints, one held note each
  const size = (k: number): number => sizeOf(senders(k));
  let first = 0;
  while (size(first + 1) === HELD_COUNTS_BUCKET) first++;   // the largest k that still fits ONE bucket
  assert.ok(first >= 40, `a bucket holds a useful number of senders (${first})`);
  for (const k of [0, 1, Math.floor(first / 2), first]) assert.equal(size(k), HELD_COUNTS_BUCKET, `${k} senders`);
  assert.equal(size(first + 1), 2 * HELD_COUNTS_BUCKET, 'one past the bucket rolls to exactly the next one');
  let second = first + 1;
  while (size(second + 1) === 2 * HELD_COUNTS_BUCKET) second++;
  assert.equal(size(second + 1), 3 * HELD_COUNTS_BUCKET, 'and so on, by whole buckets');
  const seen = new Set<number>();
  for (let k = 0; k <= 3 * first; k++) seen.add(size(k));
  assert.ok(seen.size <= 4, `a few sizes only (${[...seen].join(', ')}), never one per sender count`);
  for (const v of seen) assert.equal(v % HELD_COUNTS_BUCKET, 0);
  assert.ok(first > 0 && second > first, 'the boundaries are real');
});

