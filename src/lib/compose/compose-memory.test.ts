// Run: npx tsx --test src/lib/compose/compose-memory.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  NOTICE_INTERVAL_MS, MEMORY_RESOLVED_CAP, MEMORY_NOTICED_CAP,
  emptyMemory, isComposeMemory, pruneMemory, addResolved, isResolved, shouldNotice, markNoticed, mergeMemory, type ComposeMemory,
} from './compose-memory';

const NOW = Date.parse('2026-10-25T13:00:00.000Z');
const nonce = (n: number) => n.toString(16).padStart(32, '0');
const FP_A = 'ab'.repeat(32);
const FP_B = 'cd'.repeat(32);

test('an empty memory is valid and remembers nothing', () => {
  const m = emptyMemory();
  assert.ok(isComposeMemory(m));
  assert.equal(isResolved(m, nonce(1), NOW), false);
  assert.equal(shouldNotice(m, FP_A, NOW), true);
});

test('isComposeMemory is STRICT: wrong version, extra/missing key, bad nonce, bad fp, non-number, negative, over-cap are all NOT a memory', () => {
  const ok: ComposeMemory = { v: 1, resolved: { [nonce(1)]: NOW + 1 }, noticed: { [FP_A]: NOW } };
  assert.ok(isComposeMemory(ok));
  const bad: unknown[] = [
    null, [], 'x', 1, {}, { ...ok, v: 2 }, { ...ok, extra: 1 }, { v: 1, resolved: {} }, { v: 1, noticed: {} },
    { ...ok, resolved: { 'NOT-HEX': NOW } }, { ...ok, resolved: { ['A'.repeat(32)]: NOW } }, { ...ok, resolved: { [nonce(1)]: '5' } },
    { ...ok, resolved: { [nonce(1)]: -1 } }, { ...ok, resolved: { [nonce(1)]: Infinity } }, { ...ok, noticed: { 'abcd': NOW } }, { ...ok, noticed: { [FP_A]: NaN } },
    { ...ok, resolved: [] }, { ...ok, noticed: [] },
    { v: 1, resolved: Object.fromEntries(Array.from({ length: MEMORY_RESOLVED_CAP + 1 }, (_, i) => [nonce(i + 1), NOW + 1])), noticed: {} },
    { v: 1, resolved: {}, noticed: Object.fromEntries(Array.from({ length: MEMORY_NOTICED_CAP + 1 }, (_, i) => [(i + 16).toString(16).padStart(2, '0').repeat(32), NOW])) },
  ];
  for (const b of bad) assert.equal(isComposeMemory(b), false, JSON.stringify(b)?.slice(0, 60));
});

test('C1: a resolved nonce stays resolved until its own expires_at, and not a millisecond longer', () => {
  const m = addResolved(emptyMemory(), nonce(1), NOW + 1000, NOW);
  assert.equal(isResolved(m, nonce(1), NOW), true);
  assert.equal(isResolved(m, nonce(1), NOW + 999), true);
  assert.equal(isResolved(m, nonce(1), NOW + 1000), false);
  assert.equal(isResolved(m, nonce(2), NOW), false, 'another nonce is untouched');
});

test('adding the same nonce again keeps the LATER expiry (a shorter second report never shortens it)', () => {
  let m = addResolved(emptyMemory(), nonce(1), NOW + 5000, NOW);
  m = addResolved(m, nonce(1), NOW + 1000, NOW);
  assert.equal(m.resolved[nonce(1)], NOW + 5000);
});

test('a malformed nonce or time remembers NOTHING and returns the same object', () => {
  const m = emptyMemory();
  for (const [n, t] of [['zz', NOW + 1], ['A'.repeat(32), NOW + 1], [nonce(1), NaN], [nonce(1), -5], [nonce(1), Infinity], [undefined as unknown as string, NOW]] as Array<[string, number]>) {
    assert.equal(addResolved(m, n, t, NOW), m);
  }
});

test('pruneMemory drops lapsed nonces and notices older than 24 h, keeps the rest', () => {
  const m: ComposeMemory = { v: 1, resolved: { [nonce(1)]: NOW - 1, [nonce(2)]: NOW + 1 }, noticed: { [FP_A]: NOW - NOTICE_INTERVAL_MS, [FP_B]: NOW - NOTICE_INTERVAL_MS + 1 } };
  const p = pruneMemory(m, NOW);
  assert.deepEqual(Object.keys(p.resolved), [nonce(2)]);
  assert.deepEqual(Object.keys(p.noticed), [FP_B]);
});

test('BOUNDED: a flood of distinct nonces keeps the cap and the entries that lapse LAST', () => {
  let m = emptyMemory();
  for (let i = 1; i <= MEMORY_RESOLVED_CAP + 40; i++) m = addResolved(m, nonce(i), NOW + 1000 + i, NOW);
  assert.equal(Object.keys(m.resolved).length, MEMORY_RESOLVED_CAP);
  assert.ok(isResolved(m, nonce(MEMORY_RESOLVED_CAP + 40), NOW), 'the newest survives');
  assert.equal(isResolved(m, nonce(1), NOW), false, 'the soonest-to-lapse was evicted');
  assert.ok(isComposeMemory(m));
});

test('C3: the notice is shown once per sender per 24 h; a different sender is independent; it comes back at exactly 24 h', () => {
  let m = emptyMemory();
  assert.equal(shouldNotice(m, FP_A, NOW), true);
  m = markNoticed(m, FP_A, NOW);
  assert.equal(shouldNotice(m, FP_A, NOW + 1), false);
  assert.equal(shouldNotice(m, FP_A, NOW + NOTICE_INTERVAL_MS - 1), false);
  assert.equal(shouldNotice(m, FP_A, NOW + NOTICE_INTERVAL_MS), true);
  assert.equal(shouldNotice(m, FP_B, NOW + 1), true);
});

test('C3: case does not matter for the sender, and a junk fingerprint is never noticed or recorded', () => {
  const m = markNoticed(emptyMemory(), FP_A.toUpperCase(), NOW);
  assert.equal(shouldNotice(m, FP_A, NOW + 1), false);
  for (const junk of ['', 'abcd', 'zz'.repeat(32), undefined as unknown as string]) {
    assert.equal(shouldNotice(emptyMemory(), junk, NOW), false);
    const e = emptyMemory();
    assert.equal(markNoticed(e, junk, NOW), e);
  }
});

test('C3: a clock that went BACKWARDS cannot silence the notice forever', () => {
  const m = markNoticed(emptyMemory(), FP_A, NOW);
  assert.equal(shouldNotice(m, FP_A, NOW - 1000), true);
});

test('BOUNDED: a flood of distinct senders keeps the cap and the newest', () => {
  let m = emptyMemory();
  const fp = (i: number) => (i + 16).toString(16).padStart(2, '0').repeat(32);
  for (let i = 0; i < MEMORY_NOTICED_CAP + 10; i++) m = markNoticed(m, fp(i), NOW + i);
  assert.equal(Object.keys(m.noticed).length, MEMORY_NOTICED_CAP);
  assert.equal(shouldNotice(m, fp(MEMORY_NOTICED_CAP + 9), NOW + MEMORY_NOTICED_CAP + 10), false, 'the newest is remembered');
});

test('mergeMemory is a union taking the LATER value per key, then prunes (another tab wrote since we read)', () => {
  const a: ComposeMemory = { v: 1, resolved: { [nonce(1)]: NOW + 100, [nonce(2)]: NOW + 900 }, noticed: { [FP_A]: NOW - 5 } };
  const b: ComposeMemory = { v: 1, resolved: { [nonce(1)]: NOW + 500, [nonce(3)]: NOW - 1 }, noticed: { [FP_A]: NOW, [FP_B]: NOW - 1 } };
  const m = mergeMemory(a, b, NOW);
  assert.deepEqual(m.resolved, { [nonce(1)]: NOW + 500, [nonce(2)]: NOW + 900 }, 'later wins, lapsed dropped');
  assert.deepEqual(m.noticed, { [FP_A]: NOW, [FP_B]: NOW - 1 });
  assert.ok(isComposeMemory(m));
});

test('functions never mutate their input', () => {
  const m = addResolved(emptyMemory(), nonce(1), NOW + 1000, NOW);
  const snap = JSON.stringify(m);
  addResolved(m, nonce(2), NOW + 1000, NOW); markNoticed(m, FP_A, NOW); pruneMemory(m, NOW + 5000); mergeMemory(m, emptyMemory(), NOW);
  assert.equal(JSON.stringify(m), snap);
});

test('pruneMemory boundary: a nonce whose expiry is EXACTLY now is dropped (it is expired), one millisecond later is kept; a notice exactly 24 h old is dropped', () => {
  const m: ComposeMemory = { v: 1, resolved: { [nonce(1)]: NOW, [nonce(2)]: NOW + 1 }, noticed: { [FP_A]: NOW - NOTICE_INTERVAL_MS, [FP_B]: NOW - NOTICE_INTERVAL_MS + 1 } };
  const p = pruneMemory(m, NOW);
  assert.deepEqual(Object.keys(p.resolved), [nonce(2)]);
  assert.deepEqual(Object.keys(p.noticed), [FP_B]);
});

test('mergeMemory keeps the LATER value whichever side holds it (a smaller value on the second side never shortens a remembered nonce or notice)', () => {
  const a: ComposeMemory = { v: 1, resolved: { [nonce(4)]: NOW + 900 }, noticed: { [FP_A]: NOW } };
  const b: ComposeMemory = { v: 1, resolved: { [nonce(4)]: NOW + 10 }, noticed: { [FP_A]: NOW - 50 } };
  for (const m of [mergeMemory(a, b, NOW - 100), mergeMemory(b, a, NOW - 100)]) {
    assert.equal(m.resolved[nonce(4)], NOW + 900);
    assert.equal(m.noticed[FP_A], NOW);
  }
});
