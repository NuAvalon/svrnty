// src/lib/notes/held-events.test.ts
// #720: the in-memory held report. Run: npx tsx --test src/lib/notes/held-events.test.ts

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { __resetHeldEventsForTest, clearHeldReport, getHeldReport, reportHeld, subscribeHeld, type HeldReport } from './held-events';

beforeEach(() => __resetHeldEventsForTest());

test('V1 a report replaces the last one; 0 clears it (this is how the notice goes away)', () => {
  reportHeld(3, { expiresAt: '2026-11-03T02:10:00.000Z' });
  assert.deepEqual(getHeldReport(), { count: 3, expiresAt: '2026-11-03T02:10:00.000Z' });
  reportHeld(1);
  assert.deepEqual(getHeldReport(), { count: 1, expiresAt: undefined });
  reportHeld(0, { expiresAt: '2026-11-03T02:10:00.000Z' });
  assert.deepEqual(getHeldReport(), { count: 0 });
});

test('V2 an invalid count is ignored (the last good report stands), a non-string date is dropped', () => {
  reportHeld(2);
  for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '3' as unknown as number]) reportHeld(bad);
  assert.equal(getHeldReport().count, 2);
  reportHeld(2, { expiresAt: 12345 as unknown as string });
  assert.equal(getHeldReport().expiresAt, undefined);
});

test('V3 subscribers are woken only when the report CHANGED, never on a repeat of the same report', () => {
  const seen: HeldReport[] = [];
  subscribeHeld((r) => seen.push(r));
  reportHeld(2, { expiresAt: 'a' });
  reportHeld(2, { expiresAt: 'a' });
  reportHeld(2, { expiresAt: 'a' });
  assert.equal(seen.length, 1);
  reportHeld(2, { expiresAt: 'b' });
  assert.equal(seen.length, 2, 'same count, new date = a change');
  reportHeld(0);
  reportHeld(0);
  assert.equal(seen.length, 3);
});

test('V4 clearHeldReport (session lock / identity switch) empties the report and tells subscribers; clearing twice is silent', () => {
  const seen: HeldReport[] = [];
  reportHeld(4, { expiresAt: 'x' });
  subscribeHeld((r) => seen.push(r));
  clearHeldReport();
  assert.deepEqual(getHeldReport(), { count: 0 });
  assert.deepEqual(seen, [{ count: 0 }]);
  clearHeldReport();
  assert.equal(seen.length, 1);
});

test('V5 a throwing subscriber cannot stop the others, and unsubscribe works', () => {
  const seen: number[] = [];
  subscribeHeld(() => { throw new Error('ui exploded'); });
  const off = subscribeHeld((r) => seen.push(r.count));
  reportHeld(1);
  assert.deepEqual(seen, [1]);
  off();
  reportHeld(2);
  assert.deepEqual(seen, [1]);
});
