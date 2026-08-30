import { test } from 'node:test';
import assert from 'node:assert/strict';
import { labelBudget, selectLabels, shortDisplayName, type LabelCandidate } from './label-lod';

test('labelBudget: far zoom is force-only', () => {
  const b = labelBudget(0.3);
  assert.equal(b.cap, 0);
  assert.equal(b.allowTrusted, false);
});

test('labelBudget: mid zoom allows trusted', () => {
  const b = labelBudget(0.8);
  assert.equal(b.allowTrusted, true);
  assert.equal(b.allowKnown, false);
  assert.ok(b.cap > 0);
});

test('selectLabels always keeps force picks even when far', () => {
  const cands: LabelCandidate[] = [
    { id: 'a', name: 'Ada', x: 100, y: 100, r: 8, priority: 'force' },
    { id: 'b', name: 'Bob', x: 120, y: 100, r: 8, priority: 'trusted' },
  ];
  const picks = selectLabels(cands, { viewW: 400, viewH: 400, pxPerWorld: 0.2 });
  assert.deepEqual(
    picks.map((p) => p.id),
    ['a'],
  );
});

test('selectLabels suppresses overlapping mid-zoom labels', () => {
  const cands: LabelCandidate[] = [];
  for (let i = 0; i < 20; i++) {
    cands.push({
      id: `n${i}`,
      name: `Name${i}`,
      x: 100 + (i % 2) * 8,
      y: 100 + Math.floor(i / 2) * 4,
      r: 6,
      priority: 'trusted',
    });
  }
  const picks = selectLabels(cands, {
    viewW: 400,
    viewH: 400,
    pxPerWorld: 1.5,
    boxW: 72,
    boxH: 14,
    pad: 4,
  });
  assert.ok(picks.length < cands.length);
  assert.ok(picks.length >= 1);
});

test('shortDisplayName takes first token', () => {
  assert.equal(shortDisplayName('Ada Lovelace'), 'Ada');
});
