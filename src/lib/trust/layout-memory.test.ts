// Run: npx tsx --test src/lib/trust/layout-memory.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  applyLayoutMemory,
  glassStateSignature,
  mutualTopologySignature,
} from './layout-memory';

test('mutualTopologySignature is order-independent', () => {
  const a = mutualTopologySignature([
    { a: 'fpB', b: 'fpA' },
    { a: 'fpC', b: 'fpA' },
  ]);
  const b = mutualTopologySignature([
    { a: 'fpa', b: 'fpc' },
    { a: 'fpa', b: 'fpb' },
  ]);
  assert.equal(a, b);
});

test('applyLayoutMemory softens when topology changed', () => {
  const fresh = [{ id: 'a', x: 0, y: 0 }];
  const memory = new Map([['a', { id: 'a', x: 100, y: 100 }]]);
  const hard = applyLayoutMemory(fresh, memory, 0.8, false);
  const soft = applyLayoutMemory(fresh, memory, 0.8, true);
  // Soft recall stays closer to fresh (0) than hard recall.
  assert.ok(soft[0].x < hard[0].x);
  assert.ok(soft[0].x < 40, `soft blend too sticky: ${soft[0].x}`);
});

test('glassStateSignature is order-independent and sees verify/trust upgrades', () => {
  const a = glassStateSignature([
    { id: 'fpB', state: 'known', verified: true },
    { id: 'fpA', state: 'trusted' },
  ]);
  const b = glassStateSignature([
    { id: 'fpa', state: 'trusted' },
    { id: 'fpb', state: 'known', verified: true },
  ]);
  assert.equal(a, b);
  const before = glassStateSignature([{ id: 'fpA', state: 'known' }]);
  const after = glassStateSignature([{ id: 'fpA', state: 'trusted' }]);
  assert.notEqual(before, after);
});

test('applyLayoutMemory softens more on glass state change than topology', () => {
  const fresh = [{ id: 'a', x: 0, y: 0 }];
  const memory = new Map([['a', { id: 'a', x: 100, y: 100 }]]);
  const topo = applyLayoutMemory(fresh, memory, 0.8, true, false);
  const glass = applyLayoutMemory(fresh, memory, 0.8, false, true);
  assert.ok(glass[0].x < topo[0].x, 'glass upgrade should unstick more than mutual topology');
  assert.ok(glass[0].x < 20, `glass blend too sticky: ${glass[0].x}`);
});
