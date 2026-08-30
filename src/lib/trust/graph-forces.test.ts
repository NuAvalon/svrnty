// src/lib/trust/graph-forces.test.ts
// Run: npx tsx --test src/lib/trust/graph-forces.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  assignConcentricSlots,
  radiusForCount,
  relaxGraphNodes,
  tagMembership,
} from './graph-forces';

test('radiusForCount grows with roster until maxR', () => {
  const r3 = radiusForCount(3, 40, 120, 30);
  const r12 = radiusForCount(12, 40, 120, 30);
  const r60 = radiusForCount(60, 40, 120, 30);
  assert.ok(r3 >= 40);
  assert.ok(r12 > r3);
  assert.equal(r60, 120);
});

test('assignConcentricSlots spreads evenly across rings', () => {
  const slots = assignConcentricSlots(10, 4);
  assert.equal(slots.length, 10);
  const rings = new Set(slots.map((s) => s.ring));
  assert.equal(rings.size, 3);
  // Each ring's onRing matches how many slots claim that ring
  for (const ring of rings) {
    const onRing = slots.filter((s) => s.ring === ring);
    assert.ok(onRing.every((s) => s.onRing === onRing.length));
    const indices = onRing.map((s) => s.index).sort((a, b) => a - b);
    assert.deepEqual(indices, [...Array(onRing.length).keys()]);
  }
});

test('relaxGraphNodes separates overlapping seals', () => {
  const stacked = [
    { id: 'a', x: 100, y: 100, radius: 10 },
    { id: 'b', x: 101, y: 100, radius: 10 },
    { id: 'c', x: 100, y: 101, radius: 10 },
  ];
  const out = relaxGraphNodes(stacked, {
    width: 400,
    height: 400,
    cx: 200,
    cy: 200,
    padding: 14,
    selfClearance: 0,
    iterations: 40,
    ringGravity: 0,
    clusterGravity: 0,
    repulsion: 0.8,
  });
  for (let i = 0; i < out.length; i++) {
    for (let j = i + 1; j < out.length; j++) {
      const dist = Math.hypot(out[j].x - out[i].x, out[j].y - out[i].y);
      assert.ok(
        dist >= 20 + 14 - 1.5,
        `nodes ${out[i].id}/${out[j].id} still overlap: dist=${dist}`,
      );
    }
  }
});

test('ring gravity restores preferred radius', () => {
  const nodes = [
    { id: 'a', x: 200 + 40, y: 200, radius: 8 },
    { id: 'b', x: 200, y: 200 + 40, radius: 8 },
  ];
  const preferred = new Map([
    ['a', 80],
    ['b', 80],
  ]);
  const out = relaxGraphNodes(nodes, {
    width: 400,
    height: 400,
    cx: 200,
    cy: 200,
    preferredRadius: preferred,
    padding: 8,
    selfClearance: 20,
    iterations: 50,
    ringGravity: 0.35,
    clusterGravity: 0,
    repulsion: 0.3,
  });
  for (const n of out) {
    const r = Math.hypot(n.x - 200, n.y - 200);
    assert.ok(Math.abs(r - 80) < 12, `${n.id} radius ${r} not near 80`);
  }
});

test('cluster gravity pulls same-tag members together', () => {
  const nodes = [
    { id: 'a', x: 80, y: 200, radius: 6 },
    { id: 'b', x: 320, y: 200, radius: 6 },
    { id: 'c', x: 200, y: 80, radius: 6 },
  ];
  const before = Math.hypot(nodes[1].x - nodes[0].x, nodes[1].y - nodes[0].y);
  const out = relaxGraphNodes(nodes, {
    width: 400,
    height: 400,
    cx: 200,
    cy: 200,
    tagMembers: new Map([['crew', ['a', 'b']]]),
    padding: 10,
    selfClearance: 0,
    iterations: 40,
    ringGravity: 0,
    clusterGravity: 0.25,
    repulsion: 0.2,
  });
  const after = Math.hypot(out[1].x - out[0].x, out[1].y - out[0].y);
  assert.ok(after < before * 0.85, `same-tag pair did not converge: ${before} → ${after}`);
  // Untagged node should not be yanked into the pair centroid as hard
  const midX = (out[0].x + out[1].x) / 2;
  const midY = (out[0].y + out[1].y) / 2;
  const cDist = Math.hypot(out[2].x - midX, out[2].y - midY);
  assert.ok(cDist > 40, 'untagged node collapsed into tag cluster');
});

test('tagMembership indexes owner-local tags only', () => {
  const map = tagMembership([
    { peer_fingerprint: 'fp1', tags: ['Family', 'Work'] },
    { peer_fingerprint: 'fp2', tags: ['Family'] },
    { peer_fingerprint: 'fp3', tags: [] },
  ]);
  assert.deepEqual(map.get('Family'), ['fp1', 'fp2']);
  assert.deepEqual(map.get('Work'), ['fp1']);
  assert.equal(map.has(''), false);
});

test('relaxGraphNodes is deterministic', () => {
  const seed = [
    { id: 'x', x: 150, y: 150, radius: 9 },
    { id: 'y', x: 152, y: 148, radius: 9 },
    { id: 'z', x: 148, y: 152, radius: 9 },
  ];
  const opts = {
    width: 360,
    height: 360,
    cx: 180,
    cy: 180,
    preferredRadius: new Map([
      ['x', 70],
      ['y', 70],
      ['z', 90],
    ]),
    tagMembers: new Map([['t', ['x', 'y']]]),
    padding: 12,
    selfClearance: 36,
    iterations: 48,
    ringGravity: 0.2,
    clusterGravity: 0.1,
    repulsion: 0.55,
  };
  const a = relaxGraphNodes(seed, opts);
  const b = relaxGraphNodes(seed, opts);
  assert.deepEqual(
    a.map((n) => [n.id, n.x, n.y]),
    b.map((n) => [n.id, n.x, n.y]),
  );
});
