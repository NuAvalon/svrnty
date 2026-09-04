// src/lib/trust/graph-forces.test.ts
// Run: npx tsx --test src/lib/trust/graph-forces.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  convexHull,
  latticeChords,
  relaxGraphNodes,
  seedEgocentric,
  seedPhyllotaxis,
  tagMembership,
} from './graph-forces';

test('seedPhyllotaxis is even packing — radii are not a single ring', () => {
  const pts = seedPhyllotaxis(16, 200, 200, 40, 80);
  assert.equal(pts.length, 16);
  const rs = pts.map((p) => Math.hypot(p.x - 200, p.y - 200));
  const min = Math.min(...rs);
  const max = Math.max(...rs);
  assert.ok(max - min > 30, `sunflower collapsed to a ring: ${min}–${max}`);
});

test('seedEgocentric groups same-tag ids into a sector, not by trust', () => {
  const ids = [
    { id: 'a', tags: ['crew'] },
    { id: 'b', tags: ['crew'] },
    { id: 'c', tags: ['other'] },
    { id: 'd', tags: ['other'] },
  ];
  const pts = seedEgocentric(ids, 200, 200, 50, 90);
  const byId = Object.fromEntries(pts.map((p) => [p.id, p]));
  const crew = Math.hypot(byId.a.x - byId.b.x, byId.a.y - byId.b.y);
  const other = Math.hypot(byId.c.x - byId.d.x, byId.c.y - byId.d.y);
  const cross = Math.hypot(byId.a.x - byId.c.x, byId.a.y - byId.c.y);
  assert.ok(crew < cross * 1.15 || other < cross, 'tag sectors did not form');
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
    clusterGravity: 0,
    centerGravity: 0,
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

test('mutual-bond springs pull witnessed peers closer', () => {
  const nodes = [
    { id: 'a', x: 60, y: 200, radius: 8 },
    { id: 'b', x: 340, y: 200, radius: 8 },
    { id: 'c', x: 200, y: 60, radius: 8 },
  ];
  const before = Math.hypot(nodes[1].x - nodes[0].x, nodes[1].y - nodes[0].y);
  const out = relaxGraphNodes(nodes, {
    width: 400,
    height: 400,
    cx: 200,
    cy: 200,
    mutualBonds: [{ a: 'a', b: 'b' }],
    mutualBondGravity: 0.35,
    mutualBondRest: 70,
    padding: 10,
    selfClearance: 0,
    iterations: 50,
    clusterGravity: 0,
    centerGravity: 0,
    repulsion: 0.15,
  });
  const after = Math.hypot(out[1].x - out[0].x, out[1].y - out[0].y);
  assert.ok(after < before * 0.55, `mutual pair did not converge: ${before} → ${after}`);
  const midX = (out[0].x + out[1].x) / 2;
  const midY = (out[0].y + out[1].y) / 2;
  const cDist = Math.hypot(out[2].x - midX, out[2].y - midY);
  assert.ok(cDist > 50, 'unbonded node collapsed into mutual pair');
});

test('mutual bonds are not invented from tags — only explicit springs move pairs', () => {
  const nodes = [
    { id: 'a', x: 80, y: 200, radius: 6 },
    { id: 'b', x: 320, y: 200, radius: 6 },
  ];
  const before = Math.hypot(nodes[1].x - nodes[0].x, nodes[1].y - nodes[0].y);
  // Same tags alone via cluster gravity — separate concern; here NO mutualBonds, NO tagMembers
  const out = relaxGraphNodes(nodes, {
    width: 400,
    height: 400,
    cx: 200,
    cy: 200,
    mutualBonds: [],
    mutualBondGravity: 0.4,
    padding: 10,
    selfClearance: 0,
    iterations: 40,
    clusterGravity: 0,
    centerGravity: 0,
    repulsion: 0.1,
  });
  const after = Math.hypot(out[1].x - out[0].x, out[1].y - out[0].y);
  assert.ok(
    Math.abs(after - before) < 8,
    `empty mutualBonds moved the pair: ${before} → ${after}`,
  );
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
    clusterGravity: 0.25,
    centerGravity: 0,
    repulsion: 0.2,
  });
  const after = Math.hypot(out[1].x - out[0].x, out[1].y - out[0].y);
  assert.ok(after < before * 0.85, `same-tag pair did not converge: ${before} → ${after}`);
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

test('latticeChords are k-NN within a tag, not a complete graph', () => {
  const contacts = [
    { peer_fingerprint: 'a', tags: ['g'] },
    { peer_fingerprint: 'b', tags: ['g'] },
    { peer_fingerprint: 'c', tags: ['g'] },
    { peer_fingerprint: 'd', tags: ['g'] },
  ];
  const positions = new Map([
    ['a', { x: 0, y: 0 }],
    ['b', { x: 10, y: 0 }],
    ['c', { x: 100, y: 0 }],
    ['d', { x: 110, y: 0 }],
  ]);
  const chords = latticeChords(contacts, positions, 1);
  // 4 nodes × 1 neighbor, undirected → 2 components of pairs, not K4
  assert.ok(chords.length <= 4);
  assert.ok(chords.every((c) => c.tag === 'g'));
  assert.ok(!chords.some((c) => (c.a === 'a' && c.b === 'd') || (c.a === 'd' && c.b === 'a')));
});

test('convexHull is the outer polygon', () => {
  const hull = convexHull([
    { x: 0, y: 0 },
    { x: 10, y: 0 },
    { x: 10, y: 10 },
    { x: 0, y: 10 },
    { x: 5, y: 5 },
  ]);
  assert.equal(hull.length, 4);
  assert.ok(!hull.some((p) => p.x === 5 && p.y === 5));
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
    tagMembers: new Map([['t', ['x', 'y']]]),
    padding: 12,
    selfClearance: 36,
    iterations: 48,
    clusterGravity: 0.1,
    centerGravity: 0.03,
    repulsion: 0.55,
  };
  const a = relaxGraphNodes(seed, opts);
  const b = relaxGraphNodes(seed, opts);
  assert.deepEqual(
    a.map((n) => [n.id, n.x, n.y]),
    b.map((n) => [n.id, n.x, n.y]),
  );
});
