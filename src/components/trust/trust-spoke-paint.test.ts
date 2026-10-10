import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { halfFillVertical, offsetSpokePair } from './trust-spoke-paint';

describe('one-way spoke / half-hex geometry', () => {
  it('dual pair is two parallels, not a dash', () => {
    const [a, b] = offsetSpokePair(0, 0, 10, 0, 1);
    assert.equal(a.y1, 1);
    assert.equal(b.y1, -1);
    assert.equal(a.x1, 0);
    assert.equal(a.x2, 10);
    assert.notEqual(a.y1, b.y1);
  });

  it('half fill is the bottom half — horizontal cut, not a diagonal', () => {
    const clip = halfFillVertical(0, 0, 10);
    const pts = clip.points.split(' ').map((p) => p.split(',').map(Number));
    assert.equal(pts.length, 4);
    assert.equal(pts[0][1], 0);
    assert.equal(pts[1][1], 0);
    assert.ok(pts[2][1] > 0);
    assert.ok(pts[3][1] > 0);
    assert.equal(pts[0][1], pts[1][1]);
  });
});
