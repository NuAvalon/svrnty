import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { halfFillToward, offsetSpokePair } from './trust-spoke-paint';

describe('one-way spoke / half-hex geometry', () => {
  it('dual pair is two parallels, not a dash', () => {
    const [a, b] = offsetSpokePair(0, 0, 10, 0, 1);
    assert.equal(a.y1, 1);
    assert.equal(b.y1, -1);
    assert.equal(a.x1, 0);
    assert.equal(a.x2, 10);
    assert.notEqual(a.y1, b.y1);
  });

  it('half fill faces you, not a full core', () => {
    const clip = halfFillToward(0, 0, 10, -20, 0);
    assert.match(clip.points, /-/);
    assert.ok(clip.points.split(' ').length >= 4);
  });
});
