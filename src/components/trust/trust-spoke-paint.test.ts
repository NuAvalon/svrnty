import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { offsetSpokePair } from './trust-spoke-paint';

describe('dual-thin spoke geometry', () => {
  it('dual pair is two parallels, not a dash', () => {
    const [a, b] = offsetSpokePair(0, 0, 10, 0, 1);
    assert.equal(a.y1, 1);
    assert.equal(b.y1, -1);
    assert.equal(a.x1, 0);
    assert.equal(a.x2, 10);
    assert.notEqual(a.y1, b.y1);
  });
});
