import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { galaxyNameHit, galaxySearchHitIds, normalizeGalaxyQuery } from './galaxy-search';

describe('galaxy name search', () => {
  it('matches a name without counting or requiring an exact string', () => {
    assert.equal(galaxyNameHit('Ada Lovelace', 'ada'), true);
    assert.equal(galaxyNameHit('Ada Lovelace', 'LOVE'), true);
    assert.equal(galaxyNameHit('Alan Turing', 'ada'), false);
    assert.equal(galaxyNameHit('Ada Lovelace', ''), false);
    assert.equal(galaxyNameHit('Ada Lovelace', '   '), false);
  });

  it('strips bidi and control marks before matching', () => {
    assert.equal(normalizeGalaxyQuery('\u202eAda\u0001'), 'ada');
    assert.equal(galaxyNameHit('Ada Lovelace', '\u202eada'), true);
  });

  it('returns hit ids without inventing stars', () => {
    const nodes = [
      { id: 'a', name: 'Ada Lovelace' },
      { id: 'b', name: 'Alan Turing' },
    ];
    assert.deepEqual(galaxySearchHitIds(nodes, 'ada'), ['a']);
    assert.deepEqual(galaxySearchHitIds(nodes, ''), []);
  });
});
