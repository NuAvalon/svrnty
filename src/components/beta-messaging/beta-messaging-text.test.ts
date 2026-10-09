import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { boundAccessKey } from './beta-messaging-text';
import { BETA_BOUNDS } from './beta-messaging-copy';

describe('boundAccessKey', () => {
  it('trims, strips controls, and bounds length', () => {
    assert.equal(boundAccessKey('  abc  '), 'abc');
    assert.equal(boundAccessKey('a\u0000b'), 'ab');
    const long = 'k'.repeat(BETA_BOUNDS.accessKey + 40);
    assert.equal(boundAccessKey(long).length, BETA_BOUNDS.accessKey);
  });
});
