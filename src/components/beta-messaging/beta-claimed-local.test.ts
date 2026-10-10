import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { localClaimStorageKey, readLocalBetaClaimed } from './beta-claimed-local';

describe('beta claimed flag is device-local', () => {
  it('keys by fingerprint and never looks like a publish field', () => {
    const k = localClaimStorageKey('ABCD1234');
    assert.match(k, /^svrnty\.beta-messaging\.claimed:abcd1234$/);
    assert.doesNotMatch(k, /psi|publish|export/i);
  });

  it('is false in node (no window) — unclaimed ≠ a throw', () => {
    assert.equal(readLocalBetaClaimed('abcd'), false);
    assert.equal(readLocalBetaClaimed(''), false);
  });
});
