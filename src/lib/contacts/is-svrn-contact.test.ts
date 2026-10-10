import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { isClassicalAddressBookContact, isSvrnNetworkContact } from './is-svrn-contact';

describe('isSvrnNetworkContact', () => {
  it('treats keyless / short-fp rows as classical', () => {
    assert.equal(isSvrnNetworkContact({ fingerprint: '', public_key: '' }), false);
    assert.equal(isSvrnNetworkContact({ fingerprint: 'abcd', public_key: 'pk' }), false);
    assert.equal(isClassicalAddressBookContact({ fingerprint: '', public_key: '' }), true);
  });

  it('treats fingerprint+key peers as SVRN network', () => {
    const fp = 'a'.repeat(40);
    assert.equal(isSvrnNetworkContact({ fingerprint: fp, public_key: 'PK' }), true);
    assert.equal(isClassicalAddressBookContact({ fingerprint: fp, public_key: 'PK' }), false);
  });
});
