import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { isNoteableContact, toNoteableContacts } from './notes-contacts';

const CARD = {
  id: '1',
  name: 'Ada',
  fingerprint: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  public_key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nMII\n-----END PGP PUBLIC KEY BLOCK-----',
};

describe('notes sendable contacts', () => {
  it('accepts a SVRN card with a public key', () => {
    assert.equal(isNoteableContact(CARD), true);
    assert.equal(toNoteableContacts([CARD])[0]?.name, 'Ada');
  });

  it('omits blocked, keyless, and duplicate fingerprints', () => {
    const blocked = { ...CARD, id: '2', blocked: true };
    const keyless = { ...CARD, id: '3', name: 'Gray', public_key: '' };
    const dup = { ...CARD, id: '4', name: 'Ada 2' };
    const out = toNoteableContacts([CARD, blocked, keyless, dup]);
    assert.equal(out.length, 1);
    assert.equal(out[0].fingerprint, CARD.fingerprint);
  });

  it('does not require peer PQ pubs (seal is to the armored key)', () => {
    assert.equal(isNoteableContact(CARD), true);
  });
});
