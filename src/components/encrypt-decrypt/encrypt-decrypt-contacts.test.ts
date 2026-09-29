import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  findSenderCard,
  isEncryptableContact,
  toEncryptableContacts,
  type ContactRow,
} from './encrypt-decrypt-contacts';

const FP = 'a'.repeat(64);
const KEM = 'K'.repeat(80);
const SIG = 'S'.repeat(80);

function svrn(over: Partial<ContactRow> = {}): ContactRow {
  return {
    id: '1',
    name: 'Ada',
    fingerprint: FP,
    public_key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----',
    pq_kem_public_key: KEM,
    pq_sig_public_key: SIG,
    ...over,
  };
}

describe('encryptable contact filter', () => {
  it('accepts a SVRNTY contact with PQ pubs', () => {
    assert.equal(isEncryptableContact(svrn()), true);
    const [one] = toEncryptableContacts([svrn()]);
    assert.equal(one.fingerprint, FP);
    assert.equal(one.keys.pq_kem_public_key, KEM);
  });

  it('omits classical / keyless rows (never listed as encryptable)', () => {
    assert.equal(isEncryptableContact({ id: 'c', name: 'Phonebook', public_key: '' }), false);
    assert.equal(toEncryptableContacts([{ id: 'c', name: 'Phonebook' }]).length, 0);
  });

  it('omits SVRNTY rows missing PQ pubs', () => {
    assert.equal(isEncryptableContact(svrn({ pq_kem_public_key: '', pq_sig_public_key: SIG })), false);
    assert.equal(isEncryptableContact(svrn({ pq_sig_public_key: '' })), false);
  });

  it('omits blocked contacts', () => {
    assert.equal(isEncryptableContact(svrn({ blocked: true })), false);
    assert.equal(isEncryptableContact(svrn({ metadata: { blocked: true } })), false);
  });

  it('strips control characters from imported display names', () => {
    const [one] = toEncryptableContacts([svrn({ name: 'Ad\u0007a\u202Eevil' })]);
    assert.equal(one.name.includes('\u0007'), false);
    assert.equal(one.name.includes('\u202E'), false);
  });

  it('looks up a claimed sender by exact 64-hex fingerprint', () => {
    const book = toEncryptableContacts([svrn()]);
    assert.equal(findSenderCard(book, FP)?.name, 'Ada');
    assert.equal(findSenderCard(book, 'b'.repeat(64)), null);
    assert.equal(findSenderCard(book, FP.slice(0, 16)), null);
  });
});
