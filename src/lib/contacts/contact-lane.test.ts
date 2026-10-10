/**
 * contact-lane — Classical vs SVRNTY semantics (UI only).
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateKey, readKey } from 'openpgp';
import {
  buildLinkToSvrntyUpdate,
  contactLane,
  isPendingSvrntyContact,
  readClassicalExtras,
} from './contact-lane';
import {
  bindPastedFingerprintToKey,
  normalizeFingerprintHex,
} from '@/lib/identity/fingerprint';

describe('contactLane', () => {
  it('classifies keyless rows as classical', () => {
    assert.equal(contactLane({ fingerprint: '', public_key: '' }), 'classical');
    assert.equal(contactLane({ fingerprint: 'abcd', public_key: 'pk' }), 'classical');
  });

  it('classifies fingerprint+key as svrnty', () => {
    const fp = 'a'.repeat(16);
    assert.equal(contactLane({ fingerprint: fp, public_key: 'PK' }), 'svrnty');
  });
});

describe('isPendingSvrntyContact', () => {
  const fp = 'b'.repeat(16);

  it('is false for classical', () => {
    assert.equal(isPendingSvrntyContact({ fingerprint: '', public_key: '' }), false);
  });

  it('is true when connection_status is pending', () => {
    assert.equal(
      isPendingSvrntyContact({
        fingerprint: fp,
        public_key: 'PK',
        connection_status: 'pending',
      }),
      true,
    );
  });

  it('is false when active', () => {
    assert.equal(
      isPendingSvrntyContact({
        fingerprint: fp,
        public_key: 'PK',
        connection_status: 'active',
      }),
      false,
    );
  });
});

describe('buildLinkToSvrntyUpdate + bindPastedFingerprintToKey', () => {
  it('rejects a garbage public key', async () => {
    await assert.rejects(
      () =>
        buildLinkToSvrntyUpdate({
          fingerprint: 'c'.repeat(40),
          public_key: 'not-a-key',
          existing: { name: 'Ada' },
        }),
      /not a valid public key/,
    );
  });

  it('stores DERIVED fingerprint and rejects mismatch', async () => {
    const { privateKey: _pk, publicKey } = await generateKey({
      type: 'ecc',
      curve: 'ed25519',
      userIDs: [{ name: 'Link Test', email: 'link@example.invalid' }],
      format: 'armored',
    });
    void _pk;
    const derived = normalizeFingerprintHex(
      (await readKey({ armoredKey: publicKey })).getFingerprint(),
    );
    assert.equal(derived.length, 40);

    await assert.rejects(
      () =>
        bindPastedFingerprintToKey('deadbeef'.repeat(5), publicKey),
      /does not match/i,
    );

    const patch = await buildLinkToSvrntyUpdate({
      fingerprint: derived.toUpperCase().match(/.{1,4}/g)!.join(' '),
      public_key: publicKey,
      existing: {
        name: 'Ada',
        email: 'ada@example.com',
        contact_info: { phones: ['+1'], urls: ['https://x.test'] },
        metadata: { notes: 'met at salon', tags: ['builders'] },
      },
    });
    assert.equal(patch.fingerprint, derived);
    assert.equal(patch.connection_status, 'pending');
    assert.equal(patch.metadata.pending, true);
    const extras = readClassicalExtras({ metadata: patch.metadata as any });
    assert.ok(extras);
    assert.equal(extras?.email, 'ada@example.com');
    assert.deepEqual(extras?.phones, ['+1']);

    // Suffix ≥32 hex accepted; still stores full derived.
    const suffix = derived.slice(-32);
    const bound = await bindPastedFingerprintToKey(suffix, publicKey);
    assert.equal(bound, derived);

    // 16-char suffix is too short — refuse.
    await assert.rejects(
      () => bindPastedFingerprintToKey(derived.slice(-16), publicKey),
      /does not match/i,
    );
  });
});
