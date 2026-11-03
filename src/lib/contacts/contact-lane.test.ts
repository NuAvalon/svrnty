/**
 * contact-lane — Classical vs SVRNTY semantics (UI only).
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateKey, readKey } from 'openpgp';
import {
  bindLinkTarget,
  buildLinkToSvrntyUpdate,
  linkToSvrntyPatch,
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

    // bindLinkTarget: the derived fingerprint with the key trimmed; a mismatch is refused.
    const target = await bindLinkTarget(derived, `\n  ${publicKey}\n\n`);
    assert.equal(target.fingerprint, derived);
    assert.equal(target.public_key, publicKey.trim());
    await assert.rejects(() => bindLinkTarget('deadbeef'.repeat(5), publicKey), /does not match/i);

    // 16-char suffix is too short — refuse.
    await assert.rejects(
      () => bindPastedFingerprintToKey(derived.slice(-16), publicKey),
      /does not match/i,
    );
  });
});

describe('linkToSvrntyPatch (synchronous, from the record it is given)', () => {
  const bound = { fingerprint: 'ab'.repeat(32), public_key: 'PK' };

  it('builds the pending link with a fixed clock and keeps the metadata it is given', () => {
    const now = new Date('2026-01-02T03:04:05.000Z');
    const p = linkToSvrntyPatch({ name: 'Ada', email: 'a@x', metadata: { tags: ['t'], notes: 'N' } }, bound, now);
    assert.equal(p.fingerprint, bound.fingerprint);
    assert.equal(p.public_key, 'PK');
    assert.equal(p.connection_status, 'pending');
    assert.equal(p.metadata.linked_from_classical_at, '2026-01-02T03:04:05.000Z');
    assert.deepEqual(p.metadata.tags, ['t']);
    assert.equal((p.metadata.classical_extras as { notes?: string }).notes, 'N');
  });

  it('does not mutate the record it is given', () => {
    const existing = { name: 'Ada', metadata: { tags: ['t'] } };
    const before = JSON.stringify(existing);
    linkToSvrntyPatch(existing, bound);
    assert.equal(JSON.stringify(existing), before);
  });
});
