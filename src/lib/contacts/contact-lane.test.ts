/**
 * contact-lane — Classical vs SVRNTY semantics (UI only).
 */
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  buildLinkToSvrntyUpdate,
  contactLane,
  isPendingSvrntyContact,
  readClassicalExtras,
} from './contact-lane';

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

describe('buildLinkToSvrntyUpdate', () => {
  it('marks pending and snapshots classical extras', () => {
    const patch = buildLinkToSvrntyUpdate({
      fingerprint: 'c'.repeat(40),
      public_key: 'PUB',
      existing: {
        name: 'Ada',
        email: 'ada@example.com',
        contact_info: { phones: ['+1'], urls: ['https://x.test'] },
        metadata: { notes: 'met at salon', tags: ['builders'] },
      },
    });
    assert.equal(patch.connection_status, 'pending');
    assert.equal(patch.metadata.pending, true);
    const extras = readClassicalExtras({ metadata: patch.metadata as any });
    assert.ok(extras);
    assert.equal(extras?.email, 'ada@example.com');
    assert.deepEqual(extras?.phones, ['+1']);
  });
});
