/**
 * Apollo §2 / gap-freeze KB#87571 — NEGATIVE tests.
 *
 * Tags / blocked / group-cluster labels are device-local. They must NEVER
 * serialize onto publish / PSI-sync / export payloads.
 *
 * Run: npx tsx --test src/components/tags/strip-on-wire.test.ts
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { toVCard, toVCardFile } from '../../lib/contacts/vcard';
import type { TrustEdge } from '../../lib/trust/types';
import type { IdentityCard } from '../../lib/format/envelope';
import { identityCardSigningInput } from '../../lib/format/envelope';
import { CONTACT_UPDATE_ALLOWED_FIELDS as VERIFY_ALLOWLIST } from '../../lib/trust/contact-update';
import { CONTACT_UPDATE_ALLOWED_FIELDS as APPLY_ALLOWLIST } from '../../lib/contacts/apply-contact-update';
import {
  blindFingerprints,
  generatePSIKeypair,
} from '../../lib/trust/mutual-trust-sync';
import { tagPersistPatch } from './local-tags';

/** Marker strings that must never appear on a wire/export serialization. */
const LOCAL_ONLY_MARKERS = [
  'secret-group-label',
  'family-keepers',
  'CATEGORIES',
] as const;

/** Device-local fields that must never enter contact.update / publish allowlists. */
const LOCAL_ONLY_FIELDS = ['tags', 'blocked', 'metadata.tags', 'group', 'groups'] as const;

function poisonedEdge(over: Partial<TrustEdge> = {}): TrustEdge {
  return {
    id: 'x',
    peer_fingerprint: 'aabbccddeeff00112233445566778899',
    peer_name: 'Grace Hopper',
    peer_email: 'grace@navy.mil',
    peer_public_key: '',
    contact_info: { phones: ['+13015550100'], emails: [] },
    trusted: true,
    trusted_since: '2026-01-02T00:00:00Z',
    last_interaction: '',
    decay_days: 730,
    trust_history: [],
    verification: { method: 'none', verified_at: null },
    mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
    tags: ['secret-group-label', 'family-keepers'],
    notes: 'private note',
    connection_channels: [],
    added_at: '',
    blocked: true,
    ...over,
  };
}

function assertNoLocalOnlyLeak(serialized: string, label: string) {
  for (const marker of LOCAL_ONLY_MARKERS) {
    assert.ok(
      !serialized.includes(marker),
      `${label} must not contain local-only marker "${marker}"`
    );
  }
  assert.ok(!/blocked/i.test(serialized), `${label} must not contain blocked`);
}

describe('NEGATIVE: book export strips device-local tags/blocked', () => {
  it('toVCard never emits CATEGORIES, tag labels, or blocked', () => {
    const vcf = toVCard(poisonedEdge());
    assertNoLocalOnlyLeak(vcf, 'toVCard');
    assert.ok(vcf.includes('FN:Grace Hopper'));
    assert.ok(vcf.includes('svrnty fingerprint:'));
  });

  it('toVCardFile strips across every card', () => {
    const file = toVCardFile([
      poisonedEdge({ peer_fingerprint: 'a', peer_name: 'A', tags: ['secret-group-label'] }),
      poisonedEdge({
        peer_fingerprint: 'b',
        peer_name: 'B',
        tags: ['family-keepers'],
        blocked: true,
      }),
    ]);
    assertNoLocalOnlyLeak(file, 'toVCardFile');
  });
});

describe('NEGATIVE: contact.update allowlist excludes tags/blocked', () => {
  it('verify + apply allowlists never admit local-only fields', () => {
    for (const field of LOCAL_ONLY_FIELDS) {
      assert.equal(
        VERIFY_ALLOWLIST.has(field),
        false,
        `verify allowlist must not include "${field}"`
      );
      assert.equal(
        APPLY_ALLOWLIST.has(field),
        false,
        `apply allowlist must not include "${field}"`
      );
    }
  });
});

describe('NEGATIVE: identity-card publish assembly has no tag/blocked slots', () => {
  it('assembled IdentityCard (mirrors buildSignedIdentityCard) never pulls local-only fields', () => {
    // Identity store may carry local organization fields; the SEND assembly must
    // only copy the fleet IdentityCard allowlist (same as buildSignedIdentityCard).
    const idData = {
      fingerprint: 'aabbccddeeff00112233445566778899',
      display_name: 'Ada',
      public_key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----',
      email: 'ada@example.test',
      tags: ['secret-group-label'],
      blocked: true,
      metadata: { tags: ['family-keepers'], blocked: true },
      post_quantum: { sig_public_key: '', kem_public_key: '' },
    };
    const card: IdentityCard = {
      version: '1.0',
      type: 'identity-exchange',
      created_at: '2026-08-30T00:00:00.000Z',
      identity: {
        fingerprint: idData.fingerprint,
        display_name: idData.display_name || '',
        public_key: idData.public_key,
        email: idData.email || '',
        pq_sig_public_key: idData.post_quantum?.sig_public_key || '',
        pq_kem_public_key: idData.post_quantum?.kem_public_key || '',
      },
    };
    const wire = identityCardSigningInput(card);
    assertNoLocalOnlyLeak(wire, 'assembled IdentityCard signing input');
    const parsed = JSON.parse(wire) as IdentityCard;
    assert.deepEqual(Object.keys(parsed).sort(), ['created_at', 'identity', 'type', 'version']);
    assert.deepEqual(Object.keys(parsed.identity).sort(), [
      'display_name',
      'email',
      'fingerprint',
      'pq_kem_public_key',
      'pq_sig_public_key',
      'public_key',
    ]);
  });
});

describe('NEGATIVE: PSI sync input is fingerprints only', () => {
  it('blindFingerprints receives fps — tag labels never enter the blinded set encoding', () => {
    // Mirrors getTrustedFingerprints: peers → fingerprint strings only.
    const peers = [
      { fingerprint: 'fp-adaaaaaaaaaaaaaaaaaaaaaaaaaaaa', tags: ['secret-group-label'], blocked: true },
      { fingerprint: 'fp-graceeeeeeeeeeeeeeeeeeeeeeeeeee', tags: ['family-keepers'] },
    ];
    const trustedFps = peers.map((p) => p.fingerprint);
    assert.deepEqual(trustedFps, [
      'fp-adaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      'fp-graceeeeeeeeeeeeeeeeeeeeeeeeeee',
    ]);
    assert.ok(!JSON.stringify(trustedFps).includes('secret-group-label'));
    assert.ok(!JSON.stringify(trustedFps).includes('family-keepers'));
    assert.ok(!JSON.stringify(trustedFps).includes('tags'));
    assert.ok(!JSON.stringify(trustedFps).includes('blocked'));

    const { privateKey } = generatePSIKeypair();
    const blinded = blindFingerprints(trustedFps, privateKey);
    const body = JSON.stringify({ blinded_set: blinded });
    assertNoLocalOnlyLeak(body, 'PSI blinded_set body');
  });
});

describe('NEGATIVE: tagPersistPatch is local-only shape', () => {
  it('documents the IndexedDB patch — never a publish payload', () => {
    const patch = tagPersistPatch({ notes: 'x' }, ['secret-group-label']);
    // Local shape intentionally HAS tags — that is correct for IndexedDB.
    assert.deepEqual(patch.tags, ['secret-group-label']);
    // Prove we do not mistake this for a wire card: IdentityCard has no tags key.
    const cardKeys = ['version', 'type', 'created_at', 'identity'];
    for (const k of Object.keys(patch)) {
      assert.ok(!cardKeys.includes(k), 'persist patch must not look like IdentityCard');
    }
  });
});
