// src/lib/sync/live-book-poll.test.ts
// recordToKnownContact — the one bit of real mapping in the runtime poll wiring (client-store
// ContactRecord → the verify seam's KnownContactIdentity). buildContactStore / startLiveBookPolling
// are runtime glue over IndexedDB + timers, covered end-to-end by the beat-4 e2e (demo-arc.spec.ts).
//
// Run: npx tsx --test src/lib/sync/live-book-poll.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { recordToKnownContact } from './live-book-poll';
import type { ContactRecord } from '@/lib/identity/client-store';

function record(over: Partial<ContactRecord> = {}): ContactRecord {
  return {
    id: 'c1',
    fingerprint: 'fp-bob',
    name: 'Bob',
    email: 'bob@example.test',
    public_key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAA\n-----END PGP PUBLIC KEY BLOCK-----',
    trust_level: 'known',
    added_at: '2026-08-01T00:00:00.000Z',
    ...over,
  } as ContactRecord;
}

test('maps fingerprint + armored key + epoch/version through', () => {
  const known = recordToKnownContact(record({ epoch: 3, version: 7 }));
  assert.equal(known.fingerprint, 'fp-bob');
  assert.equal(known.epoch, 3);
  assert.equal(known.version, 7);
  assert.ok(known.classicalPublicKeyArmored.includes('PGP PUBLIC KEY'));
});

test('defaults epoch/version to 0 for a v1 record (the lowest replay floor)', () => {
  const known = recordToKnownContact(record()); // no epoch/version
  assert.equal(known.epoch, 0);
  assert.equal(known.version, 0);
});

test('omits pqSigningPublicKey — the demo path is classical (no hybrid KEM on the wire yet)', () => {
  const known = recordToKnownContact(record({ pq_sig_public_key: 'BASE64PQ' }));
  assert.equal(known.pqSigningPublicKey, undefined);
});

// #535 pin-at-import — the AC-8 liveness line: project the stored authority pin so
// verifyRotationSuccessor can check a rotation against it. WITHOUT this projection,
// known.next_authority_commitment is always undefined → every rotation (incl legit) fails closed =
// safe-but-dead-feature. '' for legacy/unpinned contacts → verify fail-closes (AC-4), which is correct.
test('#535: projects next_authority_commitment (AC-8 liveness)', () => {
  const PIN = '0123456789abcdef'.repeat(4); // 64 lowercase-hex authority pin
  assert.equal(recordToKnownContact(record({ next_authority_commitment: PIN })).next_authority_commitment, PIN);
});
test('#535: unpinned/legacy record → "" (AC-4 — verify then fail-closes, never blind-accepts)', () => {
  assert.equal(recordToKnownContact(record()).next_authority_commitment, '');
});
