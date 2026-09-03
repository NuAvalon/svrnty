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
