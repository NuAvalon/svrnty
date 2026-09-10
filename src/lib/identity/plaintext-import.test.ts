// Run: npx tsx --test src/lib/identity/plaintext-import.test.ts
//
// Plaintext JSON backup is untrusted. Contacts must go through addContact
// (fingerprint↔key) and land Known — never Trusted, never owner_verify.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { contactFromPlaintextBackup, type ContactRecord } from './client-store';

const crafted = (): ContactRecord =>
  ({
    id: 'attacker-id',
    fingerprint: 'aa'.repeat(20),
    name: 'Victim',
    email: 'v@example.test',
    public_key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nATTACKER\n-----END PGP PUBLIC KEY BLOCK-----',
    trust_level: 'trusted',
    trusted: true,
    trusted_since: '2026-01-01T00:00:00.000Z',
    verified_at: '2026-01-01T00:00:00.000Z',
    owner_verify: { owner_verified_at: '2026-01-01T00:00:00.000Z', method: 'in_person' },
    verification: { method: 'in_person', verified_at: '2026-01-01T00:00:00.000Z' },
    metadata: { owner_verify: { owner_verified_at: 'x', method: 'in_person' }, tags: ['core'] },
    added_at: '2020-01-01T00:00:00.000Z',
    owner_fingerprint: 'attacker-owner',
  }) as ContactRecord;

test('plaintext import strips trust and owner_verify; lands Known', () => {
  const out = contactFromPlaintextBackup(crafted());
  assert.equal(out.trust_level, 'known');
  assert.equal(out.trusted, undefined);
  assert.equal(out.trusted_since, undefined);
  assert.equal(out.verified_at, undefined);
  assert.equal(out.owner_verify, undefined);
  assert.deepEqual(out.verification, { method: 'none', verified_at: null });
  assert.equal((out.metadata as { owner_verify?: unknown })?.owner_verify, undefined);
  assert.deepEqual((out.metadata as { tags?: string[] }).tags, ['core']);
  assert.equal((out as { id?: string }).id, undefined);
  assert.equal((out as { added_at?: string }).added_at, undefined);
  assert.equal((out as { owner_fingerprint?: string }).owner_fingerprint, undefined);
  assert.equal(out.fingerprint, 'aa'.repeat(20));
  assert.equal(out.name, 'Victim');
});

test('importAll persists contacts via addContact, not a raw contacts txPut', () => {
  const src = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
  const importFn = src.slice(src.indexOf('export async function importAll'), src.indexOf('export async function importVaultContents'));
  assert.match(importFn, /addContact\(/);
  assert.match(importFn, /contactFromPlaintextBackup/);
  assert.doesNotMatch(importFn, /txPut\('contacts'/);
});
