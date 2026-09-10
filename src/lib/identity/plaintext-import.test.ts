// Run: npx tsx --test src/lib/identity/plaintext-import.test.ts
//
// Plaintext JSON backup is untrusted. Contacts must go through addContact
// (fingerprint↔key) and land Known — never Trusted, never owner_verify.
// Identity must bind before any write. Skipped rows are reported, not hidden.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  assertPlaintextBackupIdentityBinds,
  contactFromPlaintextBackup,
  formatPlaintextImportReport,
  type ContactRecord,
  type SovereignBackup,
} from './client-store';

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

test('formatPlaintextImportReport names kept Known and skipped mismatches', () => {
  assert.equal(formatPlaintextImportReport({ kept: 12, skipped: 0 }), '12 landed Known');
  assert.equal(
    formatPlaintextImportReport({ kept: 12, skipped: 1 }),
    "12 landed Known, 1 skipped (key didn't match)",
  );
});

test('assertPlaintextBackupIdentityBinds refuses a forged fingerprint before any write', async () => {
  const backup = {
    version: '1.0',
    exported_at: '2026-01-01T00:00:00.000Z',
    identity: {
      identity: {
        fingerprint: 'aa'.repeat(32),
        public_key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nFORGED\n-----END PGP PUBLIC KEY BLOCK-----',
      },
    },
    contacts: [],
  } as SovereignBackup;
  await assert.rejects(
    () => assertPlaintextBackupIdentityBinds(backup),
    /fingerprint↔key binding failed/,
  );
});

test('importAll binds identity, persists via addContact, reports skips, never raw-puts contacts', () => {
  const src = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
  const importFn = src.slice(
    src.indexOf('export async function assertPlaintextBackupIdentityBinds'),
    src.indexOf('export async function importVaultContents'),
  );
  assert.match(importFn, /fingerprintMatchesKey/);
  assert.match(importFn, /assertPlaintextBackupIdentityBinds/);
  assert.match(importFn, /importPlaintextContacts/);
  assert.match(importFn, /addContact\(/);
  assert.match(importFn, /contactFromPlaintextBackup/);
  assert.match(importFn, /kept/);
  assert.match(importFn, /skipped/);
  assert.doesNotMatch(importFn, /txPut\('contacts'/);
  assert.doesNotMatch(importFn, /console\.warn/);

  const importAllFn = src.slice(
    src.indexOf('export async function importAll'),
    src.indexOf('export async function importVaultContents'),
  );
  const bindAt = importAllFn.indexOf('assertPlaintextBackupIdentityBinds');
  const storeAt = importAllFn.indexOf('storeIdentity');
  assert.ok(bindAt >= 0 && storeAt > bindAt, 'identity bind must run before storeIdentity');
});
