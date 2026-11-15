// src/lib/identity/restore-with-password.test.ts
// Static pins for the order and the rules of a restore with a password. There is no IndexedDB harness in this suite; the browser spec
// e2e/restore-with-password.spec.ts is the proof of behaviour. These stop the ORDER and the contact rules from being edited away.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
const body = (start: string, end: string) => {
  const a = src.indexOf(start);
  assert.ok(a >= 0, `${start} exists`);
  const b = src.indexOf(end, a + start.length);
  assert.ok(b > a, `${end} follows`);
  return src.slice(a, b);
};
const before = (s: string, a: string, b: string, why: string) => {
  const i = s.indexOf(a), j = s.indexOf(b);
  assert.ok(i >= 0 && j >= 0 && i < j, why);
};

test('importAllWithPassword: reads first (binds, then the domain check), then the session key, then the writes', () => {
  const s = body('export async function importAllWithPassword(', '/**\n * Persist an already-decrypted .svrnty VaultContents');
  before(s, 'assertPlaintextBackupIdentityBinds(backup)', 'assertRestoreKeepsOwnerDomain(', 'the identity binds before the domain check');
  before(s, 'assertRestoreKeepsOwnerDomain(', 'initSessionKey(', 'a refusal must leave no salt and no session');
  before(s, 'initSessionKey(', 'importAll(backup)', 'the session exists before the writes');
  before(s, 'throw new DevicePasswordRequired()', 'initSessionKey(', 'asking for a password writes nothing');
});

test('importAllWithPassword: a password shorter than the floor never becomes the device password on a fresh device', () => {
  const s = body('export async function importAllWithPassword(', '/**\n * Persist an already-decrypted .svrnty VaultContents');
  assert.match(s, /filePassword\.length >= DEVICE_PASSWORD_MIN/);
  assert.match(s, /devicePassword\.length >= DEVICE_PASSWORD_MIN/);
  // a device that already holds the owner is never asked for a new password: the file password has to open what is held
  before(s, 'deviceHoldsOwner(fingerprint)', 'filePassword.length >= DEVICE_PASSWORD_MIN', 'the held-owner case is decided before the length floor');
});

test('importPlaintextContacts: a re-run adds nothing twice (multiset for keyless rows) and a backup only tightens a block', () => {
  const s = body('export async function importPlaintextContacts(', 'export async function importAll(');
  assert.match(s, /pool\.shift\(\)/, 'each incoming keyless row consumes ONE existing identical row');
  assert.match(s, /byFingerprint\.get\(/, 'a keyed row is matched by fingerprint');
  assert.match(s, /keylessSignature\(/, 'keyless rows are matched through the pinned-field signature');
  assert.match(src, /const KEYLESS_MATCH_FIELDS = \['name', 'email', 'metadata'\] as const;/, 'the matched fields are named, not fuzzy');
  // both block fields, on a matched row (updateContactIf) and on a new row
  assert.match(s, /updateContactIf\(match\.id/);
  assert.match(s, /blocked: true, metadata: \{ \.\.\.\(\(ex\.metadata as object\) \|\| \{\}\), blocked: true \}/);
  assert.match(s, /next\.blocked = true; next\.metadata = \{ \.\.\.\(\(next\.metadata as object\) \|\| \{\}\), blocked: true \}/);
  assert.doesNotMatch(s, /blocked: false|delete (next|match)\.blocked|\.blocked = false/, 'a backup never clears a block');
  assert.doesNotMatch(s, /txPut\('contacts'/);
});

test('storeIdentity: writing the same identity again keeps the row\'s created_at', () => {
  const s = body('export async function storeIdentity(', 'export async function loadIdentity(');
  assert.match(s, /data\.created_at \|\| existing\?\.created_at \|\| new Date\(\)\.toISOString\(\)/);
});

test('importPlaintextContacts: only a row addContact REFUSED is skipped; a failed write stops the restore (so the same file can be run again)', () => {
  const s = body('export async function importPlaintextContacts(', 'export async function importAll(');
  assert.match(s, /if \(!\(e instanceof ContactRefused\)\) throw e;/);
  const add = body('export async function addContact(', '\n}\n');
  assert.equal((add.match(/throw new ContactRefused\(/g) || []).length, 2, 'the two deliberate refusals are typed, with their messages unchanged');
  assert.match(add, /fingerprint↔key binding failed/);
  assert.match(add, /verify-before-trust/);
});

test('keyless contact matching ignores the block flag (a row blocked in the backup and the same row unblocked here are one contact, so the restore tightens it instead of adding a copy)', () => {
  assert.match(src, /function withoutBlockFlag\(/);
  assert.match(src, /delete rest\.blocked;/);
  assert.match(src, /f === 'metadata' \? withoutBlockFlag\(c\[f\]\)/);
});

test('passphraseOpensEveryHeldKeyRecord: the contact rows are in the check, opened under the settings salt, and a failure refuses', () => {
  const s = body('export async function passphraseOpensEveryHeldKeyRecord(', '/**\n * Call after the owner\'s fingerprint is derived');
  assert.match(s, /txGetByIndex<any>\('contacts', 'owner', fingerprint\)/, 'the owner\'s contact rows are read');
  assert.match(s, /'settings', 'key_encryption_salt'/, 'contacts are opened under the device salt, not a record\'s own salt');
  assert.match(s, /decryptContactRecord\(key, rec\.id, rec\.owner_fingerprint,/, 'every encrypted contact row is decrypted, with its id and owner as AAD');
  assert.match(s, /decryptContactRecord[\s\S]*?\} catch \{\s*return false;/, 'a contact row that does not open refuses the restore');
  assert.match(s, /for \(const sealed of OWNER_SEALED_SETTINGS\) \{/, 'every owner-sealed settings record is read, from the one list (no per-record code)');
  assert.match(s, /if \(encryptedContacts\.length > 0 \|\| heldSealed\.length > 0 \|\| heldBeacon\.length > 0\) \{/, 'the check runs when ONLY a sealed record or a beacon row is held, with no contacts');
  assert.match(s, /decryptContactRecord\(key, held\.recordId, fingerprint,/, 'each is decrypted under the settings salt with its reserved id and the owner as AAD');
  assert.match(s, /typeof held\.value\.iv !== 'string' \|\| typeof held\.value\.ciphertext !== 'string'\) return false/, 'a malformed sealed record refuses the restore');
  assert.match(s, /\n\s+for \(const held of heldSealed\) \{\n/, 'and the held records are decrypted unconditionally (not behind a constant)');
});
