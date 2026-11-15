// Opening a password-sealed contacts export: the right password opens it, a wrong password says so, anything else is "can't read this file", and the cap holds.
// Run: node --import tsx --test src/lib/contacts/sealed-book-import.test.ts
import { test, before } from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { sealWithPassword } from '@/lib/crypto/password-envelope';
import { MAX_FILE_CHARS, contactBookFile, ContactBookTooLarge } from './book-import';
import { SEALED_BOOK_MESSAGES, SealedBookRefused, looksSealed, openSealedBook, namesDifferentOwner, splitMissingKeys, splitUnbindable } from './sealed-book-import';

const PW = 'contacts-export-pass-77';
const OWNER = 'a'.repeat(64);
const FILE = JSON.stringify({ version: '1.0', exported_at: '2026-11-15T00:00:00.000Z', owner_fingerprint: OWNER, contacts: [{ name: 'Ann', fingerprint: 'b'.repeat(64) }] });
let sealed = '';

before(async () => {
  sealed = JSON.stringify({ encrypted: true, ...(await sealWithPassword(new TextEncoder().encode(FILE), PW)) });
});

const refused = async (p: Promise<unknown>): Promise<string> => {
  try { await p; } catch (e) { assert.ok(e instanceof SealedBookRefused, `a SealedBookRefused, got ${String(e)}`); return e.code; }
  assert.fail('it was expected to refuse');
};

test('B1 looksSealed: a real sealed export is; plain JSON, a bare array, non-JSON and oversize text are not', () => {
  assert.equal(looksSealed(sealed), true);
  assert.equal(looksSealed(FILE), false);
  assert.equal(looksSealed('[]'), false);
  assert.equal(looksSealed('not json at all'), false);
  assert.equal(looksSealed(JSON.stringify({ encrypted: true, salt: 's', iv: 'i' })), false, 'no data');
  assert.equal(looksSealed(JSON.stringify({ encrypted: 'yes', salt: 's', iv: 'i', data: 'd' })), false, 'encrypted must be true');
  assert.equal(looksSealed('{' + 'x'.repeat(MAX_FILE_CHARS + 1)), false, 'over the cap: the plain path refuses it before any parse');
});

test('B2 the right password opens it to the exact plaintext, and the same parser reads it (entries and the named owner)', async () => {
  const plain = await openSealedBook(sealed, PW);
  assert.equal(plain, FILE);
  const parsed = contactBookFile(plain);
  assert.equal(parsed.entries.length, 1);
  assert.equal(parsed.owner, OWNER);
});

test('B3 a wrong password is wrong-password; nothing else is: a malformed envelope, an unknown method, non-JSON are "malformed"', async () => {
  assert.equal(await refused(openSealedBook(sealed, 'definitely-the-wrong-pass')), 'wrong-password');
  const env = JSON.parse(sealed);
  const noSalt = { ...env };
  delete noSalt.salt;
  assert.equal(await refused(openSealedBook(JSON.stringify(noSalt), PW)), 'malformed', 'a missing field is not a wrong password');
  assert.equal(await refused(openSealedBook(JSON.stringify({ ...env, kdf: 'scrypt-n14' }), PW)), 'malformed', 'a method it will not run is not a wrong password');
  assert.equal(await refused(openSealedBook(JSON.stringify({ ...env, data: '!!not base64!!' }), PW)), 'malformed', 'bad data is not a wrong password');
  assert.equal(await refused(openSealedBook('{ not json', PW)), 'malformed');
  assert.equal(await refused(openSealedBook('[]', PW)), 'malformed', 'JSON that is not an envelope');
});

test('B4 the cap: sealed text over the cap is refused as too large BEFORE any decrypt (a small cap stands in for the 52 million)', async () => {
  assert.ok(sealed.length > 200, 'the fixture is bigger than the small cap');
  assert.equal(await refused(openSealedBook(sealed, PW, 200)), 'too-large');
  assert.equal(await openSealedBook(sealed, PW, sealed.length), FILE, 'at the cap it opens');
  // the importer's own cap still applies to whatever is handed on
  assert.throws(() => contactBookFile('x'.repeat(MAX_FILE_CHARS + 1)), ContactBookTooLarge);
});

test('B5 namesDifferentOwner: a missing owner and the same owner (any case, any spaces) are not different; another owner is', () => {
  assert.equal(namesDifferentOwner(null, OWNER), false);
  assert.equal(namesDifferentOwner(OWNER, OWNER), false);
  assert.equal(namesDifferentOwner(` ${OWNER.toUpperCase()} `, OWNER), false);
  assert.equal(namesDifferentOwner('c'.repeat(64), OWNER), true);
});

test('B6 splitMissingKeys counts the keyless rows and leaves every other failure', () => {
  const failed = [
    { label: 'A', reason: 'it has no fingerprint and key' },
    { label: 'B', reason: 'its key does not match its fingerprint' },
    { label: 'C', reason: 'it has no fingerprint and key' },
  ];
  const { missingKeys, other } = splitMissingKeys(failed);
  assert.equal(missingKeys, 2);
  assert.deepEqual(other, [failed[1]]);
  assert.deepEqual(splitMissingKeys([]), { missingKeys: 0, other: [] });
});

test('B7 the sentences are the approved constants; the one that takes a number takes only a number', () => {
  assert.equal(SEALED_BOOK_MESSAGES.passwordLabel, 'Password for this file');
  assert.equal(SEALED_BOOK_MESSAGES.passwordHelper, 'This file is sealed. Enter the password you chose when you exported these contacts.');
  assert.equal(SEALED_BOOK_MESSAGES.alwaysUnverified, 'Imported contacts start as unverified until you verify each one.');
  assert.equal(SEALED_BOOK_MESSAGES.malformed, "This app can't read this file as a contacts export.");
  assert.equal(SEALED_BOOK_MESSAGES.tooLarge, 'This file is too large to import. Nothing was added.');
  assert.equal(SEALED_BOOK_MESSAGES.differentOwner, 'These contacts were exported by a different identity.');
  assert.equal(SEALED_BOOK_MESSAGES.missingKeys(3), "3 contacts were exported without their keys, so they can't be added. Ask each person to share their contact again.");
  assert.match(SEALED_BOOK_MESSAGES.missingKeys(1), /^1 contact was exported without its keys/);
  assert.ok(!SEALED_BOOK_MESSAGES.malformed.includes(OWNER) && !SEALED_BOOK_MESSAGES.differentOwner.includes(OWNER), 'no value from a file is in a sentence');
  assert.doesNotMatch(SEALED_BOOK_MESSAGES.malformed, /wrong|incorrect/i, 'a file it cannot read never says wrong password');
});

// The screen's wiring, pinned (the browser cannot see these): the default cap, no file value rendered, and the plain path untouched.
const screen = readFileSync(new URL('../../components/ContactManagement.tsx', import.meta.url), 'utf8');
const handler = (() => {
  const a = screen.indexOf('const handleImportContacts = async () => {');
  assert.ok(a >= 0, 'the import handler is found');
  return screen.slice(a, screen.indexOf('const openEditDialog', a));
})();

test('B8 the screen opens a sealed file with the default cap, reads it with the one parser, and never renders a value from the file', () => {
  assert.match(handler, /openSealedBook\(importData, importPassword\)/, 'the default cap: no third argument');
  assert.match(handler, /contactBookFile\(await openSealedBook\(/, 'the plaintext goes to the same parser a plain paste uses');
  assert.match(handler, /namesDifferentOwner\(file\.owner, fingerprint\)/, 'the owner is only compared');
  assert.match(handler, /splitMissingKeys\(summary\.failed\)/, 'keyless rows are counted, not named');
  assert.match(handler, /entries = contactBookEntries\(importData\);/, 'the plain path is unchanged');
  assert.doesNotMatch(screen, /\{\s*file\.owner\s*\}|\{\s*owner\s*\}/, 'the owner the file names is never rendered');
  assert.match(screen, /data-testid="contacts-import-password"/, 'the password field has its test id');
  assert.match(screen, /disabled=\{loading \|\| !importData \|\| \(importSealed && !importPassword\)\}/, 'Import waits for the password');
});

test('B9 splitUnbindable: a canonical fingerprint with no post-quantum key can never bind and is not tried; everything else is', () => {
  const fp = 'd'.repeat(64);
  const rows: unknown[] = [
    { name: 'old', fingerprint: fp, public_key: 'k' },                                        // canonical, no PQ keys: unbindable
    { name: 'old2', fingerprint: fp, public_key: 'k', pq_kem_public_key: '', pq_sig_public_key: '' }, // empty strings count as none
    { name: 'new', fingerprint: fp, public_key: 'k', pq_kem_public_key: 'a', pq_sig_public_key: 'b' },
    { name: 'half', fingerprint: fp, public_key: 'k', pq_kem_public_key: 'a' },                // the store decides this one
    { name: 'legacy', fingerprint: 'SHORT-OLD-FP', public_key: 'k' },                          // not a canonical fingerprint: binds to its key alone
    'not an object', null,
  ];
  const { attempt, unbindable } = splitUnbindable(rows);
  assert.equal(unbindable, 2);
  assert.deepEqual(attempt.map((r) => (r && typeof r === 'object' ? (r as { name: string }).name : String(r))), ['new', 'half', 'legacy', 'not an object', 'null']);
  assert.deepEqual(splitUnbindable([]), { attempt: [], unbindable: 0 });
});

test('B10 the sealed export writes the post-quantum public keys beside the public key (without them no key-bound contact can be imported back)', () => {
  const dlg = readFileSync(new URL('../../components/SecureImportExportDialogs.tsx', import.meta.url), 'utf8');
  const a = dlg.indexOf('if (includePublicKeys && c.public_key) {');
  assert.ok(a >= 0, 'the public-key block is found');
  const block = dlg.slice(a, dlg.indexOf('return base;', a));
  assert.match(block, /base\.public_key = c\.public_key;/);
  assert.match(block, /if \(c\.pq_kem_public_key\) base\.pq_kem_public_key = c\.pq_kem_public_key;/);
  assert.match(block, /if \(c\.pq_sig_public_key\) base\.pq_sig_public_key = c\.pq_sig_public_key;/);
  assert.match(handler, /splitUnbindable\(file\.entries\)/, 'the screen does not try rows that can never bind');
});
