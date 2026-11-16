// Run: npx tsx --test src/lib/contacts/contact-io-errors.test.ts
// The contacts import/export screens show a sentence chosen by a CODE, never an error's own text (copy ledger row 210). These tests pin the constants byte for byte,
// the code -> sentence map, the password-prompt decision (typed code, before any display text), and that the three dialogs and the contact book no longer render
// `.message`. The dialogs are checked as source (the repo has no component renderer); the behaviour is in the pure module.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EnvelopeRefused, EnvelopeWrongPassword, MIN_EXPORT_PASSWORD_LENGTH } from '@/lib/crypto/password-envelope';
import { RESTORE_MESSAGES } from '@/lib/identity/restore-errors';
import { ContactBookTooLarge, MAX_FILE_CHARS, contactBookEntries } from './book-import';
import { SEALED_BOOK_MESSAGES } from './sealed-book-import';
import {
  CONTACT_IO_MESSAGES, ContactIoRefused, errorTag, exportFailureMessage, importFailureView, keyExportFailureMessage, plainPasteFailureMessage,
} from './contact-io-errors';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const code = (rel: string): string => readFileSync(join(SRC, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const handler = (src: string, name: string): string => { const a = src.indexOf(`const ${name}`); const rest = src.slice(a + 1); const m = rest.search(/\n  const /); return src.slice(a, m < 0 ? undefined : a + 1 + m); };
// a thrower whose text is hostile: a quote, a newline, a bidi override, and the very words the old string match looked for
const HOSTILE = 'x"\n‮decrypt password <b>';
const hostile = () => new Error(HOSTILE);
const shown = (s: string) => assert.ok(!s.includes('‮') && !s.includes('decrypt') && !s.includes('<b>') && !s.includes('"') && !s.includes('\n'), `thrower text on screen: ${JSON.stringify(s)}`);

test('C1 the sentences are the copy owner\'s words, byte for byte (ledger row 210), and the short-password sentence is the one the dialog threw before', () => {
  assert.equal(CONTACT_IO_MESSAGES.importUnknown, 'The import stopped; some contacts may have been added. Check your contacts before you try again.');
  assert.equal(CONTACT_IO_MESSAGES.exportUnknown, "The export didn't finish. Try again.");
  assert.equal(CONTACT_IO_MESSAGES.keyExportUnknown, "The key export didn't finish. Try again.");
  assert.equal(CONTACT_IO_MESSAGES.privateKeyMissing, "This device doesn't have your private key, so there's nothing to export.");
  assert.equal(CONTACT_IO_MESSAGES.invalidJson, 'Invalid JSON format');
  assert.equal(CONTACT_IO_MESSAGES.exportPasswordShort(MIN_EXPORT_PASSWORD_LENGTH), `Enter a password of at least ${MIN_EXPORT_PASSWORD_LENGTH} characters to export your contacts.`);
  assert.equal(CONTACT_IO_MESSAGES.exportPasswordShort(12), 'Enter a password of at least 12 characters to export your contacts.');
  assert.equal(CONTACT_IO_MESSAGES.exportPasswordShort(15), 'Enter a password of at least 15 characters to export your contacts.', 'the number is the argument, not a written-out digit');
  assert.ok(Object.isFrozen(CONTACT_IO_MESSAGES));
});

test('C2 export: the typed short-password refusal gets its sentence (number from the constant); anything else is the generic sentence, never the thrower\'s text', () => {
  assert.equal(exportFailureMessage(new ContactIoRefused('export-password-short')), CONTACT_IO_MESSAGES.exportPasswordShort(MIN_EXPORT_PASSWORD_LENGTH));
  assert.equal(exportFailureMessage(hostile()), CONTACT_IO_MESSAGES.exportUnknown);
  assert.equal(exportFailureMessage(new ContactIoRefused('private-key-missing')), CONTACT_IO_MESSAGES.exportUnknown, 'a code from another screen is not this screen\'s sentence');
  assert.equal(exportFailureMessage('a string'), CONTACT_IO_MESSAGES.exportUnknown);
  assert.equal(exportFailureMessage(null), CONTACT_IO_MESSAGES.exportUnknown);
  shown(exportFailureMessage(hostile()));
});

test('C3 key export: the typed missing-key refusal says so; anything else is the generic sentence', () => {
  assert.equal(keyExportFailureMessage(new ContactIoRefused('private-key-missing')), CONTACT_IO_MESSAGES.privateKeyMissing);
  assert.equal(keyExportFailureMessage(new Error('Private key not found in local storage')), CONTACT_IO_MESSAGES.keyExportUnknown, 'the old text alone is no longer a code');
  assert.equal(keyExportFailureMessage(hostile()), CONTACT_IO_MESSAGES.keyExportUnknown);
  shown(keyExportFailureMessage(hostile()));
});

test('C4 import: the sentence AND the password prompt come from the error\'s type/code (never from its text)', () => {
  assert.deepEqual(importFailureView(new ContactIoRefused('import-password-required')), { message: SEALED_BOOK_MESSAGES.passwordHelper, needsPassword: true });
  assert.deepEqual(importFailureView(new EnvelopeWrongPassword()), { message: RESTORE_MESSAGES.wrongPassword, needsPassword: true });
  assert.deepEqual(importFailureView(new EnvelopeRefused('bad-field', 'This file is missing its salt.')), { message: SEALED_BOOK_MESSAGES.malformed, needsPassword: false });
  assert.deepEqual(importFailureView(new SyntaxError('Unexpected token')), { message: SEALED_BOOK_MESSAGES.malformed, needsPassword: false });
  assert.deepEqual(importFailureView(hostile()), { message: CONTACT_IO_MESSAGES.importUnknown, needsPassword: false });
  shown(importFailureView(hostile()).message);
});

test('C5 THE TRAP: an error whose TEXT says "password" or "decrypt" does not open the password prompt (the old code string-matched the message)', () => {
  for (const text of ['decrypt failed', 'bad password', 'This is not a password-protected export.', HOSTILE, 'Incorrect encryption password.']) {
    assert.equal(importFailureView(new Error(text)).needsPassword, false, `plain Error: ${text}`);
  }
  // a look-alike with the right TEXT but not the type is not the wrong-password error either
  const lookalike = Object.assign(new Error('Incorrect encryption password.'), { code: 'wrong-password' });
  assert.equal(importFailureView(lookalike).needsPassword, false);
  // an envelope refusal of any code is "can't read this file": its text mentions a password, the prompt must not open
  for (const c of ['not-an-envelope', 'unknown-kdf', 'unsafe-params', 'bad-field'] as const) {
    assert.equal(importFailureView(new EnvelopeRefused(c, 'This is not a password-protected export.')).needsPassword, false, c);
  }
});

test('C6 plain-paste import: too large says so (the sealed path\'s sentence), not-JSON keeps its wording, anything else is the generic sentence', () => {
  assert.equal(plainPasteFailureMessage(new ContactBookTooLarge()), SEALED_BOOK_MESSAGES.tooLarge);
  assert.equal(plainPasteFailureMessage(new SyntaxError('Unexpected token x in JSON')), 'Invalid JSON format');
  assert.equal(plainPasteFailureMessage(hostile()), CONTACT_IO_MESSAGES.importUnknown);
  assert.equal(plainPasteFailureMessage(undefined), CONTACT_IO_MESSAGES.importUnknown);
  shown(plainPasteFailureMessage(hostile()));
});

test('C7 the log line of an unknown error is its class name and code only: never the message, never the stack, never control characters', () => {
  assert.equal(errorTag(new TypeError(HOSTILE)), 'TypeError');
  assert.equal(errorTag(new ContactIoRefused('private-key-missing')), 'ContactIoRefused:private-key-missing');
  const named = Object.assign(new Error(HOSTILE), { name: 'Evil‮\n"name', code: 'c\nx' });
  assert.equal(errorTag(named), 'Evilname:cx');
  assert.equal(errorTag(null), 'object');
  assert.equal(errorTag('text with "quotes"'), 'string');
  assert.ok(errorTag(Object.assign(new Error('m'), { name: 'N'.repeat(200) })).length <= 40);
});

test('C8 too large is refused BEFORE any write: contactBookEntries throws before it parses, and the handler calls it before the importer that writes', () => {
  assert.throws(() => contactBookEntries('x'.repeat(MAX_FILE_CHARS + 1)), (e) => e instanceof ContactBookTooLarge && !(e instanceof SyntaxError));
  const cm = code('components/ContactManagement.tsx');
  const body = handler(cm, 'handleImportContacts');
  const read = body.indexOf('contactBookEntries(importData)'), write = body.indexOf('importContactBook(');
  assert.ok(read > 0 && write > read, 'entries (and the size refusal) come before the call that adds contacts');
});

test('C9 the three dialogs and the contact book\'s paste import no longer render an error\'s text, decide the password prompt by string match, or log the error object', () => {
  const dlg = code('components/SecureImportExportDialogs.tsx');
  assert.ok(!/\.message\b/.test(dlg.replace(/\bview\.message\b/g, '')), 'no error .message anywhere in the dialogs (view.message is the typed sentence)');
  assert.ok(!/includes\(['"](decrypt|password)['"]\)/.test(dlg), 'no string match on an error for the password prompt');
  assert.equal((dlg.match(/setError\((exportFailureMessage|keyExportFailureMessage|view\.message)\(?/g) ?? []).length, 3, 'the three catches set the sentence from the mapping');
  assert.equal((dlg.match(/console\.error\('[^']+', errorTag\(err\)\)/g) ?? []).length, 3, 'the three catches log the tag, not the error');
  assert.ok(/if \(view\.needsPassword\) setNeedsPassword\(true\)/.test(dlg), 'the prompt comes from the typed view');
  assert.equal((dlg.match(/throw new Error\(/g) ?? []).length, 0, 'the dialogs throw typed refusals, not text');
  const cm = code('components/ContactManagement.tsx');
  const h = handler(cm, 'handleImportContacts');
  assert.ok(h.length > 1500 && h.includes('plainPasteFailureMessage') && h.includes('importContactBook('), 'the slice is the whole handler');
  assert.ok(!/\.message\b/.test(h), 'no .message in the paste import handler');
  assert.ok(/setImportError\(plainPasteFailureMessage\(err\)\)/.test(h));
  assert.ok(/console\.error\('Contact import failed:', errorTag\(err\)\)/.test(h), 'an unknown paste-import error is logged by its tag');
  assert.ok(!/console\.error\([^)]*\berr\b(?!\))/.test(h.replace(/errorTag\(err\)/g, '')), 'the handler never logs the error object');
});
