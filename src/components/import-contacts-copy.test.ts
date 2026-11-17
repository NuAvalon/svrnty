// Run: npx tsx --test src/components/import-contacts-copy.test.ts
// The "import contacts from a .vcf file" dialog shows a fixed sentence when reading the file, reading the book, or importing fails (copy ledger rows 232c and 256), never an error's own text. The file
// and book sentences are pinned byte for byte here, apart from the module that holds them; the import sentence is the contact book's own and is imported, not retyped. The dialog and the vCard parser
// are checked as source (the repo has no component renderer).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DB_UPGRADE_BLOCKED_MESSAGE, DbUpgradeBlocked } from '@/lib/db-upgrade-blocked';
import { CONTACT_IO_MESSAGES } from '@/lib/contacts/contact-io-errors';
import { VCF_READ_FAILED, VCF_BOOK_READ_FAILED, vcfReadFailureMessage, vcfBookReadFailureMessage, vcfImportFailureMessage } from './import-contacts-copy';

const HERE = dirname(fileURLToPath(import.meta.url));
const stripComments = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const dialog = (): string => stripComments(readFileSync(join(HERE, 'ImportContactsDialog.tsx'), 'utf8'));
const vcard = (): string => stripComments(readFileSync(join(HERE, '..', 'lib', 'contacts', 'vcard.ts'), 'utf8'));
const quiet = <T,>(fn: () => T): { out: T; logged: unknown[][] } => {
  const logged: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { logged.push(a); };
  try { return { out: fn(), logged }; } finally { console.error = real; }
};
const IMPORT_SENTENCE = 'The import stopped; some contacts may have been added. Check your contacts before you try again.';
const HELPERS = [
  ['file', vcfReadFailureMessage, VCF_READ_FAILED, 'Contacts file read failed:'],
  ['book', vcfBookReadFailureMessage, VCF_BOOK_READ_FAILED, 'Contacts book read failed:'],
  ['import', vcfImportFailureMessage, IMPORT_SENTENCE, 'Contacts import failed:'],
] as const;

test('IC1 the sentences are the copy owner\'s words byte for byte (rows 232c and 256), plain ASCII, the book one has the frozen hash; the import sentence is the contact book\'s own, reused', () => {
  assert.equal(VCF_READ_FAILED, "That file couldn't be read. Make sure it's a .vcf contacts file and try again.");
  assert.equal(VCF_BOOK_READ_FAILED, "Your contacts couldn't be read to compare with this file, so nothing was imported. Check that your identity is unlocked, then try again.");
  for (const s of [VCF_READ_FAILED, VCF_BOOK_READ_FAILED]) assert.ok(/^[\x20-\x7e]+$/.test(s));
  assert.equal(VCF_BOOK_READ_FAILED.length, 136);
  assert.equal(createHash('sha256').update(VCF_BOOK_READ_FAILED).digest('hex').slice(0, 16), '07dc61e23fefb4e0');
  assert.equal(CONTACT_IO_MESSAGES.importUnknown, IMPORT_SENTENCE);
  assert.equal(quiet(() => vcfImportFailureMessage(new Error('x'))).out, CONTACT_IO_MESSAGES.importUnknown);
});

test('IC2 any other failure shows the fixed sentence and never the error\'s own text; it is logged ONCE, by class and code only (the exact arguments), for each helper', () => {
  class Coded extends Error { code = 'x-code'; }
  for (const [, fn, sentence, label] of HELPERS) {
    for (const [err, tag] of [[new Error('SECRET-4242 quota exceeded'), 'Error'], [new TypeError('SECRET-4242'), 'TypeError'], [new Coded('SECRET-4242'), 'Error:x-code'], ['SECRET-4242', 'string']] as const) {
      const { out, logged } = quiet(() => fn(err));
      assert.equal(out, sentence);
      assert.deepEqual(logged, [[label, tag]]);
    }
    for (const v of [null, undefined, { message: 'x' }]) assert.equal(quiet(() => fn(v)).out, sentence);
  }
});

test('IC3 a blocked database upgrade keeps its own sentence in all three places, by CODE (a look-alike message is not it), and is not logged as an unknown failure', () => {
  for (const [, fn, sentence] of HELPERS) {
    const real = quiet(() => fn(new DbUpgradeBlocked()));
    assert.equal(real.out, DB_UPGRADE_BLOCKED_MESSAGE);
    assert.deepEqual(real.logged, []);
    assert.equal(quiet(() => fn(new Error(DB_UPGRADE_BLOCKED_MESSAGE))).out, sentence);
  }
});

test('IC4 THE DIALOG imports the three helpers once, calls each at its own catch, reads no caught error\'s text, retypes no sentence, and the old fallbacks are gone', () => {
  const c = dialog();
  const once = (needle: string): void => assert.equal(c.split(needle).length - 1, 1, `exactly once in the dialog: ${needle}`);
  once("import { vcfReadFailureMessage, vcfBookReadFailureMessage, vcfImportFailureMessage } from './import-contacts-copy';");
  once('setError(vcfReadFailureMessage(err));');
  once('setError(vcfBookReadFailureMessage(err));');
  once('setError(vcfImportFailureMessage(err));');
  for (const n of ['vcfReadFailureMessage', 'vcfBookReadFailureMessage', 'vcfImportFailureMessage']) assert.equal((c.match(new RegExp(`${n}\\(`, 'g')) ?? []).length, 1, n);
  assert.ok(!/\b(?:e|err)\??\.message\b/.test(c) && !c.includes('instanceof Error'), 'no caught error\'s own text is read');
  assert.ok(!c.includes('Could not read that file.') && !c.includes('Import failed.'), 'the old fallbacks are gone');
  assert.ok(!c.includes("couldn't be read") && !c.includes('import stopped') && !c.includes('nothing was imported'), 'the sentences live in the copy modules only');
  assert.ok(!/catch \(err: any\)/.test(c), 'the catches are not typed any');
});

test('IC5 THE GUARD (row 256): a file-read throw shows the file sentence and a book-read throw shows the book sentence, each never the other: file.text() and the parser sit in the FIRST try, getAllContacts and the plan in the SECOND, each with its own catch', () => {
  const c = dialog();
  const fn = c.slice(c.indexOf('const handleFile = async'), c.indexOf('const handleConfirm = async'));
  assert.equal((fn.match(/\btry \{/g) ?? []).length, 2, 'two steps');
  assert.equal((fn.match(/catch \(err\)/g) ?? []).length, 2, 'two catches');
  const iT1 = fn.indexOf('try {'), iT2 = fn.indexOf('try {', iT1 + 1);
  const iC1 = fn.indexOf('catch (err)'), iC2 = fn.indexOf('catch (err)', iC1 + 1);
  assert.ok(iT1 < iC1 && iC1 < iT2 && iT2 < iC2, 'order: try, catch, try, catch');
  const fileStep = fn.slice(iT1, iC1), fileCatch = fn.slice(iC1, iT2), bookStep = fn.slice(iT2, iC2), bookCatch = fn.slice(iC2);
  assert.ok(fileStep.includes('await file.text()') && fileStep.includes('fromVCard(text)'), 'the first step reads the file and parses it');
  assert.ok(!fileStep.includes('getAllContacts') && !fileStep.includes('dedupeContacts'), 'a book failure cannot reach the file catch');
  assert.ok(/setError\(vcfReadFailureMessage\(err\)\);\s*return;\s*\}/.test(fileCatch), 'the file catch shows the file sentence and then stops (the plan is never built without a parsed file)');
  assert.ok(bookStep.includes('await getAllContacts(') && bookStep.includes('dedupeContacts('), 'the second step reads the book and builds the plan');
  assert.ok(!bookStep.includes('file.text') && !bookStep.includes('fromVCard'), 'a file failure cannot reach the book catch');
  assert.ok(bookCatch.includes('setError(vcfBookReadFailureMessage(err));'), 'the book catch shows the book sentence');
});

test('IC6 THE PREMISES: neither read step writes (so "nothing was imported" is true), the writes are in the import step, and no safety refusal can reach the import catch (a vCard never carries a public key, so addContact\'s binding refusal, which needs a key, cannot happen; if the parser ever reads a key, this fails and the catch must map the refusal first)', () => {
  const c = dialog();
  const reads = c.slice(c.indexOf('const handleFile = async'), c.indexOf('const handleConfirm = async'));
  const imp = c.slice(c.indexOf('const handleConfirm = async'));
  assert.ok(!/\b(?:addContact|updateContact|applyImportPlan)\(/.test(reads), 'the read steps write nothing');
  assert.ok(/await addContact\(/.test(imp) && /await updateContact\(/.test(imp), 'the import step holds the writes');
  assert.equal((imp.match(/\btry \{/g) ?? []).length, 1);
  assert.ok(!/public_?key/i.test(vcard()), 'the vCard parser does not read a public key');
  assert.ok(!c.includes('ContactRefused'), 'the dialog maps no refusal today, because none can reach it');
});
