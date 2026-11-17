// Run: npx tsx --test src/components/grow-sheet-copy.test.ts
// The Grow sheet's invite builder shows the contact book's two approved sentences for the same event (copy ledger row 232f): "Unlock your identity first to build an invite." when there is no key, and
// "The invite couldn't be prepared. Check your connection and try again." for any other failure. They are IMPORTED through the contact book's own helper, never retyped, and an error's own text is never shown.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CONTACT_FAILURE_MESSAGES, CONTACT_INPUT_MESSAGES, ContactInputError, contactFailureMessage } from './contact-management-copy';
import { DB_UPGRADE_BLOCKED_MESSAGE, DbUpgradeBlocked } from '@/lib/db-upgrade-blocked';

const HERE = dirname(fileURLToPath(import.meta.url));
const stripComments = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const sheet = (): string => stripComments(readFileSync(join(HERE, 'GrowSheet.tsx'), 'utf8'));
const NO_KEY = 'Unlock your identity first to build an invite.';
const PREPARE_FAILED = "The invite couldn't be prepared. Check your connection and try again.";
const quiet = <T,>(fn: () => T): { out: T; logged: unknown[][] } => {
  const logged: unknown[][] = [];
  const real = console.error; console.error = (...a: unknown[]) => { logged.push(a); };
  try { return { out: fn(), logged }; } finally { console.error = real; }
};

test('GS1 the two sentences the Grow sheet shows are the copy owner\'s words (row 232f), byte for byte, through the contact book\'s own table and helper', () => {
  assert.equal(CONTACT_INPUT_MESSAGES['invite-no-key'], NO_KEY);
  assert.equal(CONTACT_FAILURE_MESSAGES.invite, PREPARE_FAILED);
  const noKey = quiet(() => contactFailureMessage(new ContactInputError('invite-no-key'), 'invite'));
  assert.equal(noKey.out, NO_KEY);
  assert.deepEqual(noKey.logged, [], 'a refusal the screen raises itself is not logged as an unknown failure');
  for (const e of [new TypeError('SECRET-4242 relay exploded'), new Error('Relay POST failed: 500'), 'a string', null, undefined]) {
    const r = quiet(() => contactFailureMessage(e, 'invite'));
    assert.equal(r.out, PREPARE_FAILED);
  }
  assert.deepEqual(quiet(() => contactFailureMessage(new TypeError('SECRET-4242'), 'invite')).logged, [['Contact invite failed:', 'TypeError']], 'logged once, by class only');
  const blocked = quiet(() => contactFailureMessage(new DbUpgradeBlocked(), 'invite'));
  assert.equal(blocked.out, DB_UPGRADE_BLOCKED_MESSAGE);
  assert.deepEqual(blocked.logged, []);
});

test('GS2 THE SHEET raises the typed no-key refusal, asks the contact book\'s helper once, reads no error text, and the two old strings are gone', () => {
  const c = sheet();
  const once = (needle: string): void => assert.equal(c.split(needle).length - 1, 1, `exactly once in the sheet: ${needle}`);
  once("import { ContactInputError, contactFailureMessage } from './contact-management-copy';");
  once("throw new ContactInputError('invite-no-key');");
  once("setError(contactFailureMessage(e, 'invite'));");
  assert.equal((c.match(/contactFailureMessage\(/g) ?? []).length, 1);
  assert.ok(!/\.message\b/.test(c), 'the sheet must not read an error\'s own text');
  assert.ok(!c.includes('Unlock your identity first.') && !c.includes('Could not prepare the invite.'), 'the two old strings are gone');
});

test('GS3 THE SENTENCES ARE NOT RETYPED in the sheet: they live in the contact book\'s copy module only', () => {
  const c = sheet().replace(/\s+/g, ' ');
  for (const piece of ['Unlock your identity first', "couldn't be prepared", 'Check your connection', 'build an invite']) assert.ok(!c.includes(piece), `the sheet must not retype "${piece}"`);
});
