// Run: npx tsx --test src/lib/crypto/contact-keys-mismatch.test.ts
// The refusal for a contact whose keys do not match its claimed fingerprint is CODED, so the encrypt screen asks by code and never by the error's text. The leaf, the one place that raises it, and the
// screen's wrapper are checked here (the wrapper's end-to-end behaviour with real keys is in encrypt-decrypt-keys.test.ts).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CONTACT_KEYS_MISMATCH_CODE, ContactKeysMismatch, isContactKeysMismatch } from './contact-keys-mismatch';

const HERE = dirname(fileURLToPath(import.meta.url));
const code = (rel: string): string => readFileSync(join(HERE, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');

test('KM1 the refusal is coded, and its message is exactly what it always said (a log, or a test that reads it, sees the same words)', () => {
  const e = new ContactKeysMismatch();
  assert.equal(e.code, 'contact-keys-mismatch');
  assert.equal(CONTACT_KEYS_MISMATCH_CODE, 'contact-keys-mismatch');
  assert.equal(e.name, 'ContactKeysMismatch');
  assert.equal(e.message, 'encryptToContact: contact keys do not match its claimed fingerprint — refusing to encrypt (anti-poison)');
  assert.ok(e instanceof Error);
});

test('KM2 recognised by CODE only: the real refusal and any object carrying the code are it; a plain Error with look-alike words is not, and neither is anything that is not an object', () => {
  assert.equal(isContactKeysMismatch(new ContactKeysMismatch()), true);
  assert.equal(isContactKeysMismatch(Object.assign(new Error('x'), { code: 'contact-keys-mismatch' })), true);
  assert.equal(isContactKeysMismatch(new Error('encryptToContact: contact keys do not match its claimed fingerprint — refusing to encrypt (anti-poison)')), false);
  assert.equal(isContactKeysMismatch(new Error('anti-poison does not match')), false);
  assert.equal(isContactKeysMismatch(Object.assign(new Error('x'), { code: 'something-else' })), false);
  for (const v of [null, undefined, 'contact-keys-mismatch', 42, {}]) assert.equal(isContactKeysMismatch(v), false);
});

test('KM3 THE LEAF has no imports in any form, so the screen can ask without loading the crypto', () => {
  const src = readFileSync(join(HERE, 'contact-keys-mismatch.ts'), 'utf8');
  assert.ok(!/^\s*import\b/m.test(src) && !/\brequire\(/.test(src) && !/\bimport\(/.test(src));
});

test('KM4 THE ONE PLACE THAT RAISES IT: encryptToContact throws the coded refusal, exactly once, and no plain Error with the anti-poison text is left', () => {
  const c = code('contact-message.ts');
  assert.equal(c.split('throw new ContactKeysMismatch();').length - 1, 1);
  assert.equal(c.split("import { ContactKeysMismatch } from './contact-keys-mismatch';").length - 1, 1);
  assert.ok(!/new Error\([^)]*anti-poison/.test(c), 'no plain Error carries the anti-poison text any more');
  assert.ok(!/new Error\([^)]*do not match its claimed fingerprint/.test(c));
});
