// Run: npx tsx --test src/components/encrypt-decrypt/encrypt-decrypt-actions.test.ts
// The encrypt screen's wrapper turns every throw into one of two FIXED sentences and tells the "keys do not match its fingerprint" refusal apart by its CODE, never by the error's text. These tests drive the
// real wrapper with a contact whose key getter throws (no keys to mint); the end-to-end case with real keys is in encrypt-decrypt-keys.test.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { ContactKeys, SenderKeys } from '@/lib/crypto/contact-message';
import { ContactKeysMismatch } from '@/lib/crypto/contact-keys-mismatch';
import { encryptMessageToContact } from './encrypt-decrypt-actions';
import { ENCDEC_COPY } from './encrypt-decrypt-copy';

const HERE = dirname(fileURLToPath(import.meta.url));
const code = (rel: string): string => readFileSync(join(HERE, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const SENDER = {} as unknown as SenderKeys;
const contactThatThrows = (err: unknown): ContactKeys => ({ get public_key(): string { throw err; } } as unknown as ContactKeys);

test('AX1 the coded refusal shows the poisoned sentence', async () => {
  const out = await encryptMessageToContact('hi', contactThatThrows(new ContactKeysMismatch()), SENDER);
  assert.deepEqual(out, { ok: false, error: ENCDEC_COPY.encryptPoisoned });
});

test('AX2 TEXT IS NEVER THE KEY: a plain Error carrying the old words ("anti-poison", "does not match") shows the generic failure, not the poisoned sentence', async () => {
  for (const text of ['anti-poison', 'does not match', 'encryptToContact: contact keys do not match its claimed fingerprint — refusing to encrypt (anti-poison)']) {
    const out = await encryptMessageToContact('hi', contactThatThrows(new Error(text)), SENDER);
    assert.deepEqual(out, { ok: false, error: ENCDEC_COPY.encryptFailed }, text);
  }
});

test('AX3 any other throw shows the generic failure and never the crypto error\'s own text', async () => {
  for (const err of [new Error('SECRET-4242 key material'), new TypeError('SECRET-4242'), 'SECRET-4242', null, undefined, Object.assign(new Error('x'), { code: 'other' })]) {
    const out = await encryptMessageToContact('hi', contactThatThrows(err), SENDER);
    assert.equal(out.ok, false);
    if (!out.ok) {
      assert.equal(out.error, ENCDEC_COPY.encryptFailed);
      assert.ok(!out.error.includes('SECRET'));
    }
  }
});

test('AX4 THE WRAPPER asks by code once, reads no caught error\'s text, tests no text with a regular expression, and both outputs are the copy constants', () => {
  const c = code('encrypt-decrypt-actions.ts');
  assert.equal(c.split("import { isContactKeysMismatch } from '@/lib/crypto/contact-keys-mismatch';").length - 1, 1);
  assert.equal(c.split('isContactKeysMismatch(e)').length - 1, 1);
  assert.ok(!/\b(?:e|err)\??\.message\b/.test(c) && !c.includes('instanceof Error'), 'no caught error\'s own text is read');
  assert.ok(!/\/[^/\n]+\/[a-z]*\.test\(/.test(c), 'no text is matched with a regular expression');
  assert.ok(c.includes('ENCDEC_COPY.encryptPoisoned') && c.includes('ENCDEC_COPY.encryptFailed'));
});
