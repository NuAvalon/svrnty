// Run: npx tsx --test src/lib/error-tag.test.ts
// The log tag is a leaf module: it imports nothing, and the landing screen's copy module takes it from here, not from the contacts import/export module (which pulls the
// password-envelope and book-import code). The tag's behaviour is pinned in contact-io-errors.test.ts (C7), which reaches it through the re-export.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { errorTag } from './error-tag';
import { errorTag as viaContacts } from './contacts/contact-io-errors';

const HERE = dirname(fileURLToPath(import.meta.url));
const code = (rel: string): string => readFileSync(join(HERE, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');

test('ET1 the tag is class name and code only, sanitised and clamped', () => {
  assert.equal(errorTag(new TypeError('x"\n\u202Esecret')), 'TypeError');
  assert.equal(errorTag(Object.assign(new Error('m'), { name: 'Evil\u202E\n"name', code: 'c\nx' })), 'Evilname:cx');
  assert.equal(errorTag(null), 'object');
  assert.equal(errorTag('a string with "quotes"'), 'string');
  assert.ok(errorTag(Object.assign(new Error('m'), { name: 'N'.repeat(200) })).length <= 40);
});

test('ET2 the contacts module re-exports the same function (one definition)', () => {
  assert.equal(viaContacts, errorTag);
});

test('ET3 the tag module is a LEAF: it imports nothing', () => {
  assert.ok(!/^\s*import\b/m.test(code('error-tag.ts')), 'no import in the leaf');
  assert.ok(!/\brequire\(/.test(code('error-tag.ts')));
});

test('ET4 the landing screen\'s copy module takes the tag from the leaf, not from the contacts import/export module', () => {
  const m = code('../components/joiner-ceremony-copy.ts');
  assert.ok(m.includes("from '@/lib/error-tag'"), 'imports the leaf');
  assert.ok(!m.includes('contact-io-errors'), 'does not import the contacts import/export module');
});
