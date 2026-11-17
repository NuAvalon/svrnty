// Run: npx tsx --test src/components/contact-share-copy.test.ts
// The "share your card" dialog shows ONE fixed sentence per failure (copy ledger row 232a), never an error's own text; the real error is logged by class and code only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SHARE_LINK_FAILED, SHARE_NFC_FAILED } from './contact-share-copy';

const HERE = dirname(fileURLToPath(import.meta.url));
const stripComments = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
const dialog = (): string => stripComments(readFileSync(join(HERE, 'ContactShareDialog.tsx'), 'utf8'));

test('CS1 the two sentences are the copy owner\'s words byte for byte (row 232a) and plain ASCII', () => {
  assert.equal(SHARE_NFC_FAILED, "Writing to the tag didn't finish. Try again.");
  assert.equal(SHARE_LINK_FAILED, "The link couldn't be created. Check your connection and try again.");
  for (const t of [SHARE_NFC_FAILED, SHARE_LINK_FAILED]) assert.ok(/^[\x20-\x7e]+$/.test(t), 'pure ASCII');
});

test('CS2 the copy module is a leaf: no imports in any form', () => {
  const text = stripComments(readFileSync(join(HERE, 'contact-share-copy.ts'), 'utf8'));
  assert.ok(!/(?:^|[\s;])import\s+(?:[^'"()]*?\s+from\s+)?['"]/m.test(text), 'no import statement');
  assert.ok(!/\b(?:import|require)\s*\(/.test(text), 'no dynamic import or require');
});

test('CS3 THE DIALOG imports both sentences once, shows them at the two catches, logs by tag only, and reads no error text', () => {
  const c = dialog();
  const once = (needle: string): void => assert.equal(c.split(needle).length - 1, 1, `exactly once in the dialog: ${needle}`);
  once("import { SHARE_LINK_FAILED, SHARE_NFC_FAILED } from './contact-share-copy';");
  once("import { errorTag } from '@/lib/error-tag';");
  once('setNfcError(SHARE_NFC_FAILED);');
  once('error: SHARE_LINK_FAILED,');
  once("console.error('NFC write failed:', errorTag(err));");
  once("console.error('Share link failed:', errorTag(err));");
  for (const name of ['SHARE_NFC_FAILED', 'SHARE_LINK_FAILED']) assert.equal(c.split(name).length - 1, 2, `${name} appears only in the import and the one use`);
  assert.ok(!/\.message\b/.test(c), 'the dialog must not read an error\'s own text');
});

test('CS4 the old fallbacks are gone and no piece of either sentence is typed in the dialog', () => {
  const c = dialog();
  assert.ok(!c.includes('NFC write failed\''), 'the old NFC fallback string must not return (the log label is followed by a colon)');
  assert.ok(!c.includes('Failed to generate link'), 'the old link fallback must not return');
  const flat = (t: string): string => t.replace(/\s+/g, ' ');
  const cf = flat(c);
  const pieces = [SHARE_NFC_FAILED, SHARE_LINK_FAILED].flatMap((t) => t.split(/[.,]/)).map((t) => flat(t).trim()).filter((t) => t.length >= 18);
  assert.ok(pieces.length >= 3, `expected several pieces to check, got ${pieces.length}`);
  for (const piece of pieces) assert.ok(!cf.includes(piece), `the dialog must not retype "${piece}": it lives in the copy module only`);
});
