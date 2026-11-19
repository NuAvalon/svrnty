// Run: npx tsx --test src/components/contacts/removed-before-copy.test.ts
// The words on the owner's private card for a removed-then-re-added person are the copy owner's, byte for byte (ledger rows 311a, 311b, 314a): pinned by length and sha256 prefix.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as copy from './removed-before-copy';

const h = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 16);
const HERE = dirname(fileURLToPath(import.meta.url));
const code = (f: string): string => readFileSync(join(HERE, f), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');

test('RB1 the three sentences are the copy owner\'s bytes (length + sha256 prefix) and plain ASCII', () => {
  const rows: Array<[string, string, number, string]> = [
    ['notice 311a', copy.REMOVED_BEFORE_NOTICE, 157, '89947ff34c4b995d'],
    ['helper 314a', copy.REMOVED_BEFORE_KEEP_HELPER, 60, 'bb4f6aa12f9e9976'],
    ['failure 314b = 311b', copy.REMOVED_BEFORE_DROP_FAILED, 102, '17bec0c1bbd54de7'],
  ];
  for (const [name, text, len, sha] of rows) {
    assert.equal(text.length, len, `${name}: length`);
    assert.equal(h(text), sha, `${name}: sha256 prefix`);
    assert.ok(/^[\x20-\x7e]+$/.test(text), `${name}: ASCII`);
  }
});

test('RB2 the buttons are exactly Keep them / Remove them again, and Try again / Not now; there is no default and no "Leave it"', () => {
  assert.equal(copy.REMOVED_BEFORE_KEEP, 'Keep them');
  assert.equal(copy.REMOVED_BEFORE_REMOVE_AGAIN, 'Remove them again');
  assert.equal(copy.REMOVED_BEFORE_TRY_AGAIN, 'Try again');
  assert.equal(copy.REMOVED_BEFORE_NOT_NOW, 'Not now');
  assert.doesNotMatch(code('RemovedBeforeNotice.tsx') + code('removed-before-copy.ts'), /Leave it|autoFocus|defaultChecked/i);
});

test('RB3 nothing implies blocked: none of the words appears in any string the screen shows', () => {
  for (const v of Object.values(copy)) assert.doesNotMatch(String(v), /block|restrict|unblock/i);
});

test('RB4 the screen file spells no sentence of its own: it renders the constants only', () => {
  const src = code('RemovedBeforeNotice.tsx');
  assert.doesNotMatch(src, />\s*[A-Za-z][^<>{}]*\s[^<>{}]*</, 'no literal text between tags');
  const lits = [...src.matchAll(/(['"`])((?:(?!\1).)*)\1/g)].map((m) => m[2]);
  assert.deepEqual(lits.filter((t) => /[A-Z][a-z]+( [a-z']+){2,}/.test(t)), [], 'no quoted sentence');
});
