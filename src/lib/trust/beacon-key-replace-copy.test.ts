// The words shown when a contact's newer signed card replaces what is saved for them are the copy owner's, byte for byte (ledger rows 345a, 344b, 345c).
// Run: npx tsx --test src/lib/trust/beacon-key-replace-copy.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as copy from './beacon-key-replace-copy';

const h = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 16);

// [row, template, length, sha256 prefix]: the ledger's own numbers (rows 345a, 344b, 345c), re-checked against the strings before this was written
const ROWS: Array<[string, string, number, string]> = [
  ['345a replaced', copy.KEY_REPLACED, 85, '0a863a7ac84b70a0'],
  ['344b unconfirmed again', copy.KEY_REPLACED_UNCONFIRMED, 52, '9061fecf8e057145'],
  ['345c refused', copy.KEY_REPLACE_REFUSED, 121, '4682ab5e73fd7a85'],
  ['338d nameless (reused from the held-messages copy)', copy.KEY_REPLACE_NO_NAME, 11, 'af49636912aec2d2'],
  ['347 nameless, capitalised, for the refused line only', copy.KEY_REPLACE_NO_NAME_INITIAL, 11, '75a49069894300cf'],
];

test('KC1 every template is the copy owner\'s bytes (length + sha256 prefix) and plain ASCII with straight apostrophes', () => {
  assert.equal(ROWS.length, 5);
  for (const [name, text, len, sha] of ROWS) {
    assert.equal(text.length, len, `${name}: length`);
    assert.equal(h(text), sha, `${name}: sha256 prefix`);
    assert.ok(/^[\x20-\x7e]+$/.test(text), `${name}: ASCII`);
  }
});

test('KC2 the notice for each outcome: replaced alone, replaced + unconfirmed ONLY when the pair was confirmed before, and one refused line for both refusal paths', () => {
  assert.equal(copy.replaceNotice({ kind: 'replaced', wasConfirmed: false }, 'Ada'), 'A newer signed card from Ada has changed the security details saved here for them.');
  assert.equal(copy.replaceNotice({ kind: 'replaced', wasConfirmed: true }, 'Ada'),
    'A newer signed card from Ada has changed the security details saved here for them. Because of this update, Ada is unconfirmed again.');
  assert.equal(copy.replaceNotice({ kind: 'refused' }, 'Ada'), "Ada's newer card couldn't be saved, so the security details saved for them are unchanged. Trying again later may work.");
});

test('KC3 {name} is the BOOK\'s name exactly as given: a name that looks like a placeholder or a replacement pattern is inserted as it is, and a nameless contact gets the approved words', () => {
  assert.equal(copy.replaceNotice({ kind: 'refused' }, '{name} $& $1'), "{name} $& $1's newer card couldn't be saved, so the security details saved for them are unchanged. Trying again later may work.");
  assert.ok(copy.replaceNotice({ kind: 'replaced', wasConfirmed: false }, '').includes('from this person has changed'));
  assert.ok(copy.replaceNotice({ kind: 'replaced', wasConfirmed: false }, '   ').includes('from this person has changed'), 'a name of only spaces is nameless too');
  // the refused line STARTS with the name, so a nameless contact gets the capital there, and ONLY there; a real book name is never capitalised
  assert.ok(copy.replaceNotice({ kind: 'refused' }, '').startsWith("This person's newer card couldn't be saved"), 'refused + nameless starts with a capital');
  assert.ok(copy.replaceNotice({ kind: 'refused' }, '   ').startsWith("This person's"), 'and so does a name of only spaces');
  assert.ok(copy.replaceNotice({ kind: 'refused' }, 'ada').startsWith("ada's newer card"), 'a real name is inserted exactly as it is: never capitalised');
  assert.ok(copy.replaceNotice({ kind: 'replaced', wasConfirmed: true }, '').includes('Because of this update, this person is unconfirmed again.'), 'mid-sentence the lower-case words stay');
});

test('KC4 what the rows FORBID: no line says key, generation, withdrawn, safe, verified, compromised, or points to a fix; the refused line never says nothing changed', () => {
  const lines = [copy.KEY_REPLACED, copy.KEY_REPLACED_UNCONFIRMED, copy.KEY_REPLACE_REFUSED, copy.replaceNotice({ kind: 'replaced', wasConfirmed: true }, 'Ada'), copy.replaceNotice({ kind: 'refused' }, 'Ada')];
  for (const l of lines) {
    assert.doesNotMatch(l, /\bkeys?\b|generation|withdraw|\bsafe|verified|compromis|in person|confirm (again|with)|restore|fix/i, l);
    assert.doesNotMatch(l, /\d/, 'no digit, no count');
  }
  assert.doesNotMatch(copy.KEY_REPLACE_REFUSED, /nothing changed/i, 'on the key-write-aborted path the queue is already committed, so "nothing changed" would be false');
  assert.match(copy.KEY_REPLACE_REFUSED, /unchanged/);
});

test('KC5 fill() puts each value in once, and a hole or an unused value THROWS', () => {
  assert.equal(copy.fill('a {x} b {x}', { x: '{y}' }), 'a {y} b {y}');
  assert.throws(() => copy.fill('a {x} {y}', { x: 1 }), /no value for \{y\}/);
  assert.throws(() => copy.fill('a {x}', { x: 1, z: 2 }), /\{z\} is not in this sentence/);
});
