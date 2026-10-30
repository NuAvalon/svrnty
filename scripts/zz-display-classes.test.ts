// Apollo's function-verify addition for flint/note-id-short-print (cee687d): pins EVERY character class displayLine must escape, one
// representative each, because three classes (C1, bidi isolates, tag characters) were in the regex but pinned by no test.
// No backslash-u literals are used here on purpose: every character is built from its code point.
// Run: npx tsx --test scripts/zz-display-classes.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { displayLine, shortNoteId } from './devin-comm-inbound';

const BS = String.fromCharCode(92);
const esc = (cp: number) => BS + 'u{' + cp.toString(16).toUpperCase().padStart(4, '0') + '}';
const ch = (cp: number) => String.fromCodePoint(cp);
const CLASSES: Array<[string, number[]]> = [
  ['C0 controls incl. LF CR VT FF ESC TAB NUL', [0x00, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1b, 0x1f]],
  ['DEL', [0x7f]],
  ['C1 controls incl. NEL (a line terminator) and 8-bit CSI', [0x80, 0x85, 0x9b, 0x9f]],
  ['zero-width and LRM/RLM', [0x200b, 0x200c, 0x200d, 0x200e, 0x200f]],
  ['line / paragraph separators and bidi embeddings+overrides', [0x2028, 0x2029, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e]],
  ['bidi isolates', [0x2066, 0x2067, 0x2068, 0x2069]],
  ['BOM / ZWNBSP', [0xfeff]],
  ['tag characters', [0xe0000, 0xe0041, 0xe007f]],
];

for (const [name, cps] of CLASSES) {
  test('displayLine escapes the class: ' + name, () => {
    for (const cp of cps) {
      const out = displayLine('a' + ch(cp) + 'b');
      assert.equal(out, 'a' + esc(cp) + 'b', 'U+' + cp.toString(16) + ' must be shown as a visible escape');
      assert.ok(!out.includes(ch(cp)), 'the raw U+' + cp.toString(16) + ' must not survive');
    }
  });
}

test('displayLine: after escaping there is NO line terminator of any kind left, and plain text, accents, CJK and emoji are untouched', () => {
  const breaks = [0x0a, 0x0d, 0x0b, 0x0c, 0x85, 0x2028, 0x2029].map(ch);
  const out = displayLine('x' + breaks.join('') + 'y');
  assert.equal(breaks.some((b) => out.includes(b)), false);
  const plain = 'plain text, ' + ch(0xe9) + ' ' + ch(0xfc) + ' ' + ch(0x65e5) + ch(0x672c) + ch(0x8a9e) + ' ' + ch(0x1f331);
  assert.equal(displayLine(plain), plain);
});

test('shortNoteId: at most 13 characters, never the full id, and a non-token is "?"', () => {
  const full = 'note_0123456789abcdef-0123-4567';
  assert.equal(shortNoteId(full), 'note_01234567');
  assert.equal(shortNoteId(full).length, 13);
  assert.equal(shortNoteId('has space'), '?');
  assert.equal(shortNoteId(undefined), '?');
});
