// The call walker the static guards share: it finds each `name(...)` call by balanced parentheses and must not be thrown off by what is
// inside the call body. Strings and comments are the two ways text can hide a parenthesis or a quote.
//
// Run: npx tsx --test src/lib/identity/static-guard-kit.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { callsOf } from './static-guard-kit';

test('a nested call and a multi-line body are one call', () => {
  const t = 'write(a, (f) => {\n  return patch(f, g(1));\n}); other(2);';
  assert.deepEqual(callsOf(t, 'write'), ['write(a, (f) => {\n  return patch(f, g(1));\n})']);
});

test('a parenthesis inside a string or a template literal does not end the call', () => {
  const t = "write(a, ')', `x ) ${y}`, \"(\"); after(1);";
  assert.deepEqual(callsOf(t, 'write'), ["write(a, ')', `x ) ${y}`, \"(\")"]);
});

test('an apostrophe inside a // comment in the body does not start a string and swallow the rest of the file', () => {
  const t = "write(a, (f) => {\n  // the owner's copy\n  return patch(f);\n}); const x = other('y');";
  assert.deepEqual(callsOf(t, 'write'), ["write(a, (f) => {\n  // the owner's copy\n  return patch(f);\n})"]);
});

test('a quote and a parenthesis inside a /* */ comment in the body are skipped; an unclosed one ends the scan at the end of the text', () => {
  const t = "write(a, /* ) ' \" ` */ b); after(1);";
  assert.deepEqual(callsOf(t, 'write'), ["write(a, /* ) ' \" ` */ b)"]);
  assert.equal(callsOf('write(a, /* never closed', 'write').length, 1);
});

test('// inside a string is text, not a comment', () => {
  const t = "write('http://x.test/a', g()); next(1);";
  assert.deepEqual(callsOf(t, 'write'), ["write('http://x.test/a', g())"]);
});

test('a longer identifier or a method of something else is not the call', () => {
  assert.deepEqual(callsOf('xwrite(1); a.write(2); write(3);', 'write'), ['write(3)']);
});

test('two block comments side by side are both skipped, even with no space between them', () => {
  const t = "write(a, /* one *//* two ) */ b); after(1);";
  assert.deepEqual(callsOf(t, 'write'), ["write(a, /* one *//* two ) */ b)"]);
});

test('a // comment right after a colon (a ternary or an object key) is still a comment', () => {
  const t = "write(c ? b ://it's the other branch\n d); after('x');";
  assert.deepEqual(callsOf(t, 'write'), ["write(c ? b ://it's the other branch\n d)"]);
});
