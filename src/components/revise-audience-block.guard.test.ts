// Run: npx tsx --test src/components/revise-audience-block.guard.test.ts
// Pins the wiring in SoverentityFrontend, which unit tests can't reach: a real browser spec proves the behaviour, this keeps it wired.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const src = readFileSync(join(__dirname, 'SoverentityFrontend.tsx'), 'utf8');

test('the send reads the book at send time and hands the check to the builder', () => {
  assert.match(src, /recipientGateFromBook\(await getAllContacts\(/);
  assert.match(src, /sendContactUpdate\(\s*\{ version: nextVersion, delta: buildMethodDelta\(req\.kind, value\) \},\s*owner,\s*recipients,\s*admit,\s*\)/);
});

test('the check is read inside the try, so a store failure can never become a send', () => {
  const at = src.indexOf('recipientGateFromBook(await getAllContacts(');
  const tryAt = src.lastIndexOf('try {', at);
  const between = src.slice(tryAt, at);
  assert.ok(tryAt > 0 && !between.includes('} catch'), 'read must sit inside the try block');
});

test('the audience leaves out anyone a block applies to', () => {
  assert.match(src, /rows\s*\.filter\(admitContact\)\s*\.map\(/);
});

test('Revise rebuilds the audience from the book before the dialog opens', () => {
  assert.match(src, /onRevise=\{\(kind\) => \{ void refreshAudience\(\)\.finally\(\(\) => setReviseKind\(kind\)\); \}\}/);
});

test('a failed audience read leaves nobody offered, not the old list', () => {
  assert.match(src, /\.catch\(\(\) => setAudience\(\[\]\)\)/);
});
