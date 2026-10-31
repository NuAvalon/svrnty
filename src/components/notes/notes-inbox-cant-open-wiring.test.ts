// src/components/notes/notes-inbox-cant-open-wiring.test.ts
// #731 static guards: the repo has no DOM harness for NotesInbox, so these pin the wiring (the pure lines are in cant-open-notice.test.ts).
// Run: npx tsx --test src/components/notes/notes-inbox-cant-open-wiring.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const inbox = () => readFileSync(new URL('./NotesInbox.tsx', import.meta.url), 'utf8');

test('W1 the inbox builds its lines ONLY through cantOpenNotices, from the local rows and the saved dismissal', () => {
  const src = inbox();
  assert.match(src, /cantOpenNotices\(deadRows, \(f\) => byFp\.get\(normalizeFingerprintHex\(f\)\) \?\? null, sDismissedAt\)/);
  assert.match(src, /listDeadLetters\(\), getCantOpenSDismissedAt\(\)/);
  assert.doesNotMatch(src, /keptDeadLettered/, 'the old count line is not used here: #731 copy replaces it');
});

test('W2 each line renders its text and nothing else from the row (no fp, no time)', () => {
  const src = inbox();
  const block = src.slice(src.indexOf('data-testid="notes-cant-open"'), src.indexOf('{NOTES_COPY.searchLabel}'));
  assert.ok(block.length > 0);
  assert.match(block, /\{n\.text\}/);
  assert.doesNotMatch(block, /first_seen|n\.fingerprint\}|formatFingerprintShort/, 'no time and no fingerprint on screen');
});

test('W3 the resend action shows only on R lines for a contact this device can message; the S line is the only one with Dismiss', () => {
  const src = inbox();
  assert.match(src, /n\.group === 'R' && n\.fingerprint && sendable\.has\(normalizeFingerprintHex\(n\.fingerprint\)\)/);
  assert.match(src, /n\.group === 'S' \? \(\s*<button[\s\S]*?onClick=\{\(\) => void dismissCantOpenS\(\)\}/);
  assert.match(src, /await setCantOpenSDismissedAt\(now\)/);
});
