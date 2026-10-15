// Ace vivre: jagged top-right char, not a glow blob.
// Run: npx tsx --test src/components/vivre-burn.test.ts

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import assert from 'node:assert/strict';

const src = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'VivreBurn.tsx'),
  'utf8',
);

test('distress mark is a jagged top-right corner, not a full-width ribbon', () => {
  assert.match(src, /data-ace-vivre="corner"/);
  assert.match(src, /data-testid="vivre-paper-bite"/);
  assert.match(src, /data-testid="vivre-char-ridge"/);
  assert.match(src, /top: 0/);
  assert.match(src, /right: 0/);
  assert.doesNotMatch(src, /width: '100%'/);
});

test('the paper is eaten — jagged L-path char, not a smooth quadratic wedge', () => {
  assert.match(src, /L188 154 L176 162/);
  assert.doesNotMatch(src, /Q72 62 58 48/);
  assert.match(src, /strokeLinejoin="miter"/);
});

test('flames sit on the ridge and rest when motion is reduced', () => {
  assert.match(src, /FLAMES/);
  assert.match(src, /prefers-reduced-motion/);
  assert.doesNotMatch(src, /radialGradient id=\{ember\}/);
});

test('galaxy star ember is a vivre tongue, not a presence pip', () => {
  assert.match(src, /data-ace-vivre="star"/);
  assert.doesNotMatch(src, /last-seen|online|presence/i);
});
