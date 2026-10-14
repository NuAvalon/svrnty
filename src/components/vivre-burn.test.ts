// Ace vivre: the paper edge burns, not a corner badge.
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

test('distress mark is a full-width top paper edge, not a corner wedge', () => {
  assert.match(src, /data-ace-vivre="edge"/);
  assert.match(src, /data-testid="vivre-paper-bite"/);
  assert.match(src, /left: 0/);
  assert.match(src, /width: '100%'/);
  assert.doesNotMatch(src, /top-right corner/);
});

test('flames sit on the char ridge and rest when motion is reduced', () => {
  assert.match(src, /FLAMES/);
  assert.match(src, /prefers-reduced-motion/);
  assert.match(src, /svrnty-vivre-lick/);
});

test('galaxy star ember is a vivre tongue, not a presence pip', () => {
  assert.match(src, /data-ace-vivre="star"/);
  assert.doesNotMatch(src, /last-seen|online|presence/i);
});
