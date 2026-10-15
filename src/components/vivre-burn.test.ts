// Ace vivre: eaten top-right corner, char crust — not a glow blob or ribbon.
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
const map = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), 'TrustMap.tsx'),
  'utf8',
);

test('distress mark is a jagged top-right corner, not a full-width ribbon', () => {
  assert.match(src, /data-ace-vivre="corner"/);
  assert.match(src, /data-testid="vivre-paper-bite"/);
  assert.match(src, /data-testid="vivre-char-ridge"/);
  assert.match(src, /VIVRE_PAPER_CLIP/);
  // Bite starts on the top edge, not at x=0 (that would be a full-width top burn).
  assert.match(src, /\[70\.5, 0\.0\]/);
  assert.doesNotMatch(src, /viewBox="0 0 400 64"/);
});

test('the card clip eats the corner — irregular bite, not a filled char mass or smooth wedge', () => {
  assert.match(src, /export const VIVRE_PAPER_CLIP/);
  assert.match(map, /clipPath: contactHasDistress\(focusEdge\) \? VIVRE_PAPER_CLIP/);
  assert.match(src, /strokeLinejoin="miter"/);
  assert.doesNotMatch(src, /Q72 62 58 48/);
  assert.doesNotMatch(src, /L188 154 L176 162/);
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
