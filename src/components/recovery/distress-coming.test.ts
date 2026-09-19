// P0 — Distress Coming gate. Sender control is disabled + labelled Coming.
// Copy must say it isn't live. Must not read as a cry for help.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { DISTRESS_COMING_COPY } from './distress-coming';

const here = dirname(fileURLToPath(import.meta.url));
const sheet = readFileSync(join(here, '..', 'RecoverySheet.tsx'), 'utf8');
const help = readFileSync(join(here, '..', 'HelpGuide.tsx'), 'utf8');

test('Coming copy states it is not live — no present-tense cry, no EMERGENCY', () => {
  assert.equal(DISTRESS_COMING_COPY.controlLabel, 'Coming');
  assert.match(DISTRESS_COMING_COPY.menuLabel, /coming/i);
  assert.match(DISTRESS_COMING_COPY.heading, /coming/i);
  assert.match(DISTRESS_COMING_COPY.body, /isn['’]t live/i);
  assert.match(DISTRESS_COMING_COPY.body, /would do nothing/i);

  const surfaces = [
    DISTRESS_COMING_COPY.menuLabel,
    DISTRESS_COMING_COPY.heading,
    DISTRESS_COMING_COPY.body,
    DISTRESS_COMING_COPY.controlLabel,
  ].join('\n');
  assert.doesNotMatch(surfaces, /emergency/i);
  assert.doesNotMatch(surfaces, /auto-?dial/i);
  assert.doesNotMatch(surfaces, /calling for help/i);
  assert.doesNotMatch(surfaces, /\b(was|is|has been) sent\b/i);
  assert.doesNotMatch(surfaces, /silent cry/i);
});

test('RecoverySheet wires the Coming control as hard-disabled — no sendDistress path', () => {
  assert.match(sheet, /DISTRESS_COMING_COPY/);
  assert.match(sheet, /disabled=\{true\}/);
  assert.match(sheet, /aria-disabled=\{true\}/);
  assert.match(sheet, /data-testid="distress-coming-control"/);
  assert.doesNotMatch(sheet, /sendDistress/);
  assert.doesNotMatch(sheet, /EMERGENCY/);
  assert.doesNotMatch(sheet, /auto-?dial/i);
  // No leftover targeting UI that looks like composing a cry.
  assert.doesNotMatch(sheet, /Name Guardians first/);
});

test('HelpGuide does not render the live-cry Distress constant', () => {
  assert.doesNotMatch(help, /TRUST_RECIPE_COPY\.recoveryDistress/);
});
