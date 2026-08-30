import assert from 'node:assert/strict';
import { test } from 'node:test';
import { HELP_STEPS } from './copy';

test('HELP_STEPS has the Getting Started sections', () => {
  assert.equal(HELP_STEPS.length, 6);
  assert.deepEqual(
    HELP_STEPS.map((s) => s.title),
    [
      'Create Your Identity',
      'Back Up Your Identity',
      'Add People You Know',
      'Trust',
      'Trust over time',
      'How It Works',
    ]
  );
});

test('recovery copy uses alternatives model — never both-required', () => {
  const blob = HELP_STEPS.flatMap((s) => s.content).join('\n').toLowerCase();
  assert.match(blob, /recovery code/);
  assert.match(blob, /password \+ file/);
  assert.match(blob, /recovery code \+ file/);
  assert.doesNotMatch(blob, /both (a )?password and (a )?recovery/);
  assert.doesNotMatch(blob, /if you lose it, you lose your identity/);
});

test('backup path points at Export Vault — not stale Secure Export', () => {
  const backup = HELP_STEPS.find((s) => s.title === 'Back Up Your Identity');
  assert.ok(backup);
  const blob = backup!.content.join('\n');
  assert.match(blob, /Export Vault \(\.svrnty\)/);
  assert.doesNotMatch(blob, /Secure Export/);
});

test('trust copy does not invent wire notify or decay customize UI', () => {
  const blob = HELP_STEPS.flatMap((s) => s.content).join('\n').toLowerCase();
  assert.match(blob, /not sent from the confirm/);
  assert.match(blob, /not shipped yet/);
  assert.doesNotMatch(blob, /both of you will notice/);
  assert.doesNotMatch(blob, /you can customize the decay period/);
});

test('no seed-only / phrase-alone overclaim', () => {
  const blob = HELP_STEPS.flatMap((s) => s.content).join('\n').toLowerCase();
  assert.doesNotMatch(blob, /phrase alone/);
  assert.doesNotMatch(blob, /without (the |your )?backup file/);
  assert.doesNotMatch(blob, /12-word/);
});
