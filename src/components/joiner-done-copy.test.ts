// Run: npx tsx --test src/components/joiner-done-copy.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { alreadyKnownCopy } from './joiner-done-copy';

test('a giver you blocked: the screen says so, and that nothing was sent', () => {
  assert.deepEqual(alreadyKnownCopy('Bob', true), { heading: 'You’ve blocked this person', sub: 'Nothing was sent to them.' });
});

test('a giver you blocked is not named as connected, and nothing suggests undoing the block', () => {
  const c = alreadyKnownCopy('Bob', true);
  assert.doesNotMatch(c.heading + c.sub, /connected|network|unblock/i);
});

test('a giver you already know is unchanged', () => {
  assert.deepEqual(alreadyKnownCopy('Bob', false), { heading: 'You’re already connected', sub: 'Bob are already in your network.' });
  assert.equal(alreadyKnownCopy('', false).sub, 'They are already in your network.');
});
