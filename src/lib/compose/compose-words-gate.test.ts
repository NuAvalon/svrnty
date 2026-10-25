// Run: npx tsx --test src/lib/compose/compose-words-gate.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { composeWordsConfirmed } from './compose-words-gate';

test('the check-words switch is OFF by default and ON only for the exact string "1" (nothing truthy-ish turns it on)', () => {
  assert.equal(composeWordsConfirmed({}), false);
  for (const v of [undefined, '', '0', 'true', 'TRUE', 'yes', ' 1', '1 ', '01', 'on']) assert.equal(composeWordsConfirmed({ NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED: v }), false, JSON.stringify(v));
  assert.equal(composeWordsConfirmed({ NEXT_PUBLIC_COMPOSE_WORDS_CONFIRMED: '1' }), true);
  assert.equal(composeWordsConfirmed({ COMPOSE_WORDS_CONFIRMED: '1' }), false, 'only the NEXT_PUBLIC_ name counts');
});
