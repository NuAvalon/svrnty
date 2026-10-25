import test from 'node:test';
import assert from 'node:assert/strict';
import { assertNotesStoreOpenFor } from './notes-owner-guard';

test('open for the same owner → allowed', () => {
  assert.doesNotThrow(() => assertNotesStoreOpenFor('aa'.repeat(20), 'aa'.repeat(20)));
});

test('locked (null) → refused (retryable throw, never a silent pass)', () => {
  assert.throws(() => assertNotesStoreOpenFor(null, 'aa'.repeat(20)), /not open for this owner/);
});

test('open for a DIFFERENT owner (stale tab after an identity switch) → refused', () => {
  assert.throws(() => assertNotesStoreOpenFor('bb'.repeat(20), 'aa'.repeat(20)), /not open for this owner/);
});
