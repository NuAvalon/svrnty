// src/lib/trust/frozen-contact.test.ts: "frozen" = a contact who is IN the book and BLOCKED. It is the exact complement of admitContact over present contacts:
// a stranger, a removed contact (no row) and anything that is not an object are NOT frozen, so none of them can ever reach the hold path.
// Run: npx tsx --test src/lib/trust/frozen-contact.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { admitContact, isFrozenContact } from './admit-contact';

test('F1 a present contact that is blocked (top-level flag) is frozen', () => {
  assert.equal(isFrozenContact({ blocked: true }), true);
});

test('F2 a contact blocked only in metadata is frozen too (the same two places admitContact checks)', () => {
  assert.equal(isFrozenContact({ metadata: { blocked: true } }), true);
});

test('F3 an unblocked present contact is NOT frozen (it is admitted)', () => {
  for (const c of [{}, { blocked: false }, { blocked: false, metadata: { blocked: false } }, { metadata: {} }, { metadata: null }]) {
    assert.equal(isFrozenContact(c), false, JSON.stringify(c));
    assert.equal(admitContact(c), true, `and admitContact agrees: ${JSON.stringify(c)}`);
  }
});

test('F4 a stranger or a REMOVED contact (no row) and anything that is not an object is NOT frozen', () => {
  for (const c of [null, undefined, 'x', 0, 1, true, false]) assert.equal(isFrozenContact(c), false, String(c));
});

test('F5 over present contacts frozen is exactly "not admitted": the two can never both be true or both be false', () => {
  const present = [{}, { blocked: true }, { blocked: 'yes' }, { blocked: 0 }, { metadata: { blocked: true } }, { metadata: { blocked: 1 } }, { metadata: { blocked: '' } }, { blocked: false, metadata: { blocked: true } }];
  for (const c of present) assert.equal(isFrozenContact(c), !admitContact(c), JSON.stringify(c));
});
