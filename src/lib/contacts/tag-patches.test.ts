// The group edits decide from the record the store holds when the write runs. Each helper takes only that record, so these tests show that
// what it carries now (tags added since a screen was drawn) is kept, and that nothing is written when there is nothing to change.
//
// Run: npx tsx --test src/lib/contacts/tag-patches.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toggleTagPatch, renameTagPatch, removeTagPatch, addTagPatch } from './tag-patches';
import type { ContactRecord } from '@/lib/identity/client-store';

const rec = (metadata: Record<string, unknown> | undefined): ContactRecord =>
  ({ id: 'c1', owner_fingerprint: 'o', fingerprint: 'f', name: 'n', email: 'e', public_key: 'k', added_at: 'a', metadata }) as unknown as ContactRecord;

test('toggle: adds a tag the held record lacks, and keeps every other tag and metadata key', () => {
  const p = toggleTagPatch(rec({ tags: ['a', 'x'], notes: 'keep' }), 'b');
  assert.deepEqual(p.metadata, { tags: ['a', 'x', 'b'], notes: 'keep' });
});

test('toggle: removes a tag the held record has', () => {
  assert.deepEqual(toggleTagPatch(rec({ tags: ['a', 'b'] }), 'a').metadata, { tags: ['b'] });
});

test('toggle: a record with no metadata gets a one-tag list', () => {
  assert.deepEqual(toggleTagPatch(rec(undefined), 'a').metadata, { tags: ['a'] });
});

test('toggle: the tags come from the held record, so a tag added elsewhere since the screen was drawn survives', () => {
  // the screen showed ['a']; another tab added 'z'; the held record is what the store has now
  assert.deepEqual(toggleTagPatch(rec({ tags: ['a', 'z'] }), 'b').metadata, { tags: ['a', 'z', 'b'] });
});

test('rename: renames on the held record, and de-duplicates when the new name is already there', () => {
  assert.deepEqual(renameTagPatch(rec({ tags: ['a', 'b'] }), 'a', 'c').metadata, { tags: ['c', 'b'] });
  assert.deepEqual(renameTagPatch(rec({ tags: ['a', 'c'] }), 'a', 'c').metadata, { tags: ['c'] });
});

test('rename: an EMPTY patch when the held record no longer carries the old name', () => {
  assert.deepEqual(renameTagPatch(rec({ tags: ['b'] }), 'a', 'c'), {});
  assert.deepEqual(renameTagPatch(rec(undefined), 'a', 'c'), {});
});

test('remove: removes from the held record; an EMPTY patch when it is not there', () => {
  assert.deepEqual(removeTagPatch(rec({ tags: ['a', 'b'] }), 'a').metadata, { tags: ['b'] });
  assert.deepEqual(removeTagPatch(rec({ tags: ['b'] }), 'a'), {});
});

test('add: adds once, keeps what the held record carries', () => {
  assert.deepEqual(addTagPatch(rec({ tags: ['a'] }), 'b').metadata, { tags: ['a', 'b'] });
  assert.deepEqual(addTagPatch(rec({ tags: ['a', 'b'] }), 'b').metadata, { tags: ['a', 'b'] });
  assert.deepEqual(addTagPatch(rec(undefined), 'b').metadata, { tags: ['b'] });
});

test('add: keeps the other metadata keys the held record carries', () => {
  assert.deepEqual(addTagPatch(rec({ tags: ['a'], notes: 'keep' }), 'b').metadata, { tags: ['a', 'b'], notes: 'keep' });
});

test('no helper mutates the record it is given', () => {
  const r = rec({ tags: ['a', 'b'], notes: 'n' });
  const before = JSON.stringify(r);
  toggleTagPatch(r, 'c'); renameTagPatch(r, 'a', 'z'); removeTagPatch(r, 'a'); addTagPatch(r, 'q');
  assert.equal(JSON.stringify(r), before);
});
