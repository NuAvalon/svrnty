// src/lib/contacts/empty-book-copy.test.ts
// Run: npx tsx --test src/lib/contacts/empty-book-copy.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { emptyBookCopy } from './empty-book-copy';

const base = { searching: false, showBlocked: false, totalCount: 0, blockedCount: 0 };

test('a book that holds no contacts at all still says "No contacts yet"', () => {
  assert.deepEqual(emptyBookCopy(base), { title: 'No contacts yet', hint: 'Import a VCF or add someone to start your master book' });
});

test('a book whose only contacts are blocked says they exist, how many, and where (one and several)', () => {
  assert.deepEqual(emptyBookCopy({ ...base, totalCount: 1, blockedCount: 1 }), {
    title: 'No contacts in your main book',
    hint: '1 blocked contact is kept out of it. Open ⋯ → View blocked contacts (1).',
  });
  assert.equal(emptyBookCopy({ ...base, totalCount: 3, blockedCount: 3 }).hint, '3 blocked contacts are kept out of it. Open ⋯ → View blocked contacts (3).');
});

test('NEG: it does not claim "only blocked" when some contacts are not blocked (the empty list is a filter, not the book)', () => {
  assert.equal(emptyBookCopy({ ...base, totalCount: 3, blockedCount: 2 }).title, 'No contacts yet');
});

test('the other states are unchanged: a search, and the blocked list itself', () => {
  assert.deepEqual(emptyBookCopy({ ...base, searching: true, totalCount: 2, blockedCount: 2 }), { title: 'No matching contacts', hint: 'Try a different search' });
  assert.deepEqual(emptyBookCopy({ ...base, showBlocked: true, totalCount: 2, blockedCount: 0 }), { title: 'No blocked contacts', hint: 'Blocked stays out of the main book — exit via ⋯' });
  assert.equal(emptyBookCopy({ ...base, showBlocked: true, totalCount: 2, blockedCount: 2 }).title, 'No blocked contacts');
});

test('PIN: the contact manager takes the empty-state words from emptyBookCopy and no longer hard-codes "No contacts yet"', () => {
  const ui = readFileSync(new URL('../../components/ContactManagement.tsx', import.meta.url), 'utf8');
  assert.match(ui, /emptyBookCopy\(\{ searching: !!searchQuery, showBlocked, totalCount: contacts\.length, blockedCount \}\)/);
  assert.doesNotMatch(ui, /'No contacts yet'/);
});
