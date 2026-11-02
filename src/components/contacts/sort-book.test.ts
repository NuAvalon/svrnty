import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sortBookContacts } from './sort-book';

const rows = [
  { name: 'Hypatia', trust_level: 'unverified' },
  { name: 'Ada Lovelace', trust_level: 'verified' },
  { name: 'Nikola Tesla', trust_level: 'unverified' },
  { name: 'alan turing', trust_level: 'trusted' },
];

test('default book order is name A–Z, case-insensitive', () => {
  const names = sortBookContacts(rows, 'name-asc').map((r) => r.name);
  assert.deepEqual(names, ['Ada Lovelace', 'alan turing', 'Hypatia', 'Nikola Tesla']);
});

test('name Z–A reverses the book', () => {
  const names = sortBookContacts(rows, 'name-desc').map((r) => r.name);
  assert.deepEqual(names, ['Nikola Tesla', 'Hypatia', 'alan turing', 'Ada Lovelace']);
});

test('trusted first is boolean grouping, then name — not a score', () => {
  const sorted = sortBookContacts(rows, 'trusted-first');
  assert.deepEqual(
    sorted.map((r) => r.name),
    ['Ada Lovelace', 'alan turing', 'Hypatia', 'Nikola Tesla'],
  );
  assert.equal(sorted[0].trust_level, 'verified');
  assert.equal(sorted[1].trust_level, 'trusted');
});

test('explicit trusted:false wins over a trusted trust_level', () => {
  const mixed = [
    { name: 'Zed', trusted: false, trust_level: 'trusted' },
    { name: 'Ann', trusted: true, trust_level: 'unverified' },
  ];
  const names = sortBookContacts(mixed, 'trusted-first').map((r) => r.name);
  assert.deepEqual(names, ['Ann', 'Zed']);
});
