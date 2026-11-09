// Run: npx tsx --test src/lib/sync/contact-update-gate.test.ts
// Who an update may go to is decided from the address book as it stands at send time.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { blockedInBook, recipientGateFromBook as gate } from './contact-update-gate';

const A = 'AAAA0000', B = 'BBBB1111';

test('a contact in the book who is not blocked is admitted', () => {
  assert.equal(gate([{ fingerprint: A }])(A), true);
});

test('blocked at the top level is refused', () => {
  assert.equal(gate([{ fingerprint: A, blocked: true }])(A), false);
});

test('blocked only in metadata is refused', () => {
  assert.equal(gate([{ fingerprint: A, metadata: { blocked: true } }])(A), false);
});

test('blocked AND trusted is refused: trust does not outrank a block', () => {
  assert.equal(gate([{ fingerprint: A, blocked: true, trusted: true, trust_level: 'trusted' }])(A), false);
});

test('someone no longer in the book is refused', () => {
  assert.equal(gate([{ fingerprint: B }])(A), false);
});

for (const book of [[], null, undefined, 'x', 3, {}]) {
  test(`a book of ${JSON.stringify(book)} admits nobody`, () => {
    assert.equal(gate(book)(A), false);
  });
}

test('one blocked row refuses the person, in either order', () => {
  assert.equal(gate([{ fingerprint: A }, { fingerprint: A, blocked: true }])(A), false);
  assert.equal(gate([{ fingerprint: A, blocked: true }, { fingerprint: A }])(A), false);
});

test('a row with no fingerprint falls back to its id, the same way the audience does', () => {
  assert.equal(gate([{ id: A }])(A), true);
  assert.equal(gate([{ id: A, blocked: true }])(A), false);
});

test('surrounding space and letter case do not separate a person from their block', () => {
  assert.equal(gate([{ fingerprint: ` ${A.toLowerCase()} ` }])(A), true);
  assert.equal(gate([{ fingerprint: A.toLowerCase() }, { fingerprint: A, blocked: true }])(A.toLowerCase()), false);
});

test('junk rows are ignored and never throw', () => {
  const g = gate([null, 3, 'x', [], {}, { fingerprint: '' }, { fingerprint: A }]);
  assert.equal(g(A), true);
  assert.equal(g(''), false);
});

test('fingerprints compare as hex, so case, colons and spaces are the same person', () => {
  assert.equal(gate([{ fingerprint: 'aa:bb cc00' }])('AABBCC00'), true);
  assert.equal(gate([{ fingerprint: 'aa:bb cc00', blocked: true }])('AABBCC00'), false);
});

test('a row that carries the person under peer_fingerprint is read, the same way the notes list reads it', () => {
  assert.equal(gate([{ peer_fingerprint: A }])(A), true);
  assert.equal(gate([{ peer_fingerprint: A, blocked: true }])(A), false);
});

test('a blocked row under peer_fingerprint outranks a clean row under fingerprint', () => {
  assert.equal(gate([{ fingerprint: A }, { peer_fingerprint: A, metadata: { blocked: true } }])(A), false);
});

test('blockedInBook: only a blocked row says blocked', () => {
  assert.equal(blockedInBook([{ fingerprint: A, blocked: true }])(A), true);
  assert.equal(blockedInBook([{ fingerprint: A, metadata: { blocked: true } }])(A), true);
  assert.equal(blockedInBook([{ fingerprint: A }])(A), false);
});

test('blockedInBook: someone not in the book is not blocked (a joiner has usually never met the giver)', () => {
  assert.equal(blockedInBook([])(A), false);
  assert.equal(blockedInBook([{ fingerprint: B, blocked: true }])(A), false);
});

test('blockedInBook: one blocked row wins over a clean row, and spelling does not matter', () => {
  assert.equal(blockedInBook([{ fingerprint: 'aa:bb' }, { peer_fingerprint: 'AABB', blocked: true }])('aabb'), true);
});

for (const book of [null, undefined, 'x', 3, {}]) {
  test(`blockedInBook: an unreadable book (${JSON.stringify(book)}) can't say someone is safe, so it refuses`, () => {
    assert.equal(blockedInBook(book)(A), true);
  });
}
