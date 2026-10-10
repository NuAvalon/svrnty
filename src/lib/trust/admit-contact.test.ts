// src/lib/trust/admit-contact.test.ts
// Survivor-safety gate (Codex P1 #2): a BLOCKED in-book sender must NOT be admitted — their inbound
// note / trust-affirmation is dropped at admission (never persisted, never flips trust). Refutes the
// prior "in-book EXISTS = admitted" gap that let a blocked sender still deliver.
// Run: npx tsx --test src/lib/trust/admit-contact.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { admitContact } from '@/lib/trust/admit-contact';

test('a stranger (not in book) is NOT admitted', () => {
  assert.equal(admitContact(null), false);
  assert.equal(admitContact(undefined), false);
});

test('an in-book UNblocked sender IS admitted (blocked false or absent)', () => {
  assert.equal(admitContact({ blocked: false }), true);
  assert.equal(admitContact({}), true);
});

test('an in-book BLOCKED sender is NOT admitted — blocking must block (P1#2 survivor-safety)', () => {
  assert.equal(admitContact({ blocked: true }), false);
});

test('blocked via metadata.blocked (device-local) is ALSO not admitted — canonical dual check', () => {
  assert.equal(admitContact({ metadata: { blocked: true } }), false);
  assert.equal(admitContact({ blocked: false, metadata: { blocked: true } }), false);
  assert.equal(admitContact({ blocked: false, metadata: { blocked: false } }), true);
});
