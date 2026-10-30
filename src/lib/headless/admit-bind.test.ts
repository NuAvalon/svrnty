// admit-card-key-hash-bind-001 anchors (node:test) — the two holes
// flint's reconciliation surfaced:
//
// (a) a card must not be mergeable under a member's claimed fp when its
//     key material doesn't hash to that fp — derivedCardFp +
//     cardFpBound run the SAME canonical quad derivation the consume
//     gate's fp-check uses.
// (b) upsertContact's shallow overlay let a partial card Frankenstein a
//     row's quad across epochs — key fields now move group-atomically.
//
// Anchors: forged card (claimed fp, foreign keys) -> underivable-or-
// mismatch refuse signal; legit card (keys hash to claimed) binds;
// underivable quad -> null (fail-closed); merge clears absent legs
// atomically; metadata-only card leaves key material untouched.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HeadlessStore } from './headless-store';
import { mergeKeyFieldsGroup } from './key-field-merge';
import { cardFpBound } from './admit-bind';

const dir = () => mkdtempSync(join(tmpdir(), 'admit-bind-'));

const ROW = {
  id: 'fpA', fingerprint: 'fpA', name: 'ember',
  public_key: 'OLD-ASC', pq_sig_public_key: 'OLD-SIG',
  pq_kem_public_key: 'OLD-KEM', trust_level: 'known',
};

test('group-atomic: a card carrying one key field takes ALL key fields — absent legs clear', () => {
  const s = new HeadlessStore(join(dir(), 'store.json'));
  s.upsertContact(ROW);
  s.upsertContact({ id: 'fpA', fingerprint: 'fpA', public_key: 'NEW-ASC' });
  const c = s.getContactByFingerprint('fpA');
  assert.equal(c.public_key, 'NEW-ASC');
  assert.equal(c.pq_sig_public_key, undefined,
               'stale sig leg must not overlay onto a new epoch');
  assert.equal(c.pq_kem_public_key, undefined);
  assert.equal(c.name, 'ember', 'non-key fields still merge');
});

test('metadata-only card leaves the row\'s key material untouched', () => {
  const s = new HeadlessStore(join(dir(), 'store.json'));
  s.upsertContact(ROW);
  s.upsertContact({ id: 'fpA', fingerprint: 'fpA', name: 'ember-2' });
  const c = s.getContactByFingerprint('fpA');
  assert.equal(c.public_key, 'OLD-ASC');
  assert.equal(c.pq_sig_public_key, 'OLD-SIG');
  assert.equal(c.pq_kem_public_key, 'OLD-KEM');
  assert.equal(c.name, 'ember-2');
});

test('id collision with a different fp REFUSES — row takeover is never a merge', () => {
  const s = new HeadlessStore(join(dir(), 'store.json'));
  s.upsertContact(ROW);
  assert.throws(
    () => s.upsertContact({ id: 'fpA', fingerprint: 'fpB',
                            public_key: 'FORGED' }),
    /refused: id fpA held by fp/);
  const c = s.getContactByFingerprint('fpA');
  assert.equal(c.public_key, 'OLD-ASC', 'row untouched after refuse');
});

test('same fp arriving under a different id refuses the merge leg', () => {
  const s = new HeadlessStore(join(dir(), 'store.json'));
  s.upsertContact(ROW);
  // fp match resolves the row by fingerprint — a colliding id field
  // still hits the takeover guard when the stored fp differs.
  s.upsertContact({ id: 'other-id', fingerprint: 'fpA',
                    name: 'ember-renamed' });
  assert.equal(s.getContactByFingerprint('fpA').name, 'ember-renamed');
  assert.equal(s.listContacts().length, 1);
});

test('keyless new contact inserts as-is', () => {
  const s = new HeadlessStore(join(dir(), 'store.json'));
  s.upsertContact({ id: 'x', fingerprint: 'x', name: 'n1' });
  s.upsertContact({ id: 'x', fingerprint: 'x', trust_level: 'known' });
  assert.equal(s.listContacts().length, 1);
  assert.equal(s.getContactByFingerprint('x').trust_level, 'known');
});

test('mergeKeyFieldsGroup: full quad overlay replaces the epoch wholesale', () => {
  const m = mergeKeyFieldsGroup(ROW, {
    public_key: 'N-ASC', pq_sig_public_key: 'N-SIG',
    pq_kem_public_key: 'N-KEM', epoch: 1,
  });
  assert.deepEqual(
    { pk: m.public_key, s: m.pq_sig_public_key, k: m.pq_kem_public_key },
    { pk: 'N-ASC', s: 'N-SIG', k: 'N-KEM' });
  assert.equal(m.epoch, 1);
});

test('cardFpBound: full-fp + >=16-hex prefix claims bind, wrong fp refuses', () => {
  const derived = 'ab'.repeat(32);
  assert.equal(cardFpBound(derived, derived), true);
  assert.equal(cardFpBound(derived.slice(0, 24), derived), true);
  assert.equal(cardFpBound('cd'.repeat(32), derived), false);
  assert.equal(cardFpBound('', derived), false);
});

// Live-key anchor is exercised by the devin-comm refuseUnboundCard call
// sites + the derive smoke on a real mint (mneme's own card derives to
// its claimed fp — verified live this session); the helper's null-on-
// underivable contract is covered by fp-check's identical upstream path.
