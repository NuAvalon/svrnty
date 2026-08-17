// import-dedup tests — exact-key auto-merge, living-wins field-union, review-not-silent, idempotency.
// Phones must be valid E.164 (8-15 digits) or normalizeChannel drops them (no dedup key).
// Run: npx tsx --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dedupeContacts } from './import-dedup';
import { livingWinsMerge } from './dedup';
import type { TrustEdge } from '../trust/types';

const edge = (over: Partial<TrustEdge> = {}): TrustEdge => ({
  id: 'e', peer_fingerprint: 'FP', peer_name: 'Existing', peer_email: '', peer_public_key: '',
  contact_info: { phones: [], emails: [] }, trusted: true, trusted_since: null,
  last_interaction: '', decay_days: 730, trust_history: [],
  verification: { method: 'none', verified_at: null },
  mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
  tags: [], notes: '', connection_channels: [], added_at: '', ...over,
});

test('exact-key: incoming sharing a phone auto-merges (not fresh); living name wins; email unions', () => {
  const existing = [edge({ id: 'a', peer_name: 'Grace Hopper', contact_info: { phones: ['+13015550100'], emails: [] } })];
  const incoming: Partial<TrustEdge>[] = [
    { peer_name: 'G. Hopper', contact_info: { phones: ['+13015550100'], emails: ['grace@navy.mil'] } },
  ];
  const plan = dedupeContacts(incoming, existing);
  assert.equal(plan.autoMerge.length, 1);
  assert.equal(plan.fresh.length, 0);
  assert.equal(plan.autoMerge[0].survivor.peer_name, 'Grace Hopper');            // living wins
  assert.deepEqual(plan.autoMerge[0].survivor.contact_info?.emails, ['grace@navy.mil']); // unioned
});

test('living-wins: attested scalar NOT overwritten; living non-empty email wins; phones union', () => {
  const existing = edge({ notes: 'met at conf', peer_email: 'a@x.com', contact_info: { phones: ['+13015550100'], emails: [] } });
  const incoming: Partial<TrustEdge> = { notes: 'stale', peer_email: 'b@x.com', contact_info: { phones: ['+13015550100', '+442071838750'], emails: [] } };
  const m = livingWinsMerge(existing, incoming);
  assert.equal(m.notes, 'met at conf');                                    // attested not overwritten
  assert.equal(m.peer_email, 'a@x.com');                                   // living non-empty wins
  assert.deepEqual(m.contact_info?.phones, ['+13015550100', '+442071838750']); // union
});

test('living-wins: empty living scalar is filled from incoming', () => {
  const m = livingWinsMerge(edge({ notes: '' }), { notes: 'first note' });
  assert.equal(m.notes, 'first note');
});

test('ambiguous: incoming matching >1 existing → review, NEVER a silent merge', () => {
  const existing = [
    edge({ id: 'a', contact_info: { phones: ['+13015550100'], emails: [] } }),
    edge({ id: 'b', contact_info: { phones: [], emails: ['shared@x.com'] } }),
  ];
  const incoming: Partial<TrustEdge>[] = [
    { peer_email: 'shared@x.com', contact_info: { phones: ['+13015550100'], emails: [] } }, // shares phone w/ a, email w/ b
  ];
  const plan = dedupeContacts(incoming, existing);
  assert.equal(plan.review.length, 1);
  assert.equal(plan.autoMerge.length, 0);
  assert.equal(plan.review[0].candidates.length, 2);
});

test('no channel match → fresh (gray) contact', () => {
  const existing = [edge({ contact_info: { phones: ['+13015550100'], emails: [] } })];
  const incoming: Partial<TrustEdge>[] = [{ peer_name: 'Stranger', contact_info: { phones: ['+13015559999'], emails: [] } }];
  const plan = dedupeContacts(incoming, existing);
  assert.equal(plan.fresh.length, 1);
  assert.equal(plan.autoMerge.length, 0);
});

test('idempotent: re-importing the merged survivor yields no new fresh row', () => {
  const existing = [edge({ id: 'a', peer_name: 'Ada', contact_info: { phones: ['+13015550100'], emails: [] } })];
  const incoming: Partial<TrustEdge>[] = [{ peer_name: 'Ada', contact_info: { phones: ['+13015550100'], emails: ['ada@x.com'] } }];
  const first = dedupeContacts(incoming, existing);
  const merged = first.autoMerge.map((m) => m.survivor);
  const second = dedupeContacts(incoming, merged);   // re-import same against merged book
  assert.equal(second.fresh.length, 0);              // no dupe
  assert.equal(second.autoMerge.length, 1);          // re-matches its own channel
});
