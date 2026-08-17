// import-apply tests — plan→ops mapping + the never-silent-merge fail-safe on review rows.
// Run: npx tsx --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyImportPlan } from './import-apply';
import { dedupeContacts, type DedupPlan } from './import-dedup';
import type { TrustEdge } from '../trust/types';

const edge = (over: Partial<TrustEdge> = {}): TrustEdge => ({
  id: 'e', peer_fingerprint: 'FP', peer_name: 'X', peer_email: '', peer_public_key: '',
  contact_info: { phones: [], emails: [] }, trusted: true, trusted_since: null,
  last_interaction: '', decay_days: 730, trust_history: [],
  verification: { method: 'none', verified_at: null },
  mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
  tags: [], notes: '', connection_channels: [], added_at: '', ...over,
});

test('autoMerge → update(existing.id, survivor); fresh → add', () => {
  const plan: DedupPlan = {
    autoMerge: [{ survivor: edge({ id: 'a', peer_name: 'Ada' }), existing: edge({ id: 'a' }), incoming: { peer_name: 'Ada' } }],
    review: [],
    fresh: [{ peer_name: 'New' }],
  };
  const ops = applyImportPlan(plan);
  assert.equal(ops.updates.length, 1);
  assert.equal(ops.updates[0].id, 'a');
  assert.equal(ops.updates[0].survivor.peer_name, 'Ada');
  assert.deepEqual(ops.adds.map((a) => a.peer_name), ['New']);
});

test('review + merge choice → update into the chosen candidate (livingWinsMerge)', () => {
  const cand = edge({ id: 'c1', peer_name: 'Grace', contact_info: { phones: ['+13015550100'], emails: [] } });
  const plan: DedupPlan = {
    autoMerge: [], fresh: [],
    review: [{ incoming: { peer_name: 'G.', contact_info: { phones: [], emails: ['grace@navy.mil'] } }, candidates: [cand, edge({ id: 'c2' })] }],
  };
  const ops = applyImportPlan(plan, [{ action: 'merge', candidateId: 'c1' }]);
  assert.equal(ops.updates.length, 1);
  assert.equal(ops.updates[0].id, 'c1');
  assert.equal(ops.updates[0].survivor.peer_name, 'Grace');                          // living wins
  assert.deepEqual(ops.updates[0].survivor.contact_info?.emails, ['grace@navy.mil']); // unioned
  assert.equal(ops.adds.length, 0);
});

test('review + skip → add as fresh (not merged)', () => {
  const plan: DedupPlan = {
    autoMerge: [], fresh: [],
    review: [{ incoming: { peer_name: 'Maybe' }, candidates: [edge({ id: 'c1' })] }],
  };
  const ops = applyImportPlan(plan, [{ action: 'skip' }]);
  assert.equal(ops.updates.length, 0);
  assert.deepEqual(ops.adds.map((a) => a.peer_name), ['Maybe']);
});

test('never-silent-merge: review row with NO choice falls back to fresh (not merged)', () => {
  const plan: DedupPlan = {
    autoMerge: [], fresh: [],
    review: [{ incoming: { peer_name: 'Ambiguous' }, candidates: [edge({ id: 'c1' }), edge({ id: 'c2' })] }],
  };
  const ops = applyImportPlan(plan, []);   // no choices provided
  assert.equal(ops.updates.length, 0);     // NOT silently merged
  assert.equal(ops.adds.length, 1);
});

test('fail-safe: invalid candidateId → fresh (never guess which to merge)', () => {
  const plan: DedupPlan = {
    autoMerge: [], fresh: [],
    review: [{ incoming: { peer_name: 'Z' }, candidates: [edge({ id: 'c1' })] }],
  };
  const ops = applyImportPlan(plan, [{ action: 'merge', candidateId: 'nope' }]);
  assert.equal(ops.updates.length, 0);
  assert.equal(ops.adds.length, 1);
});

test('integration: dedupeContacts → applyImportPlan end-to-end', () => {
  const existing = [edge({ id: 'a', peer_name: 'Grace Hopper', contact_info: { phones: ['+13015550100'], emails: [] } })];
  const incoming: Partial<TrustEdge>[] = [
    { peer_name: 'G. Hopper', contact_info: { phones: ['+13015550100'], emails: ['grace@navy.mil'] } }, // → auto-merge
    { peer_name: 'Stranger', contact_info: { phones: ['+13015559999'], emails: [] } },                  // → fresh
  ];
  const ops = applyImportPlan(dedupeContacts(incoming, existing));
  assert.equal(ops.updates.length, 1);
  assert.equal(ops.updates[0].id, 'a');
  assert.deepEqual(ops.adds.map((a) => a.peer_name), ['Stranger']);
});
