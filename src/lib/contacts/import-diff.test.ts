// import-diff tests — per-field merge provenance (chaos#32 B). The load-bearing invariant: `added`
// must equal EXACTLY what livingWinsMerge writes that wasn't there — including UNNORMALIZABLE channels
// (raw union), the injection vector the count-only UI hid. Run: npx tsx --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mergeProvenance } from './import-diff';
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

const vals = (cs: { type: string; value: string }[]) => cs.map((c) => `${c.type}:${c.value}`).sort();

test('chaos#32 injection: shares ONE email with a trusted contact → adds attacker phone + signal handle, both VISIBLE', () => {
  const target = edge({
    peer_name: 'Grace (trusted)', peer_email: 'grace@navy.mil',
    contact_info: { phones: ['+13015550100'], emails: [] },
  });
  const incoming: Partial<TrustEdge> = {
    peer_email: 'grace@navy.mil', // the ONE shared channel that makes it match
    contact_info: { phones: ['+19998887777'], emails: [], handles: { signal: '@attacker' } },
  };
  const p = mergeProvenance(target, incoming);
  assert.deepEqual(vals(p.matchedOn), ['email:grace@navy.mil']);
  assert.deepEqual(vals(p.added), ['phone:+19998887777', 'signal:@attacker']); // both injected channels shown
});

test('added is TRUTHFUL to livingWinsMerge, including an UNNORMALIZABLE injected channel (raw union)', () => {
  const target = edge({ contact_info: { phones: ['+13015550100'], emails: [] } });
  const incoming: Partial<TrustEdge> = {
    // "555-1234" has no country code → normalizeChannel drops it (no dedup key), but livingWinsMerge
    // still unions it raw. The diff MUST surface it — else a bare-phone injection is silent.
    contact_info: { phones: ['+13015550100', '555-1234'], emails: [] },
  };
  const p = mergeProvenance(target, incoming);
  const survivor = livingWinsMerge(target, incoming);
  for (const c of p.added) {
    // every reported add is genuinely in the survivor and not in the target
    assert.ok(survivor.contact_info!.phones!.includes(c.value));
    assert.ok(!target.contact_info!.phones!.includes(c.value));
  }
  assert.deepEqual(vals(p.added), ['phone:555-1234']);            // the unnormalizable injection shows
  assert.deepEqual(p.matchedOn.map((c) => c.value), ['+13015550100']); // matched on the normalizable shared phone
});

test('idempotent re-import: nothing new → added is empty (no false alarm on the benign re-import path)', () => {
  const target = edge({ peer_name: 'Ada', contact_info: { phones: ['+13015550100'], emails: ['ada@x.com'] } });
  const incoming: Partial<TrustEdge> = { peer_name: 'Ada', contact_info: { phones: ['+13015550100'], emails: ['ada@x.com'] } };
  const p = mergeProvenance(target, incoming);
  assert.equal(p.added.length, 0);
  assert.ok(p.matchedOn.length >= 1);
});

test('per-platform living wins: a handle the target already holds is NOT added; only a new platform is', () => {
  const target = edge({ contact_info: { phones: ['+13015550100'], emails: [], handles: { signal: '@grace' } } });
  const incoming: Partial<TrustEdge> = {
    contact_info: { phones: ['+13015550100'], emails: [], handles: { signal: '@not-grace', telegram: '@grace-tg' } },
  };
  const p = mergeProvenance(target, incoming);
  // signal already on target → living wins → attacker's @not-grace is NOT written, so NOT added;
  // only the genuinely new platform (telegram) is added.
  assert.deepEqual(vals(p.added), ['telegram:@grace-tg']);
});

test('empty scalar fill: target has no peer_email → the incoming email is a genuine added channel', () => {
  const target = edge({ peer_email: '', contact_info: { phones: ['+13015550100'], emails: [] } });
  const incoming: Partial<TrustEdge> = { peer_email: 'new@x.com', contact_info: { phones: ['+13015550100'], emails: [] } };
  const p = mergeProvenance(target, incoming);
  assert.deepEqual(vals(p.added), ['email:new@x.com']);
});

test('order-independent + deterministic: same inputs → identical result', () => {
  const target = edge({ contact_info: { phones: ['+13015550100'], emails: ['a@x.com'] } });
  const incoming: Partial<TrustEdge> = { contact_info: { phones: ['+13015550100', '+442071838750'], emails: ['b@x.com'] } };
  const p1 = mergeProvenance(target, incoming);
  const p2 = mergeProvenance(target, incoming);
  assert.deepEqual(p1, p2);
  assert.deepEqual(vals(p1.added), ['email:b@x.com', 'phone:+442071838750']);
});
