// src/lib/trust/contact-state.test.ts
// Run: node --experimental-strip-types --test src/lib/trust/contact-state.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getContactState, isBloomTransition, partitionBook } from './contact-state';
import type { TrustEdge } from './types';

const DAY = 24 * 60 * 60 * 1000;

function edge(over: Partial<TrustEdge>): TrustEdge {
  return {
    id: 'e1', peer_fingerprint: 'fp', peer_name: 'Test', peer_email: '', peer_public_key: '',
    trusted: false, trusted_since: null, last_interaction: new Date().toISOString(),
    decay_days: 730, trust_history: [],
    verification: { method: 'none', verified_at: null },
    mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
    tags: [], notes: '', connection_channels: [], added_at: new Date().toISOString(),
    ...over,
  } as TrustEdge;
}

test('GRAY = not trusted (known, not Trusted)', () => {
  assert.equal(getContactState(edge({ trusted: false })), 'gray');
});

test('LIVING = trusted + fresh (within decay window)', () => {
  assert.equal(getContactState(edge({ trusted: true, last_interaction: new Date().toISOString(), decay_days: 730 })), 'living');
});

test('DIM = trusted + decayed (past decay window)', () => {
  const stale = new Date(Date.now() - 800 * DAY).toISOString(); // 800d > 730d decay
  assert.equal(getContactState(edge({ trusted: true, last_interaction: stale, decay_days: 730 })), 'dim');
});

test('bloom fires GRAY/DIM -> LIVING, not otherwise', () => {
  assert.equal(isBloomTransition('gray', 'living'), true);
  assert.equal(isBloomTransition('dim', 'living'), true);
  assert.equal(isBloomTransition('living', 'living'), false); // steady state
  assert.equal(isBloomTransition(undefined, 'living'), false); // first render never blooms
  assert.equal(isBloomTransition('gray', 'dim'), false);       // fading is not a bloom
});

test('partitionBook splits living vs resting (gray+dim)', () => {
  const now = new Date().toISOString();
  const stale = new Date(Date.now() - 800 * DAY).toISOString();
  const edges = [
    edge({ id: 'g', trusted: false }),
    edge({ id: 'l', trusted: true, last_interaction: now }),
    edge({ id: 'd', trusted: true, last_interaction: stale }),
  ];
  const { living, resting } = partitionBook(edges);
  assert.deepEqual(living.map(e => e.id), ['l']);
  assert.deepEqual(resting.map(e => e.id).sort(), ['d', 'g']);
});
