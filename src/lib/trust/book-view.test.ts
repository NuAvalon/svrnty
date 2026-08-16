// src/lib/trust/book-view.test.ts
// Run: node --experimental-strip-types --test src/lib/trust/book-view.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildBookView } from './book-view';
import type { ContactState } from './contact-state';
import type { TrustEdge } from './types';

const DAY = 24 * 60 * 60 * 1000;
const now = () => new Date().toISOString();
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString();

function edge(over: Partial<TrustEdge>): TrustEdge {
  return {
    id: 'e1', peer_fingerprint: 'fp', peer_name: 'Test', peer_email: '', peer_public_key: '',
    trusted: false, trusted_since: null, last_interaction: now(),
    decay_days: 730, trust_history: [],
    verification: { method: 'none', verified_at: null },
    mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
    tags: [], notes: '', connection_channels: [], added_at: now(),
    ...over,
  } as TrustEdge;
}

const gray = (over: Partial<TrustEdge> = {}) => edge({ trusted: false, ...over });
const living = (over: Partial<TrustEdge> = {}) => edge({ trusted: true, last_interaction: now(), ...over });
const dim = (over: Partial<TrustEdge> = {}) => edge({ trusted: true, last_interaction: ago(800), decay_days: 730, ...over });

test('partitions living vs resting (gray + dim)', () => {
  const v = buildBookView([
    gray({ id: 'g' }), living({ id: 'l' }), dim({ id: 'd' }),
  ]);
  assert.deepEqual(v.living.map(r => r.edge.id), ['l']);
  assert.deepEqual(v.resting.map(r => r.edge.id).sort(), ['d', 'g']);
  assert.deepEqual(v.living.map(r => r.state), ['living']);
});

test('first render never blooms (empty prevStates)', () => {
  const v = buildBookView([living({ id: 'l' }), dim({ id: 'd' }), gray({ id: 'g' })]);
  assert.deepEqual(v.bloomingIds, []);
  assert.equal(v.living[0].blooming, false);
});

test('bloom fires on gray->living and dim->living only', () => {
  const edges = [living({ id: 'a' }), living({ id: 'b' }), living({ id: 'c' })];
  const prev: Record<string, ContactState> = { a: 'gray', b: 'dim', c: 'living' };
  const v = buildBookView(edges, prev);
  assert.deepEqual(v.bloomingIds.sort(), ['a', 'b']); // c was already living -> steady, no bloom
  const byId = Object.fromEntries(v.living.map(r => [r.edge.id, r.blooming]));
  assert.equal(byId.a, true);
  assert.equal(byId.b, true);
  assert.equal(byId.c, false);
});

test('fading (living->dim) and staying gray never bloom', () => {
  const v = buildBookView(
    [dim({ id: 'faded' }), gray({ id: 'still-gray' })],
    { faded: 'living', 'still-gray': 'gray' },
  );
  assert.deepEqual(v.bloomingIds, []);
});

test('states map round-trips: replaying it yields zero blooms (stable render)', () => {
  const edges = [living({ id: 'l' }), dim({ id: 'd' }), gray({ id: 'g' })];
  const first = buildBookView(edges);            // first paint, some become living
  const second = buildBookView(edges, first.states); // same edges, same states fed back
  assert.deepEqual(second.bloomingIds, []);      // nothing changed -> nothing blooms
});

test('daysUntilDecay: null for gray, number for living/dim (negative when faded)', () => {
  const v = buildBookView([gray({ id: 'g' }), living({ id: 'l' }), dim({ id: 'd' })]);
  const byId = Object.fromEntries([...v.living, ...v.resting].map(r => [r.edge.id, r.daysUntilDecay]));
  assert.equal(byId.g, null);
  assert.equal(typeof byId.l, 'number');
  assert.ok((byId.l as number) > 0);
  assert.equal(typeof byId.d, 'number');
  assert.ok((byId.d as number) < 0); // 800d since contact, 730d window => past decay
});

test('living side is freshest-first; resting side is gray-before-dim', () => {
  const v = buildBookView([
    living({ id: 'older', last_interaction: ago(300) }),
    living({ id: 'fresher', last_interaction: ago(1) }),
    dim({ id: 'd1' }),
    gray({ id: 'g1' }),
  ]);
  assert.deepEqual(v.living.map(r => r.edge.id), ['fresher', 'older']); // more days-until-decay first
  assert.deepEqual(v.resting.map(r => r.edge.id), ['g1', 'd1']);        // gray before dim
});
