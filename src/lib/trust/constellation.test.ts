import { test } from 'node:test';
import assert from 'node:assert/strict';
import { constellationCaption, focusConstellation } from './constellation';
import type { TrustEdge } from './types';

function edge(fp: string, tags: string[], extra: Partial<TrustEdge> = {}): TrustEdge {
  return {
    id: fp,
    peer_fingerprint: fp,
    peer_name: fp,
    peer_email: '',
    peer_public_key: '',
    trusted: false,
    trusted_since: null,
    last_interaction: new Date().toISOString(),
    decay_days: 730,
    trust_history: [],
    verification: { method: 'none', verified_at: null },
    mutual: { they_trust_me: null, last_sync: null, reciprocal: false },
    tags,
    notes: '',
    connection_channels: [],
    added_at: new Date().toISOString(),
    ...extra,
  };
}

test('shared owner tags light a constellation — not inferred trust', () => {
  const contacts = [
    edge('hub', ['crew', 'work']),
    edge('a', ['crew']),
    edge('b', ['work']),
    edge('c', ['other']),
  ];
  const c = focusConstellation('hub', contacts);
  assert.equal(c.members.size, 2);
  assert.ok(c.members.get('a')?.reasons.includes('shared-group'));
  assert.ok(c.members.get('b')?.reasons.includes('shared-group'));
  assert.equal(c.members.has('c'), false);
});

test('disclosed_circle only includes people already in the book', () => {
  const contacts = [
    edge('hub', [], {
      disclosed_circle: ['a', 'ghost'],
    } as TrustEdge),
    edge('a', []),
    edge('b', []),
  ];
  const c = focusConstellation('hub', contacts);
  assert.ok(c.members.get('a')?.reasons.includes('disclosed-circle'));
  assert.equal(c.members.has('ghost'), false);
  assert.equal(c.members.has('b'), false);
});

const openMutual = {
  trusted: true,
  open_visibility: true,
  mutual: { they_trust_me: true as const, last_sync: null, reciprocal: true },
};

test('they-trust lights only under open-visibility reciprocal + they_trust both ways', () => {
  const contacts = [
    edge('hub', [], { ...openMutual, they_trust: ['a'] }),
    edge('a', [], { ...openMutual, they_trust: ['hub'] }),
    edge('b', [], { ...openMutual, they_trust: ['hub'] }),
    edge('c', [], {
      trusted: true,
      they_trust: ['hub'],
      mutual: { they_trust_me: true, last_sync: null, reciprocal: true },
    }),
  ];
  const c = focusConstellation('hub', contacts);
  assert.ok(c.members.get('a')?.reasons.includes('they-trust'));
  assert.equal(c.members.has('b'), false, 'hub did not list b');
  assert.equal(c.members.has('c'), false, 'c did not opt into open visibility');
  const cap = constellationCaption(focusConstellation('hub', contacts), true);
  assert.ok(cap.includes('open-visibility peer trust'));
  assert.ok(!/\d+/.test(cap), cap);
});

test('they-trust is not invented from a shared owner tag', () => {
  const contacts = [
    edge('hub', ['crew'], openMutual),
    edge('a', ['crew'], openMutual),
  ];
  const c = focusConstellation('hub', contacts);
  assert.ok(c.members.get('a')?.reasons.includes('shared-group'));
  assert.equal(c.members.get('a')?.reasons.includes('they-trust'), false);
});

test('caption stays qualitative — no mutual-friend score', () => {
  const contacts = [edge('hub', ['crew']), edge('a', ['crew'])];
  const cap = constellationCaption(focusConstellation('hub', contacts), true);
  assert.ok(cap.includes('groups you named'));
  assert.ok(!/\d+/.test(cap), cap);
});
