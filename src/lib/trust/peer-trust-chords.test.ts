// Run: npx tsx --test src/lib/trust/peer-trust-chords.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { peerTrustNeighbors, witnessedPeerTrustChords } from './peer-trust-chords';
import type { TrustEdge } from './types';

function edge(fp: string, extra: Partial<TrustEdge> = {}): TrustEdge {
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
    tags: [],
    notes: '',
    connection_channels: [],
    added_at: new Date().toISOString(),
    ...extra,
  };
}

function openMutual(fp: string, theyTrust: string[], extra: Partial<TrustEdge> = {}): TrustEdge {
  return edge(fp, {
    trusted: true,
    open_visibility: true,
    they_trust: theyTrust,
    mutual: { they_trust_me: true, last_sync: new Date().toISOString(), reciprocal: true },
    ...extra,
  });
}

test('Sally↔Joe lights when I trust both, they trust me, open vis, they_trust both ways', () => {
  const contacts = [
    openMutual('sally', ['joe']),
    openMutual('joe', ['sally']),
    openMutual('other', []),
  ];
  const chords = witnessedPeerTrustChords(contacts);
  assert.equal(chords.length, 1);
  assert.equal(chords[0].a, 'joe');
  assert.equal(chords[0].b, 'sally');
  assert.deepEqual([...peerTrustNeighbors('sally', contacts)].sort(), ['joe']);
});

test('missing open visibility on one peer — no chord', () => {
  const contacts = [
    openMutual('sally', ['joe']),
    openMutual('joe', ['sally'], { open_visibility: false }),
  ];
  assert.equal(witnessedPeerTrustChords(contacts).length, 0);
});

test('non-reciprocal (they do not trust me yet) — no chord', () => {
  const contacts = [
    openMutual('sally', ['joe']),
    edge('joe', {
      trusted: true,
      open_visibility: true,
      they_trust: ['sally'],
      mutual: { they_trust_me: false, last_sync: null, reciprocal: false },
    }),
  ];
  assert.equal(witnessedPeerTrustChords(contacts).length, 0);
});

test('one-way they_trust — fail closed', () => {
  const contacts = [
    openMutual('sally', ['joe']),
    openMutual('joe', []),
  ];
  assert.equal(witnessedPeerTrustChords(contacts).length, 0);
});

test('shared owner tags without they_trust is not a bond', () => {
  const contacts = [
    openMutual('sally', [], { tags: ['crew'] }),
    openMutual('joe', [], { tags: ['crew'] }),
  ];
  assert.equal(witnessedPeerTrustChords(contacts).length, 0);
});

test('peer_mutual is an allowed they_trust stand-in (fleet shape)', () => {
  const contacts = [
    openMutual('sally', [], {
      they_trust: undefined,
      peer_mutual: [{ peer_fingerprint: 'joe' }],
    } as TrustEdge),
    openMutual('joe', [], {
      they_trust: undefined,
      peer_mutual: [{ peer_fingerprint: 'sally' }],
    } as TrustEdge),
  ];
  assert.equal(witnessedPeerTrustChords(contacts).length, 1);
});

test('untrusted contact listed in they_trust — no chord', () => {
  const contacts = [
    openMutual('sally', ['joe']),
    edge('joe', {
      trusted: false,
      open_visibility: true,
      they_trust: ['sally'],
      mutual: { they_trust_me: true, last_sync: null, reciprocal: true },
    }),
  ];
  assert.equal(witnessedPeerTrustChords(contacts).length, 0);
});
