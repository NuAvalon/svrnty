// Run: npx tsx --test src/lib/trust/peer-trust-chords.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  peerTrustNeighbors,
  witnessedPeerChords,
  witnessedPeerKnowChords,
  witnessedPeerTrustChords,
} from './peer-trust-chords';
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

/** Trusted + reciprocal + they_trust, but NO per-person open_visibility — relies on the global default (#255). */
function mutualNoVis(fp: string, theyTrust: string[], extra: Partial<TrustEdge> = {}): TrustEdge {
  return edge(fp, {
    trusted: true,
    they_trust: theyTrust,
    mutual: { they_trust_me: true, last_sync: new Date().toISOString(), reciprocal: true },
    ...extra,
  });
}

const TRUST_GLOBAL_ON = { known: false, trusted: true } as const;
const KNOWN_GLOBAL_ON = { known: true, trusted: false } as const;
const ALL_OFF = { known: false, trusted: false } as const;

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
    } as unknown as TrustEdge),
    openMutual('joe', [], {
      they_trust: undefined,
      peer_mutual: [{ peer_fingerprint: 'sally' }],
    } as unknown as TrustEdge),
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

test('Sally↔Joe Know chord lights when both disclosed each other and opened vis', () => {
  const contacts = [
    edge('sally', {
      open_visibility: true,
      disclosed_circle: ['joe'],
    }),
    edge('joe', {
      open_visibility: true,
      disclosed_circle: ['sally'],
    }),
    edge('other', {
      open_visibility: true,
      disclosed_circle: ['sally'],
    }),
  ];
  const chords = witnessedPeerKnowChords(contacts);
  assert.equal(chords.length, 1);
  assert.equal(chords[0].a, 'joe');
  assert.equal(chords[0].b, 'sally');
});

test('Know chord fail-closed: one-way disclosed_circle or missing vis or tags-only', () => {
  assert.equal(
    witnessedPeerKnowChords([
      edge('sally', { open_visibility: true, disclosed_circle: ['joe'] }),
      edge('joe', { open_visibility: true, disclosed_circle: [] }),
    ]).length,
    0,
  );
  assert.equal(
    witnessedPeerKnowChords([
      edge('sally', { open_visibility: true, disclosed_circle: ['joe'] }),
      edge('joe', { open_visibility: false, disclosed_circle: ['sally'] }),
    ]).length,
    0,
  );
  assert.equal(
    witnessedPeerKnowChords([
      edge('sally', { open_visibility: true, tags: ['crew'] }),
      edge('joe', { open_visibility: true, tags: ['crew'] }),
    ]).length,
    0,
    'tags must never invent a Know bond',
  );
  assert.equal(
    witnessedPeerKnowChords([
      edge('sally', {
        open_visibility: true,
        metadata: { mutual_contacts: ['joe'] },
      } as unknown as TrustEdge),
      edge('joe', {
        open_visibility: true,
        metadata: { mutual_contacts: ['sally'] },
      } as unknown as TrustEdge),
    ]).length,
    0,
    'card-exchange mutual_contacts is not disclosed_circle',
  );
});

test('pending Gate/intro is not a Know chord', () => {
  assert.equal(
    witnessedPeerKnowChords([
      edge('sally', {
        open_visibility: true,
        disclosed_circle: ['frank'],
        connection_status: 'accepted',
      }),
      edge('frank', {
        open_visibility: true,
        disclosed_circle: ['sally'],
        connection_status: 'pending',
      }),
    ]).length,
    0,
  );
});

test('Trust chord supersedes Know for the same pair', () => {
  const contacts = [
    openMutual('sally', ['joe'], { disclosed_circle: ['joe'] }),
    openMutual('joe', ['sally'], { disclosed_circle: ['sally'] }),
    edge('claude', {
      open_visibility: true,
      disclosed_circle: ['hedy'],
    }),
    edge('hedy', {
      open_visibility: true,
      disclosed_circle: ['claude'],
    }),
  ];
  const layered = witnessedPeerChords(contacts);
  assert.equal(layered.length, 2);
  const sallyJoe = layered.find((c) => c.a === 'joe' && c.b === 'sally');
  const claudeHedy = layered.find((c) => c.a === 'claude' && c.b === 'hedy');
  assert.equal(sallyJoe?.layer, 'trust');
  assert.equal(claudeHedy?.layer, 'know');
});

// ── #255 consent toggles: global default + per-person override, per-tier ──────────

test('default-off baseline: no per-person vis + no globals → no trust chord (opt-in)', () => {
  const contacts = [mutualNoVis('sally', ['joe']), mutualNoVis('joe', ['sally'])];
  assert.equal(witnessedPeerTrustChords(contacts).length, 0);
  assert.equal(witnessedPeerTrustChords(contacts, ALL_OFF).length, 0);
});

test('trusted-tier GLOBAL default ON draws the chord without any per-person open_vis (neg-control)', () => {
  const contacts = [mutualNoVis('sally', ['joe']), mutualNoVis('joe', ['sally'])];
  assert.equal(witnessedPeerTrustChords(contacts, TRUST_GLOBAL_ON).length, 1);
});

test('per-person open_visibility:false WINS over the trusted global default ON', () => {
  const contacts = [
    mutualNoVis('sally', ['joe']),
    mutualNoVis('joe', ['sally'], { open_visibility: false }),
  ];
  assert.equal(witnessedPeerTrustChords(contacts, TRUST_GLOBAL_ON).length, 0);
});

test('revoke: flipping the global default OFF drops the chord on the next query (no materialized edge)', () => {
  const contacts = [mutualNoVis('sally', ['joe']), mutualNoVis('joe', ['sally'])];
  assert.equal(witnessedPeerTrustChords(contacts, TRUST_GLOBAL_ON).length, 1);
  assert.equal(witnessedPeerTrustChords(contacts, ALL_OFF).length, 0);
});

test('known-tier GLOBAL default ON draws the Know chord without per-person vis', () => {
  const contacts = [
    edge('sally', { disclosed_circle: ['joe'] }),
    edge('joe', { disclosed_circle: ['sally'] }),
  ];
  assert.equal(witnessedPeerKnowChords(contacts).length, 0);
  assert.equal(witnessedPeerKnowChords(contacts, KNOWN_GLOBAL_ON).length, 1);
});

test('per-person known_visibility overrides the known global default (both directions)', () => {
  // known_visibility:true draws even with the global default OFF
  assert.equal(
    witnessedPeerKnowChords([
      edge('sally', { disclosed_circle: ['joe'], metadata: { share_settings: { known_visibility: true } } } as unknown as TrustEdge),
      edge('joe', { disclosed_circle: ['sally'], metadata: { share_settings: { known_visibility: true } } } as unknown as TrustEdge),
    ]).length,
    1,
  );
  // known_visibility:false blocks even with the global known default ON
  assert.equal(
    witnessedPeerKnowChords(
      [
        edge('sally', { disclosed_circle: ['joe'] }),
        edge('joe', { disclosed_circle: ['sally'], metadata: { share_settings: { known_visibility: false } } } as unknown as TrustEdge),
      ],
      KNOWN_GLOBAL_ON,
    ).length,
    0,
  );
});

test('known_visibility SURVIVES the #111 open_visibility severance (sibling field, un-swept)', () => {
  // Models a post-sweep known contact: open_visibility cleared to false, but known_visibility:true persists.
  const contacts = [
    edge('sally', {
      open_visibility: false,
      disclosed_circle: ['joe'],
      metadata: { share_settings: { known_visibility: true } },
    } as unknown as TrustEdge),
    edge('joe', {
      open_visibility: false,
      disclosed_circle: ['sally'],
      metadata: { share_settings: { known_visibility: true } },
    } as unknown as TrustEdge),
  ];
  assert.equal(witnessedPeerKnowChords(contacts).length, 1);
});

test('Flint severance gate: a BLOCKED peer never rides the trust mesh (blocked+trusted+open_vis → no chord)', () => {
  const contacts = [
    openMutual('sally', ['joe']),
    openMutual('joe', ['sally'], { blocked: true }),
  ];
  assert.equal(witnessedPeerTrustChords(contacts).length, 0);
  // and not via the global default either
  assert.equal(
    witnessedPeerTrustChords(
      [mutualNoVis('sally', ['joe']), mutualNoVis('joe', ['sally'], { blocked: true })],
      TRUST_GLOBAL_ON,
    ).length,
    0,
  );
});

test('Flint severance gate: a BLOCKED peer never rides the known mesh', () => {
  const contacts = [
    edge('sally', { open_visibility: true, disclosed_circle: ['joe'] }),
    edge('joe', { open_visibility: true, disclosed_circle: ['sally'], blocked: true }),
  ];
  assert.equal(witnessedPeerKnowChords(contacts).length, 0);
});

test('metadata.blocked (canonical admitContact dual) also excludes from the mesh', () => {
  const contacts = [
    openMutual('sally', ['joe']),
    openMutual('joe', ['sally'], { metadata: { blocked: true } } as unknown as TrustEdge),
  ];
  assert.equal(witnessedPeerTrustChords(contacts).length, 0);
});

test('#255: global-known ON does NOT bypass the peer bidirectional consent gate (one-way disclosed → no chord)', () => {
  // Owner consents to both via the global known default, but joe never disclosed sally.
  // The 3-party "nothing mutual unless all consent" invariant must still hold: no chord.
  const contacts = [
    edge('sally', { disclosed_circle: ['joe'] }),
    edge('joe', { disclosed_circle: [] }),
  ];
  assert.equal(witnessedPeerKnowChords(contacts, KNOWN_GLOBAL_ON).length, 0);
});

test('#255 scope boundary: peer-trust-chords does NOT import allowed-sync (discovery) — structural guard', () => {
  // The global-visibility default must be unreachable from the allowed_senders/discovery path.
  // Lock it structurally so a future refactor cannot silently add the edge (Flint #171527).
  const src = readFileSync(new URL('./peer-trust-chords.ts', import.meta.url), 'utf8');
  // match an actual import/re-export (`from '…allowed-sync…'`), not a prose mention in comments
  assert.equal(/from\s+['"][^'"]*allowed-sync/.test(src), false, 'global visibility must never reach discovery/allowed_senders');
});
