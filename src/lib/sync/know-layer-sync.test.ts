// src/lib/sync/know-layer-sync.test.ts
// The KNOW-layer PSI overlay deps-impl + trigger (#4). Proves the privacy contract with an injected
// store + an injected syncMutualTrust spy — IndexedDB-free, satellite-free.
//
// Run: PATH=/home/alpha/.nvm/versions/node/v22.22.1/bin:$PATH \
//        node --import tsx --test src/lib/sync/know-layer-sync.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { ContactRecord } from '@/lib/identity/client-store';
import type { OrchestratorDeps, PSISyncOptions } from '@/lib/trust/mutual-trust-sync';
import {
  buildKnowOverlayDeps,
  runKnowLayerSyncTick,
  startKnowLayerSync,
  type KnowOverlayStore,
  type SyncMutualTrustFn,
} from './know-layer-sync';

const OWNER = 'owner-fp';

// A minimal ContactRecord with sane defaults; override per test.
function rec(partial: Partial<ContactRecord>): ContactRecord {
  return {
    id: partial.id ?? `id-${partial.fingerprint ?? Math.random()}`,
    fingerprint: partial.fingerprint ?? 'fp',
    name: partial.name ?? 'Someone',
    email: partial.email ?? '',
    public_key: partial.public_key ?? 'pk',
    trust_level: partial.trust_level ?? 'known',
    added_at: partial.added_at ?? new Date().toISOString(),
    ...partial,
  } as ContactRecord;
}

// An in-memory store seam that records every updateContact write.
function fakeStore(contacts: ContactRecord[]): {
  store: KnowOverlayStore;
  writes: Array<{ id: string; updates: Partial<ContactRecord> }>;
} {
  const writes: Array<{ id: string; updates: Partial<ContactRecord> }> = [];
  return {
    writes,
    store: {
      getAllContacts: async () => contacts,
      updateContact: async (id, updates) => {
        writes.push({ id, updates });
      },
    },
  };
}

const DUMMY_OPTIONS: PSISyncOptions = {
  satelliteUrl: 'https://satellite.test',
  myFingerprint: OWNER,
  signFn: () => new Uint8Array(64),
};

// A syncMutualTrust spy that records the layer arg and returns an empty result.
function spySync(): { fn: SyncMutualTrustFn; calls: Array<'know' | 'trust' | undefined> } {
  const calls: Array<'know' | 'trust' | undefined> = [];
  const fn = (async (_deps: OrchestratorDeps, _opts: PSISyncOptions, layer?: 'know' | 'trust') => {
    calls.push(layer);
    return { responded: [], initiated: [], errors: [] };
  }) as unknown as SyncMutualTrustFn;
  return { fn, calls };
}

// ── C1 — the trigger MUST pass layer === 'know' explicitly (do NOT rely on the 'trust' default) ────

test('C1: runKnowLayerSyncTick calls syncMutualTrust with layer "know" explicitly', async () => {
  const { fn, calls } = spySync();
  const deps = buildKnowOverlayDeps(OWNER, fakeStore([]).store);
  await runKnowLayerSyncTick(deps, DUMMY_OPTIONS, fn);
  assert.deepEqual(calls, ['know']); // literal 'know' — not undefined, not 'trust'
});

test('C1: startKnowLayerSync immediate tick passes layer "know" explicitly', async () => {
  const { fn, calls } = spySync();
  const { store } = fakeStore([]);
  const handle = startKnowLayerSync(
    { identity: { fingerprint: OWNER } },
    DUMMY_OPTIONS,
    { store, syncFn: fn, intervalMs: 10_000 }, // long interval → only the immediate tick fires
  );
  await new Promise((r) => setTimeout(r, 20));
  handle.stop();
  assert.equal(calls.length >= 1, true, 'immediate tick fired');
  assert.equal(calls[0], 'know');
  assert.equal(calls.includes('trust'), false);
  assert.equal(calls.includes(undefined), false);
});

test('trigger is inert (no sync) when the identity is locked / absent — fail-soft', async () => {
  const { fn, calls } = spySync();
  const { store } = fakeStore([]);
  const handle = startKnowLayerSync(null, DUMMY_OPTIONS, { store, syncFn: fn, intervalMs: 10_000 });
  await new Promise((r) => setTimeout(r, 20));
  handle.stop();
  assert.deepEqual(calls, []); // no owner fingerprint ⇒ no sync
});

// ── applyMutualResult — write disclosed ∩ book, never more ─────────────────────────────────────────

test('applyMutualResult writes disclosed_circle = disclosed ∩ book (drops non-book, dedups, never more)', async () => {
  const contacts = [
    rec({ id: 'p1', fingerprint: 'peer-1' }),
    rec({ id: 'a', fingerprint: 'contact-a' }),
    rec({ id: 'b', fingerprint: 'contact-b' }),
    rec({ id: 'c', fingerprint: 'contact-c' }),
  ];
  const { store, writes } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);

  // Apollo's result includes an in-book pair, a duplicate, and a fp NOT in the book.
  await deps.applyMutualResult('peer-1', 'know', [
    'contact-a',
    'contact-b',
    'contact-a', // dup
    'contact-ZZZ', // not in book — MUST be dropped
  ]);

  assert.equal(writes.length, 1);
  assert.equal(writes[0].id, 'p1'); // written onto the peer contact
  const dc = writes[0].updates.disclosed_circle as string[];
  assert.deepEqual([...dc].sort(), ['contact-a', 'contact-b']); // ∩ book, de-duplicated, nothing extra
  // Only disclosed_circle was written — no they_trust, no wider field set.
  assert.deepEqual(Object.keys(writes[0].updates), ['disclosed_circle']);
});

test('applyMutualResult writes they_trust (∩ book) for the trust layer', async () => {
  const contacts = [rec({ id: 'p1', fingerprint: 'peer-1' }), rec({ id: 'a', fingerprint: 'contact-a' })];
  const { store, writes } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);

  await deps.applyMutualResult('peer-1', 'trust', ['contact-a', 'nope']);

  assert.equal(writes.length, 1);
  assert.deepEqual(writes[0].updates.they_trust, ['contact-a']);
  assert.deepEqual(Object.keys(writes[0].updates), ['they_trust']);
});

test('applyMutualResult with an empty result clears to [] (hard-revoke shrink)', async () => {
  const contacts = [rec({ id: 'p1', fingerprint: 'peer-1' })];
  const { store, writes } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);

  await deps.applyMutualResult('peer-1', 'know', []);

  assert.equal(writes.length, 1);
  assert.deepEqual(writes[0].updates.disclosed_circle, []);
});

test('applyMutualResult fail-closes (no write) on malformed input / unknown peer / bad layer', async () => {
  const contacts = [rec({ id: 'p1', fingerprint: 'peer-1' }), rec({ id: 'a', fingerprint: 'contact-a' })];
  const { store, writes } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);

  // non-array disclosed
  await assert.rejects(() =>
    deps.applyMutualResult('peer-1', 'know', 'contact-a' as unknown as string[]),
  );
  // unknown peer (not in the book)
  await assert.rejects(() => deps.applyMutualResult('ghost', 'know', ['contact-a']));
  // bad layer
  await assert.rejects(() =>
    deps.applyMutualResult('peer-1', 'gossip' as unknown as 'know', ['contact-a']),
  );
  // empty / missing peer fingerprint
  await assert.rejects(() => deps.applyMutualResult('', 'know', ['contact-a']));

  assert.deepEqual(writes, []); // nothing persisted on any fail-closed path
});

// ── getKnownPeers — the open_visibility SUBSET; empty ⇒ fail-closed ─────────────────────────────────

test('getKnownPeers returns only the open_visibility subset (with real fingerprints)', async () => {
  const contacts = [
    rec({ id: 'p1', fingerprint: 'peer-open-1', open_visibility: true }),
    rec({ id: 'p2', fingerprint: 'peer-open-2', metadata: { share_settings: { open_visibility: true } } }),
    rec({ id: 'p3', fingerprint: 'peer-closed', open_visibility: false }),
    rec({ id: 'p4', fingerprint: 'peer-default' }), // no consent field ⇒ closed
    // keyless / gray contact that somehow carries a consent flag — must NOT leak (no real fingerprint)
    rec({ id: 'p5', fingerprint: '', open_visibility: true }),
  ];
  const { store } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);

  const known = await deps.getKnownPeers();
  const fps = known.map((p) => p.fingerprint).sort();
  assert.deepEqual(fps, ['peer-open-1', 'peer-open-2']); // both consent shapes, no closed, no keyless
});

test('getKnownPeers is empty when no contact is open-visible (fail-closed)', async () => {
  const contacts = [
    rec({ id: 'p1', fingerprint: 'peer-1' }),
    rec({ id: 'p2', fingerprint: 'peer-2', open_visibility: false }),
  ];
  const { store } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);

  assert.deepEqual(await deps.getKnownPeers(), []); // no consent ⇒ no participation
});

// ── getTrustedPeers — trusted, non-decayed (the required TRUST-layer / staleness-scheduler source) ──

test('getTrustedPeers returns the trusted, non-decayed subset', async () => {
  const now = new Date().toISOString();
  const old = new Date(Date.now() - 1000 * 24 * 60 * 60 * 1000).toISOString(); // 1000 days ago
  const contacts = [
    rec({ id: 't1', fingerprint: 'trusted-fresh', trust_level: 'trusted', last_interaction: now }),
    rec({ id: 'k1', fingerprint: 'known-only', trust_level: 'known' }),
    // trusted but past its 730-day decay window ⇒ excluded
    rec({
      id: 'd1',
      fingerprint: 'trusted-decayed',
      trusted: true,
      trusted_since: old,
      last_interaction: old,
      decay_days: 730,
    } as Partial<ContactRecord>),
  ];
  const { store } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);

  const trusted = (await deps.getTrustedPeers()).map((p) => p.fingerprint);
  assert.deepEqual(trusted, ['trusted-fresh']);
});

test('NEGATIVE: PSI peer list is fingerprint+lastSync only — no tags/blocked/group labels', async () => {
  const contacts = [
    rec({
      id: 'p1',
      fingerprint: 'peer-open-1',
      open_visibility: true,
      tags: ['family', 'secret-group'],
      blocked: true,
      metadata: { tags: ['family'], blocked: true, notes: 'stay off the wire' },
    } as Partial<ContactRecord>),
  ];
  const { store } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);
  const known = await deps.getKnownPeers();
  assert.equal(known.length, 1);
  assert.deepEqual(Object.keys(known[0]).sort(), ['fingerprint', 'lastSync']);
  assert.equal('tags' in known[0], false);
  assert.equal('blocked' in known[0], false);
  assert.equal(JSON.stringify(known).includes('family'), false);
  assert.equal(JSON.stringify(known).includes('secret-group'), false);
});
