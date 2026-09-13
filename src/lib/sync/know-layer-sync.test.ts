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
  runPsiCompletionPass,
  savePsiInitiated,
  runBindCeremony,
  runRegisterCeremony,
  type KnowOverlayStore,
  type SyncMutualTrustFn,
  type CompleteTrustSyncFn,
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

test('getKnownPeers excludes grow_gate rows even if open_visibility leaked on', async () => {
  const contacts = [
    rec({ id: 'p1', fingerprint: 'peer-open', open_visibility: true }),
    rec({
      id: 'g1',
      fingerprint: 'peer-gate',
      open_visibility: true,
      metadata: { grow_gate: true },
    }),
  ];
  const { store } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);
  const fps = (await deps.getKnownPeers()).map((p) => p.fingerprint);
  assert.deepEqual(fps, ['peer-open']);
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

// ── PSI initiator completion (Option A wire-in): the initiator half that was never wired ──────────
// (syncMutualTrust returned `initiated` but the tick discarded it → completeTrustSync had zero callers
//  → no intersection → no trust map). These lock the persist/complete/expire/retract state machine.

const STUB_DEPS: OrchestratorDeps = {
  getTrustedPeers: async () => [],
  getKnownPeers: async () => [],
  applyMutualResult: async () => {},
};
const readyFn: CompleteTrustSyncFn = async () => ({ mutualFingerprints: [], totalChecked: 0, sessionId: 's', role: 'initiator' });
const notReadyFn: CompleteTrustSyncFn = async () => ({ error: 'Session not ready or not found' });

test('savePsiInitiated persists the blinder onto the peer contact record', async () => {
  const { store, writes } = fakeStore([rec({ id: 'c1', fingerprint: 'peer-fp', open_visibility: true })]);
  await savePsiInitiated(store, OWNER, [
    { peerFingerprint: 'peer-fp', sessionId: 'sess-1', keypair: { privateKey: 'sk', publicKey: 'pub' }, fpOrder: ['a', 'b'] },
  ]);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].id, 'c1');
  assert.equal(writes[0].updates.psi_session_id, 'sess-1');
  assert.equal(writes[0].updates.psi_sk_A, 'sk');
  assert.deepEqual(writes[0].updates.psi_fp_order, ['a', 'b']);
  assert.equal(writes[0].updates.psi_attempts, 0);
});

test('savePsiInitiated never stores a session against a non-book fingerprint', async () => {
  const { store, writes } = fakeStore([rec({ id: 'c1', fingerprint: 'other', open_visibility: true })]);
  await savePsiInitiated(store, OWNER, [
    { peerFingerprint: 'ghost-fp', sessionId: 's', keypair: { privateKey: 'sk', publicKey: 'pub' }, fpOrder: [] },
  ]);
  assert.equal(writes.length, 0);
});

test('completion READY: completeFn returns a result → session cleared (ephemeral delete)', async () => {
  const { store, writes } = fakeStore([rec({ id: 'c1', fingerprint: 'peer-fp', open_visibility: true, psi_session_id: 'sess-1', psi_sk_A: 'sk', psi_pub: 'pub', psi_fp_order: ['a'], psi_layer: 'know', psi_attempts: 0 })]);
  await runPsiCompletionPass(store, OWNER, STUB_DEPS, DUMMY_OPTIONS, readyFn);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].updates.psi_session_id, undefined); // cleared after apply
});

test('completion NOT-READY: bumps the attempt counter (logical clock, no wall-clock)', async () => {
  const { store, writes } = fakeStore([rec({ id: 'c1', fingerprint: 'peer-fp', open_visibility: true, psi_session_id: 'sess-1', psi_sk_A: 'sk', psi_pub: 'pub', psi_fp_order: ['a'], psi_layer: 'know', psi_attempts: 2 })]);
  await runPsiCompletionPass(store, OWNER, STUB_DEPS, DUMMY_OPTIONS, notReadyFn);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].updates.psi_attempts, 3);
  assert.equal('psi_session_id' in writes[0].updates, false); // NOT cleared — only the counter bumped
});

test('completion EXPIRE: attempts past MAX → cleared (logical-clock expiry, no wall-clock)', async () => {
  const { store, writes } = fakeStore([rec({ id: 'c1', fingerprint: 'peer-fp', open_visibility: true, psi_session_id: 'sess-1', psi_sk_A: 'sk', psi_pub: 'pub', psi_fp_order: ['a'], psi_layer: 'know', psi_attempts: 12 })]);
  await runPsiCompletionPass(store, OWNER, STUB_DEPS, DUMMY_OPTIONS, notReadyFn);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].updates.psi_session_id, undefined); // cleared — responder never answered within TTL
});

test('completion FORWARD-RETRACT: de-consented peer → session + disclosed_circle cleared, never completed', async () => {
  const { store, writes } = fakeStore([rec({ id: 'c1', fingerprint: 'peer-fp', open_visibility: false, psi_session_id: 'sess-1', psi_sk_A: 'sk', psi_fp_order: ['a'], disclosed_circle: ['x', 'y'] })]);
  let completeCalled = false;
  const spyComplete: CompleteTrustSyncFn = async () => { completeCalled = true; return { error: 'x' }; };
  await runPsiCompletionPass(store, OWNER, STUB_DEPS, DUMMY_OPTIONS, spyComplete);
  assert.equal(completeCalled, false); // a de-consented peer is never completed
  assert.equal(writes.length, 1);
  assert.equal(writes[0].updates.psi_session_id, undefined); // session dropped (forward-revocation)
  assert.deepEqual(writes[0].updates.disclosed_circle, []); // disclosure retracted
});

test('completion FAIL-CLOSED: session missing its scalar → dropped, never completed with a guessed key', async () => {
  const { store, writes } = fakeStore([rec({ id: 'c1', fingerprint: 'peer-fp', open_visibility: true, psi_session_id: 'sess-1', psi_fp_order: ['a'] })]); // no psi_sk_A
  let completeCalled = false;
  const spyComplete: CompleteTrustSyncFn = async () => { completeCalled = true; return { error: 'x' }; };
  await runPsiCompletionPass(store, OWNER, STUB_DEPS, DUMMY_OPTIONS, spyComplete);
  assert.equal(completeCalled, false); // never proceeds without the persisted scalar
  assert.equal(writes.length, 1);
  assert.equal(writes[0].updates.psi_session_id, undefined); // dropped
});

// ── runBindCeremony: bind-405 fix — POST-direct to the authoritative POST-only /bind ──
// The satellite has NO GET-challenge route (a GET 405s → fail-closed → PSI never ran = the Gate-A
// bind-405). Fix: POST /bind directly, self-gen nonce, fields sig_pubkey/binding_sig (byte-matches
// psi_harness.py + satellite_9223f3d3_reconciled.py `@app.post("/bind")`).
test('runBindCeremony: POST-direct to /bind (no GET-challenge), authoritative fields', async () => {
  const calls: Array<{ url: string; method: string; body?: Record<string, unknown> }> = [];
  const mockFetch = (async (url: string, init?: { method?: string; body?: string }) => {
    calls.push({
      url,
      method: init?.method ?? 'GET',
      body: init?.body ? JSON.parse(init.body) : undefined,
    });
    return { ok: true, json: async () => ({}) } as Response;
  }) as unknown as typeof fetch;
  const ok = await runBindCeremony({
    satelliteUrl: 'https://sat/api/satellite',
    fingerprint: 'fp-alice',
    seed: new Uint8Array(32).fill(7),
    signPub: new Uint8Array(32).fill(9),
    fetchImpl: mockFetch,
  });
  assert.equal(ok, true);
  assert.equal(calls.length, 1); // exactly one call — NO GET-challenge
  assert.equal(calls[0].method, 'POST');
  assert.ok(calls[0].url.endsWith('/bind') && !calls[0].url.includes('?'), 'POST /bind, no ?fingerprint challenge');
  const b = calls[0].body as Record<string, unknown>;
  assert.equal(b.fingerprint, 'fp-alice');
  assert.equal(typeof b.sig_pubkey, 'string');
  assert.equal((b.sig_pubkey as string).length, 64); // hex of 32-byte pub
  assert.equal((b.nonce as string).length, 32); // hex of 16 random bytes
  assert.equal(b.epoch, 0);
  assert.equal(typeof b.binding_sig, 'string');
  assert.ok(!('sign_pubkey' in b) && !('signature' in b), 'no legacy field names');
});

test('runBindCeremony: fail-closed when POST /bind !ok (no PSI)', async () => {
  const mockFetch = (async () => ({ ok: false, json: async () => ({}) }) as Response) as unknown as typeof fetch;
  const ok = await runBindCeremony({
    satelliteUrl: 'https://sat/api/satellite',
    fingerprint: 'fp',
    seed: new Uint8Array(32).fill(7),
    signPub: new Uint8Array(32).fill(9),
    fetchImpl: mockFetch,
  });
  assert.equal(ok, false);
});

// ── runRegisterCeremony: enroll at the satellite before bind (else bind 404 "Unknown fingerprint") ──
test('runRegisterCeremony: POST /register {fingerprint, public_key} (enroll before bind)', async () => {
  const calls: Array<{ url: string; body?: Record<string, unknown> }> = [];
  const mockFetch = (async (url: string, init?: { body?: string }) => {
    calls.push({ url, body: init?.body ? JSON.parse(init.body) : undefined });
    return { ok: true, status: 200, json: async () => ({}) } as Response;
  }) as unknown as typeof fetch;
  const ok = await runRegisterCeremony({
    satelliteUrl: 'https://sat/api/satellite',
    identity: { identity: { fingerprint: 'fp-alice', public_key: 'PUBKEY-armored' } },
    fetchImpl: mockFetch,
  });
  assert.equal(ok, true);
  assert.equal(calls.length, 1);
  assert.ok(calls[0].url.endsWith('/register'), 'POST /register');
  assert.equal(calls[0].body?.fingerprint, 'fp-alice');
  assert.equal(calls[0].body?.public_key, 'PUBKEY-armored');
});

test('runRegisterCeremony: 409 (already registered) = success', async () => {
  const mockFetch = (async () => ({ ok: false, status: 409, json: async () => ({}) }) as Response) as unknown as typeof fetch;
  const ok = await runRegisterCeremony({
    satelliteUrl: 'https://sat',
    identity: { identity: { fingerprint: 'fp', public_key: 'pk' } },
    fetchImpl: mockFetch,
  });
  assert.equal(ok, true);
});

test('runRegisterCeremony: 403 "Key rotation requires signature" (already-registered) = success → proceed to bind', async () => {
  const mockFetch = (async () => ({
    ok: false,
    status: 403,
    text: async () => JSON.stringify({ detail: 'Key rotation requires signature from existing key' }),
    json: async () => ({ detail: 'Key rotation requires signature from existing key' }),
  }) as Response) as unknown as typeof fetch;
  const ok = await runRegisterCeremony({
    satelliteUrl: 'https://sat',
    identity: { identity: { fingerprint: 'fp', public_key: 'pk' } },
    fetchImpl: mockFetch,
  });
  assert.equal(ok, true); // re-register of an existing fp = already enrolled → proceed (KB#89344)
});

test('runRegisterCeremony: unrelated 403 → fail-closed (does NOT blanket-accept 403)', async () => {
  const mockFetch = (async () => ({
    ok: false,
    status: 403,
    text: async () => JSON.stringify({ detail: 'Forbidden: invalid auth token' }),
    json: async () => ({}),
  }) as Response) as unknown as typeof fetch;
  const ok = await runRegisterCeremony({
    satelliteUrl: 'https://sat',
    identity: { identity: { fingerprint: 'fp', public_key: 'pk' } },
    fetchImpl: mockFetch,
  });
  assert.equal(ok, false); // a 403 that is NOT the rotation/already-registered guard must fail-closed
});

test('runRegisterCeremony: missing public_key → false, no call (fail-closed)', async () => {
  let called = false;
  const mockFetch = (async () => {
    called = true;
    return { ok: true, status: 200, json: async () => ({}) } as Response;
  }) as unknown as typeof fetch;
  const ok = await runRegisterCeremony({
    satelliteUrl: 'https://sat',
    identity: { identity: { fingerprint: 'fp' } },
    fetchImpl: mockFetch,
  });
  assert.equal(ok, false);
  assert.equal(called, false);
});
