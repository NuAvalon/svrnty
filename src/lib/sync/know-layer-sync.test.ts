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
import { edgeTrusted } from '@/lib/trust/contact-edge';
import {
  buildKnowOverlayDeps,
  runKnowLayerSyncTick,
  startKnowLayerSync,
  runPsiCompletionPass,
  savePsiInitiated,
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

test('getKnownPeers returns only the trusted ∩ open_visibility subset (with real fingerprints)', async () => {
  const contacts = [
    rec({ id: 'p1', fingerprint: 'peer-open-1', trusted: true, open_visibility: true }),
    rec({ id: 'p2', fingerprint: 'peer-open-2', trusted: true, metadata: { share_settings: { open_visibility: true } } }),
    rec({ id: 'p3', fingerprint: 'peer-closed', trusted: true, open_visibility: false }), // trusted but NOT open-vis ⇒ out
    rec({ id: 'p4', fingerprint: 'peer-default' }), // no consent field ⇒ closed
    // keyless / gray contact that somehow carries a consent flag — must NOT leak (no real fingerprint)
    rec({ id: 'p5', fingerprint: '', trusted: true, open_visibility: true }),
  ];
  const { store } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);

  const known = await deps.getKnownPeers();
  const fps = known.map((p) => p.fingerprint).sort();
  assert.deepEqual(fps, ['peer-open-1', 'peer-open-2']); // both consent shapes; trusted-but-closed, default, keyless all out
});

test('getKnownPeers excludes grow_gate rows even if open_visibility leaked on', async () => {
  const contacts = [
    rec({ id: 'p1', fingerprint: 'peer-open', trusted: true, open_visibility: true }),
    rec({
      id: 'g1',
      fingerprint: 'peer-gate',
      trusted: true,
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

test('NEGATIVE: PSI peer list is fingerprint+lastSync only — no tags/group labels', async () => {
  const contacts = [
    rec({
      id: 'p1',
      fingerprint: 'peer-open-1',
      trusted: true,
      open_visibility: true,
      tags: ['family', 'secret-group'],
      metadata: { tags: ['family'], notes: 'stay off the wire' },
    } as Partial<ContactRecord>),
  ];
  const { store } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);
  const known = await deps.getKnownPeers();
  assert.equal(known.length, 1);
  assert.deepEqual(Object.keys(known[0]).sort(), ['fingerprint', 'lastSync']);
  assert.equal('tags' in known[0], false);
  assert.equal(JSON.stringify(known).includes('family'), false);
  assert.equal(JSON.stringify(known).includes('secret-group'), false);
});

// ── Chaos #111 (Flint survivor-safety ruling): a BLOCKED peer must NEVER enter the PSI reveal set ────
// Regression lock on the exact survivor-catastrophe: a survivor blocks an adversary who had
// open_visibility=true; the adversary must drop OUT of getKnownPeers immediately, by construction —
// NOT linger until some handler happens to clear open_visibility. Covers both blocked shapes
// (top-level `blocked` and `metadata.blocked`) since isContactBlocked() honors both.
// piece-1 (Flint seal #158892): the trusted term DROPPED from the reveal (→ trust layer, piece-2), so an
// untrusted-open edge NOW reveals in the known layer. The Chaos #111 survivor-guard is UNCHANGED and
// PRESERVED: a BLOCKED peer (either shape) still NEVER reveals (dropped at ownerEdges). In live data the
// SET-path clamp (H1) + legacy sweep (G) prevent an untrusted-open RECORD from existing; this fixture
// exercises the reveal LOGIC directly.
test('getKnownPeers reveal set: blocked (both shapes) NEVER reveals (Chaos #111 guard preserved); untrusted-open NOW reveals (trusted dropped — piece-1)', async () => {
  const contacts = [
    // the honest path — trusted + open-visible + not blocked ⇒ revealed (Flint co-verify case 4)
    rec({ id: 'ok', fingerprint: 'peer-open', trusted: true, open_visibility: true }),
    // blocked via top-level, else fully revealable (trusted + open_vis) ⇒ blocked is the SOLE reason it drops (case 2)
    rec({ id: 'b1', fingerprint: 'peer-blocked-top', trusted: true, open_visibility: true, blocked: true } as Partial<ContactRecord>),
    // blocked via metadata.blocked — the other shape isContactBlocked() honors (|| not ??)
    rec({ id: 'b2', fingerprint: 'peer-blocked-meta', trusted: true, open_visibility: true, metadata: { blocked: true } }),
    // untrusted but open-visible ⇒ NOW REVEALED (two-layer: trusted moved to the trust layer, piece-1 §B1)
    rec({ id: 'u1', fingerprint: 'peer-untrusted-open', trusted: false, open_visibility: true }),
  ];
  const { store } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);

  const fps = (await deps.getKnownPeers()).map((p) => p.fingerprint).sort();
  // ★ blocked (both shapes) STILL excluded = Chaos #111 survivor-guard PRESERVED; untrusted-open NOW revealed (trusted dropped)
  assert.deepEqual(fps, ['peer-open', 'peer-untrusted-open']);
  // Belt-and-suspenders: a blocked peer must not reach the TRUST reveal path either (ownerEdges single point).
  const trustedFps = (await deps.getTrustedPeers()).map((p) => p.fingerprint);
  assert.equal(trustedFps.includes('peer-blocked-top'), false);
  assert.equal(trustedFps.includes('peer-blocked-meta'), false);
});

// ── piece-1: KNOWN reveal = open_visibility ∩ !blocked ∩ !per_contact_private (the &&trusted term DROPPED
// to the TRUSTED layer, piece-2). §F case 1 — an open-visible UNtrusted edge is now REVEALED;
// per_contact_private is the new fail-closed AND-term; blocked + go-private still drop as before. ──────
test('piece-1 getKnownPeers: open-visible UNtrusted REVEALS; pcp / blocked / go-private all drop', async () => {
  const contacts = [
    // open-visible but UNTRUSTED → now REVEALED (was dropped by the old &&trusted term)
    rec({ id: 'u', fingerprint: 'peer-untrusted-open', trusted: false, open_visibility: true }),
    // open-visible + trusted, but per_contact_private → EXCLUDED (new AND-term, truthy-exclusion)
    rec({ id: 'pcp', fingerprint: 'peer-pcp', trusted: true, open_visibility: true, per_contact_private: true }),
    // open-visible + trusted, but blocked → EXCLUDED (ownerEdges !blocked, unchanged by piece-1)
    rec({ id: 'b', fingerprint: 'peer-blocked', trusted: true, open_visibility: true, blocked: true }),
    // go-private: open_visibility=false → EXCLUDED (unchanged)
    rec({ id: 'gp', fingerprint: 'peer-goprivate', trusted: true, open_visibility: false }),
  ];
  const { store } = fakeStore(contacts);
  const deps = buildKnowOverlayDeps(OWNER, store);
  const fps = (await deps.getKnownPeers()).map((p) => p.fingerprint).sort();
  // ONLY the open-visible untrusted edge reveals; pcp + blocked + go-private all excluded
  assert.deepEqual(fps, ['peer-untrusted-open']);
});

test('piece-1 getKnownPeers: per_contact_private is the SOLE reason an open-visible edge drops (fail-closed)', async () => {
  // Same edge, pcp the only differentiator: set → excluded (truthy-exclusion, fail-closed); clear → revealed.
  const withPcp = fakeStore([
    rec({ id: 'x', fingerprint: 'peer-x', trusted: true, open_visibility: true, per_contact_private: true }),
  ]);
  const withoutPcp = fakeStore([
    rec({ id: 'x', fingerprint: 'peer-x', trusted: true, open_visibility: true, per_contact_private: false }),
  ]);
  const depsWith = buildKnowOverlayDeps(OWNER, withPcp.store);
  const depsWithout = buildKnowOverlayDeps(OWNER, withoutPcp.store);
  assert.deepEqual((await depsWith.getKnownPeers()).map((p) => p.fingerprint), []); // pcp EXCLUDES
  assert.deepEqual((await depsWithout.getKnownPeers()).map((p) => p.fingerprint), ['peer-x']); // not-private reveals
});

// ── piece-1 §G: #111-LEGACY SWEEP (migratePerContactPrivacyOnUnlock, client-store.ts) ─────────────────
// The sweep fn itself is IndexedDB + session-key gated (txGetAll / updateContact / decryptContactIfNeeded,
// not exported) → not directly runnable under node:test. We test (a) its exact per-record decision
// predicate — the ★★ shared edgeTrusted derivation (explicit c.trusted===false WINS over trust_level) + the
// open_visibility clear, and (b) the integration: a swept (cleared) record drops OUT of getKnownPeers, a
// trusted-open record is UNTOUCHED, and a 2nd pass writes nothing (idempotent). NOTE: the predicate is the
// SHARED edgeTrusted (imported from contact-edge.ts — pure, not browser-coupled, so no drift vs the source);
// only the sweep FN itself is browser-coupled (IndexedDB/session-key), so sweepClear mirrors just its
// open_visibility-clear logic around that shared predicate.

// Mirror of migratePerContactPrivacyOnUnlock's per-record core (clear logic only; the trusted predicate is
// the shared edgeTrusted). Returns the clearing patch when a NON-trusted edge carries open_visibility=true,
// else null (no write).
function sweepClear(c: { trust_level?: string; trusted?: boolean; metadata?: any }): { metadata: any } | null {
  const trusted = edgeTrusted(c);
  const md = (c.metadata as Record<string, unknown>) ?? {};
  const ss = (md.share_settings as { open_visibility?: boolean }) ?? {};
  if (!trusted && ss.open_visibility === true) {
    return { metadata: { ...md, share_settings: { ...ss, open_visibility: false } } };
  }
  return null;
}

// Run the sweep loop over an in-memory book; returns the post-sweep book + the write count.
function runSweep(book: ContactRecord[]): { book: ContactRecord[]; writes: number } {
  let writes = 0;
  const out = book.map((c) => {
    const patch = sweepClear(c);
    if (patch) { writes++; return { ...c, ...patch } as ContactRecord; }
    return c;
  });
  return { book: out, writes };
}

test('piece-1 §G sweep: untrusted-open → open_visibility cleared + dropped from getKnownPeers; verified-open UNTOUCHED; idempotent', async () => {
  const seed = [
    rec({ id: 'u', fingerprint: 'peer-untrusted-open', trust_level: 'unverified', metadata: { share_settings: { open_visibility: true } } }),
    rec({ id: 'v', fingerprint: 'peer-verified-open', trust_level: 'verified', metadata: { share_settings: { open_visibility: true } } }),
  ];

  // first pass clears exactly the one untrusted-open record
  const pass1 = runSweep(seed);
  assert.equal(pass1.writes, 1);

  const swept = pass1.book;
  const u = swept.find((c) => c.id === 'u')!;
  const v = swept.find((c) => c.id === 'v')!;
  assert.equal((u.metadata as any).share_settings.open_visibility, false); // untrusted-open → cleared
  assert.equal((v.metadata as any).share_settings.open_visibility, true);  // verified-open → UNTOUCHED

  // integration: the swept book's known set no longer contains the untrusted edge; verified-open still reveals
  const { store } = fakeStore(swept);
  const deps = buildKnowOverlayDeps(OWNER, store);
  const fps = (await deps.getKnownPeers()).map((p) => p.fingerprint).sort();
  assert.deepEqual(fps, ['peer-verified-open']);

  // idempotent: a 2nd pass over the already-swept book writes nothing
  const pass2 = runSweep(swept);
  assert.equal(pass2.writes, 0);
});

test('piece-1 §G sweep predicate: explicit c.trusted===false WINS over trust_level (★★ reveal derivation)', () => {
  // {trusted:false, trust_level:'trusted'} is NON-trusted per the reveal (?? short-circuits on the explicit
  // false) → its open_visibility IS swept. A trust_level-only test (isTrusted@112) would WRONGLY skip it.
  assert.notEqual(
    sweepClear({ trusted: false, trust_level: 'trusted', metadata: { share_settings: { open_visibility: true } } }),
    null,
  );
  // trusted (explicit true, or trust_level verified/trusted) → NOT swept
  assert.equal(sweepClear({ trusted: true, trust_level: 'unverified', metadata: { share_settings: { open_visibility: true } } }), null);
  assert.equal(sweepClear({ trust_level: 'verified', metadata: { share_settings: { open_visibility: true } } }), null);
});

// §F case 4 (block≡offline integration: a pcp'd peer's /initiate → sinkhole ≡ offline) is SATELLITE-side
// (satellite.py allowed_senders gate) — OUT OF SCOPE for these TS client unit tests; not faked here.

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
