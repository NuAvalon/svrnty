// src/lib/trust/psi-flow.integration.test.ts
//
// PSI end-to-end integration — QA-1st-pass for the client-alpha wire-in (PR#127).
// Peter #134445: "deploy psi to dev and test — need complex know/trust rel's to test thorough."
//
// This runs the REAL DH-PSI crypto flow (initiateTrustSync → respondToTrustSync → completeTrustSync)
// between independent clients through an in-memory BLIND relay (mock satellite), over COMPLEX,
// overlapping, partially-consented contact graphs, and asserts the discovered trust map equals the
// TRUE consented intersection — plus determinism, unlinkability, mutual-consent (D1), and
// forward-retract.
//
// It complements the PR#127 unit tests (know-layer-sync.test.ts), which mock completeTrustSync and
// so only lock the completion STATE MACHINE. This file locks the crypto-flow CORRECTNESS: that the
// intersection math + blinding + wire actually produce the right "contacts you both know" on real
// graphs. (The intersection is the shared THIRD-PARTY contacts — a peer's own fp is never in its own
// blinded set, so A↔B never surfaces A or B themselves, only contacts both hold AND both consented.)
//
// Run: npx tsx --test src/lib/trust/psi-flow.integration.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  initiateTrustSync,
  respondToTrustSync,
  completeTrustSync,
  syncMutualTrust,
  type OrchestratorDeps,
  type PSISyncOptions,
} from './mutual-trust-sync';

// ── In-memory BLIND relay (mock satellite) ──────────────────────────────────────────────────────
// Stores + forwards blinded sets keyed by session; computes NOTHING (it stays blind — it never sees
// H(fp) or the intersection). Implements the 5 endpoints the client fetches.
interface RelaySession {
  session_id: string;
  initiator: string;
  responder: string;
  initiator_blinded_set: string[];
  created_at: number; // seconds — the client does created_at * 1000 for the age check
  responder_blinded_set?: string[];
  reblinded_initiator_set?: string[];
}

interface MockResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}

function makeRelay() {
  const sessions = new Map<string, RelaySession>();
  let seq = 0;
  const reply = (obj: unknown, ok = true, status = 200): MockResponse => ({
    ok,
    status,
    json: async () => obj,
    text: async () => JSON.stringify(obj),
  });

  const fetchImpl = async (url: string, init?: { method?: string; body?: string }): Promise<MockResponse> => {
    const { pathname } = new URL(url);
    const method = init?.method ?? 'GET';

    if (pathname.endsWith('/trust/psi/initiate') && method === 'POST') {
      const b = JSON.parse(init!.body!);
      const session_id = `sess-${++seq}`;
      sessions.set(session_id, {
        session_id,
        initiator: b.initiator_fingerprint,
        responder: b.responder_fingerprint,
        initiator_blinded_set: b.blinded_set,
        created_at: Math.floor(Date.now() / 1000),
      });
      return reply({ session_id });
    }

    const pend = pathname.match(/\/trust\/psi\/pending\/(.+)$/);
    if (pend && method === 'GET') {
      const fp = decodeURIComponent(pend[1]);
      const pending_sessions = [...sessions.values()]
        .filter((s) => s.responder === fp && !s.responder_blinded_set)
        .map((s) => ({ session_id: s.session_id, initiator: s.initiator, created_at: s.created_at }));
      return reply({ pending_sessions });
    }

    const bl = pathname.match(/\/trust\/psi\/session\/([^/]+)\/blinded$/);
    if (bl && method === 'GET') {
      const s = sessions.get(bl[1]);
      if (!s) return reply({}, false, 404);
      return reply({ blinded_set: s.initiator_blinded_set });
    }

    const rp = pathname.match(/\/trust\/psi\/session\/([^/]+)\/respond$/);
    if (rp && method === 'POST') {
      const s = sessions.get(rp[1]);
      if (!s) return reply({}, false, 404);
      const b = JSON.parse(init!.body!);
      s.responder_blinded_set = b.blinded_set;
      s.reblinded_initiator_set = b.reblinded_initiator_set;
      return reply({ ok: true });
    }

    const rs = pathname.match(/\/trust\/psi\/session\/([^/]+)\/result$/);
    if (rs && method === 'GET') {
      const s = sessions.get(rs[1]);
      if (!s || !s.responder_blinded_set) return reply({}, false, 404);
      return reply({
        responder_blinded_set: s.responder_blinded_set,
        reblinded_initiator_set: s.reblinded_initiator_set,
      });
    }

    return reply({}, false, 404);
  };

  return { sessions, fetchImpl };
}

// ── Client harness ──────────────────────────────────────────────────────────────────────────────
// A client = a fingerprint + a book of contacts (each flagged consented or not). getKnownPeers is
// the CONSENTED subset (the KNOW-layer consent gate for both roles). applyMutualResult records the
// discovered set per peer (the disclosed_circle sink).
interface Contact {
  fp: string;
  consented: boolean;
}

function makeClient(fingerprint: string, book: Contact[]) {
  const disclosedByPeer = new Map<string, string[]>();
  const deps: OrchestratorDeps = {
    getTrustedPeers: async () => book.map((c) => ({ fingerprint: c.fp })),
    getKnownPeers: async () => book.filter((c) => c.consented).map((c) => ({ fingerprint: c.fp })),
    applyMutualResult: async (peerFp, _layer, disclosed) => {
      disclosedByPeer.set(peerFp, disclosed);
    },
  };
  const options: PSISyncOptions = {
    satelliteUrl: 'http://relay',
    myFingerprint: fingerprint,
    signFn: () => new Uint8Array(64), // relay ignores signatures in-test
  };
  return { fingerprint, deps, options, disclosedByPeer };
}

type Client = ReturnType<typeof makeClient>;

// Drive one full initiator→responder→initiator round; returns the sorted disclosed set the initiator
// computed for the peer (the "contacts you both know").
async function runRound(initiator: Client, responder: Client): Promise<string[]> {
  const init = await initiateTrustSync(initiator.deps, responder.fingerprint, initiator.options, 'know');
  if ('error' in init) throw new Error(`initiate failed: ${init.error}`);
  await respondToTrustSync(responder.deps, responder.options, 'know');
  const res = await completeTrustSync(
    initiator.deps,
    init.sessionId,
    responder.fingerprint,
    init.keypair,
    initiator.options,
    init.fpOrder,
    'know',
  );
  if ('error' in res) throw new Error(`complete failed: ${res.error}`);
  return [...(initiator.disclosedByPeer.get(responder.fingerprint) ?? [])].sort();
}

// Distinct fingerprints (any string hashes via HKDF; distinct → distinct points).
const A = 'fp-alice';
const B = 'fp-bob';
const C = 'fp-carol';
const X = 'fp-xavier';
const Y = 'fp-yara';
const Z = 'fp-zed';
const W = 'fp-wren';

// Install/uninstall the blind relay as global fetch around each round.
async function withRelay<T>(fn: (relay: ReturnType<typeof makeRelay>) => Promise<T>): Promise<T> {
  const relay = makeRelay();
  const original = globalThis.fetch;
  (globalThis as unknown as { fetch: unknown }).fetch = relay.fetchImpl;
  try {
    return await fn(relay);
  } finally {
    (globalThis as unknown as { fetch: unknown }).fetch = original;
  }
}

test('MUTUAL: A↔B discover exactly the contacts they both hold + both consented', async () => {
  await withRelay(async () => {
    // A knows {B, X, Y, Z}; B knows {A, Y, Z, W}. Shared third parties = {Y, Z}.
    const alice = makeClient(A, [B, X, Y, Z].map((fp) => ({ fp, consented: true })));
    const bob = makeClient(B, [A, Y, Z, W].map((fp) => ({ fp, consented: true })));
    const disclosed = await runRound(alice, bob);
    assert.deepEqual(disclosed, [Y, Z].sort(), 'A must discover exactly {Y,Z}');
    // A or B themselves must NEVER appear (own fp not in own blinded set).
    assert.equal(disclosed.includes(A), false);
    assert.equal(disclosed.includes(B), false);
  });
});

test('KNOW initiate: layer-aware candidate source — an open-visible but UNTRUSTED peer IS initiated (KB#89649)', async () => {
  await withRelay(async (relay) => {
    // Alice holds Bob as open-visible (KNOW-level) but NOT trusted, never synced. Pre-fix the KNOW
    // initiate candidate source was getTrustedPeers → Bob excluded → POST /trust/psi/initiate never
    // fired → "who you both know" chord stayed 0. Post-fix the KNOW source IS getKnownPeers.
    const deps: OrchestratorDeps = {
      getTrustedPeers: async () => [], // NO trusted peers
      getKnownPeers: async () => [{ fingerprint: B, lastSync: null }], // Bob: open-visible, never synced
      applyMutualResult: async () => {},
    };
    const options: PSISyncOptions = { satelliteUrl: 'http://relay', myFingerprint: A, signFn: () => new Uint8Array(64) };
    const result = await syncMutualTrust(deps, options, 'know');
    assert.deepEqual(result.errors, [], 'no errors');
    assert.equal(result.initiated.length, 1, 'KNOW initiates with the untrusted open-visible peer');
    assert.equal(result.initiated[0].peerFingerprint, B);
    assert.equal(relay.sessions.size, 1, 'exactly one PSI session created (POST /initiate fired)');
  });
});

test('KNOW initiate: an EMPTY open-visible set initiates NOTHING even with a trusted peer (chord-0 correct, Flint D1/D2 not loosened)', async () => {
  await withRelay(async (relay) => {
    const deps: OrchestratorDeps = {
      getTrustedPeers: async () => [{ fingerprint: B, lastSync: null }], // trusted, but NOT open-visible
      getKnownPeers: async () => [], // empty open set ⇒ fail-closed
      applyMutualResult: async () => {},
    };
    const options: PSISyncOptions = { satelliteUrl: 'http://relay', myFingerprint: A, signFn: () => new Uint8Array(64) };
    const result = await syncMutualTrust(deps, options, 'know');
    assert.equal(result.initiated.length, 0, 'no open-visible peers → no initiate (the boundary is not widened to trusted)');
    assert.equal(relay.sessions.size, 0);
  });
});

test('TRUST layer unchanged: an open-visible-but-untrusted peer is NOT initiated at the trust layer', async () => {
  await withRelay(async () => {
    const deps: OrchestratorDeps = {
      getTrustedPeers: async () => [], // no trusted peers
      getKnownPeers: async () => [{ fingerprint: B, lastSync: null }], // open-visible only
      applyMutualResult: async () => {},
    };
    const options: PSISyncOptions = { satelliteUrl: 'http://relay', myFingerprint: A, signFn: () => new Uint8Array(64) };
    const result = await syncMutualTrust(deps, options, 'trust');
    assert.equal(result.initiated.length, 0, 'trust layer sources getTrustedPeers only (unchanged)');
  });
});

test('PARTIAL CONSENT: an un-consented contact is never blinded, so never discovered', async () => {
  await withRelay(async () => {
    // A holds {B, X, Y, Z} but has NOT consented Z (open_visibility off). B holds {A, Y, Z}.
    const alice = makeClient(A, [
      { fp: B, consented: true },
      { fp: X, consented: true },
      { fp: Y, consented: true },
      { fp: Z, consented: false }, // retracted / private — must not surface even though B has Z
    ]);
    const bob = makeClient(B, [A, Y, Z].map((fp) => ({ fp, consented: true })));
    const disclosed = await runRound(alice, bob);
    assert.deepEqual(disclosed, [Y], 'Z is un-consented on A → excluded despite being shared');
  });
});

test('DISJOINT: no shared contacts → nothing disclosed (empty, not error)', async () => {
  await withRelay(async () => {
    const alice = makeClient(A, [B, X, Y].map((fp) => ({ fp, consented: true })));
    const bob = makeClient(B, [A, Z, W].map((fp) => ({ fp, consented: true })));
    const disclosed = await runRound(alice, bob);
    assert.deepEqual(disclosed, [], 'no overlap → empty disclosed set');
  });
});

test('MUTUAL-CONSENT (D1): if the responder has not consented to the initiator, nothing is revealed', async () => {
  await withRelay(async () => {
    // A consents to B and holds {B, Y, Z}. B holds {Y, Z} but has NOT consented to A
    // (A not in B's known/consented set) → B must not respond → A gets no result.
    const alice = makeClient(A, [B, Y, Z].map((fp) => ({ fp, consented: true })));
    const bob = makeClient(B, [
      { fp: Y, consented: true },
      { fp: Z, consented: true },
      { fp: A, consented: false }, // B did NOT opt into mutual visibility with A
    ]);
    const init = await initiateTrustSync(alice.deps, B, alice.options, 'know');
    assert.ok(!('error' in init));
    await respondToTrustSync(bob.deps, bob.options, 'know'); // D1 gate → skips (no consent to A)
    const res = await completeTrustSync(alice.deps, (init as any).sessionId, B, (init as any).keypair, alice.options, (init as any).fpOrder, 'know');
    // Responder never answered → no result → nothing disclosed. No unilateral reveal.
    assert.ok('error' in res || (alice.disclosedByPeer.get(B) ?? []).length === 0);
    assert.deepEqual(alice.disclosedByPeer.get(B) ?? [], []);
  });
});

test('RETRACT (forward): de-consenting the peer fail-closes the initiate (no sync, no leak)', async () => {
  await withRelay(async () => {
    // A holds B but has gone private on B (consented:false). Initiating with B must fail-closed.
    const alice = makeClient(A, [
      { fp: B, consented: false },
      { fp: Y, consented: true },
    ]);
    const init = await initiateTrustSync(alice.deps, B, alice.options, 'know');
    assert.ok('error' in init, 'de-consented peer → initiate must fail-closed (D1)');
  });
});

test('MULTI-PEER: A syncs B and C independently → correct, isolated per-peer discovery', async () => {
  await withRelay(async () => {
    // A knows {B, C, X, Y}. B knows {A, X, Z}. C knows {A, Y, W}.
    const alice = makeClient(A, [B, C, X, Y].map((fp) => ({ fp, consented: true })));
    const bob = makeClient(B, [A, X, Z].map((fp) => ({ fp, consented: true })));
    const carol = makeClient(C, [A, Y, W].map((fp) => ({ fp, consented: true })));
    const withB = await runRound(alice, bob);
    const withC = await runRound(alice, carol);
    assert.deepEqual(withB, [X], 'A∩B = {X}');
    assert.deepEqual(withC, [Y], 'A∩C = {Y}');
  });
});

test('DETERMINISM: the same graph run twice yields the same discovered set', async () => {
  const graph = () => {
    const alice = makeClient(A, [B, X, Y, Z].map((fp) => ({ fp, consented: true })));
    const bob = makeClient(B, [A, Y, Z, W].map((fp) => ({ fp, consented: true })));
    return { alice, bob };
  };
  const r1 = await withRelay(async () => {
    const { alice, bob } = graph();
    return runRound(alice, bob);
  });
  const r2 = await withRelay(async () => {
    const { alice, bob } = graph();
    return runRound(alice, bob);
  });
  assert.deepEqual(r1, r2, 'PSI result must be deterministic for fixed inputs');
  assert.deepEqual(r1, [Y, Z].sort());
});

test('UNLINKABILITY: two sessions blind the SAME contact to DIFFERENT values (fresh per-session key)', async () => {
  await withRelay(async (relay) => {
    // A initiates two separate sessions with B; each uses a fresh ephemeral keypair (Flint D3), so
    // the blinded value of any shared fp must differ between sessions → the blind relay can't link
    // the two runs (or A's set across peers) by matching blinded points.
    const alice = makeClient(A, [B, X, Y, Z].map((fp) => ({ fp, consented: true })));
    const bob = makeClient(B, [A, Y, Z, W].map((fp) => ({ fp, consented: true })));
    await initiateTrustSync(alice.deps, B, alice.options, 'know');
    await initiateTrustSync(alice.deps, B, alice.options, 'know');
    const sets = [...relay.sessions.values()].map((s) => s.initiator_blinded_set);
    assert.equal(sets.length, 2, 'two sessions recorded');
    const overlap = sets[0].filter((v) => sets[1].includes(v));
    assert.equal(overlap.length, 0, 'no blinded value repeats across sessions → unlinkable');
  });
});
