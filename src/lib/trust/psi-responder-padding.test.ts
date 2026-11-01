// src/lib/trust/psi-responder-padding.test.ts
// The set a responder sends is padded to the fixed bucket, like the initiator's, so neither the peer nor the relay learns how many
// contacts the responder has consented to share. The REAL respondToTrustSync against an in-memory relay that records exactly what it
// was sent. A responder with more contacts than the bucket holds cannot be padded and is not answered (it would otherwise send an
// unpadded set, or a truncated one that the initiator would then store as the whole result).
//
// Run: npx tsx --test src/lib/trust/psi-responder-padding.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  initiateTrustSync,
  respondToTrustSync,
  completeTrustSync,
  type OrchestratorDeps,
  type PSISyncOptions,
} from './mutual-trust-sync';
import { PSI_BLINDED_BUCKET_N } from './psi-resync-slot';

// ── In-memory relay: stores what each side sends, computes nothing ────────────────────────────────
interface RelaySession {
  session_id: string;
  initiator: string;
  responder: string;
  initiator_blinded_set: string[];
  created_at: number;
  responder_blinded_set?: string[];
  reblinded_initiator_set?: string[];
}
type Res = { ok: boolean; status: number; json: () => Promise<unknown>; text: () => Promise<string> };

function makeRelay() {
  const sessions = new Map<string, RelaySession>();
  let seq = 0;
  const reply = (obj: unknown, ok = true, status = 200): Res => ({ ok, status, json: async () => obj, text: async () => JSON.stringify(obj) });
  const fetchImpl = async (url: string, init?: { method?: string; body?: string }): Promise<Res> => {
    const { pathname } = new URL(url);
    const method = init?.method ?? 'GET';
    if (pathname.endsWith('/trust/psi/initiate') && method === 'POST') {
      const b = JSON.parse(init!.body!);
      const session_id = `sess-${++seq}`;
      sessions.set(session_id, { session_id, initiator: b.initiator_fingerprint, responder: b.responder_fingerprint,
        initiator_blinded_set: b.blinded_set, created_at: Math.floor(Date.now() / 1000) });
      return reply({ session_id });
    }
    const pend = pathname.match(/\/trust\/psi\/pending\/(.+)$/);
    if (pend && method === 'GET') {
      const fp = decodeURIComponent(pend[1]);
      return reply({ pending_sessions: [...sessions.values()].filter((s) => s.responder === fp && !s.responder_blinded_set)
        .map((s) => ({ session_id: s.session_id, initiator: s.initiator, created_at: s.created_at })) });
    }
    const bl = pathname.match(/\/trust\/psi\/session\/([^/]+)\/blinded$/);
    if (bl && method === 'GET') {
      const s = sessions.get(bl[1]);
      return s ? reply({ blinded_set: s.initiator_blinded_set }) : reply({}, false, 404);
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
      return s && s.responder_blinded_set ? reply({ responder_blinded_set: s.responder_blinded_set, reblinded_initiator_set: s.reblinded_initiator_set }) : reply({}, false, 404);
    }
    return reply({}, false, 404);
  };
  return { sessions, fetchImpl };
}

async function withRelay<T>(fn: (relay: ReturnType<typeof makeRelay>) => Promise<T>): Promise<T> {
  const relay = makeRelay();
  const original = globalThis.fetch;
  (globalThis as unknown as { fetch: unknown }).fetch = relay.fetchImpl;
  try { return await fn(relay); } finally { (globalThis as unknown as { fetch: unknown }).fetch = original; }
}

// ── Clients ────────────────────────────────────────────────────────────────────────────────────
function makeClient(fingerprint: string, consented: string[]) {
  const disclosed = new Map<string, string[]>();
  const deps: OrchestratorDeps = {
    getTrustedPeers: async () => consented.map((fp) => ({ fingerprint: fp })),
    getKnownPeers: async () => consented.map((fp) => ({ fingerprint: fp })),
    getTrustVisiblePeers: async () => [],
    applyMutualResult: async (peerFp, _layer, d) => { disclosed.set(peerFp, d); },
  };
  const options: PSISyncOptions = { satelliteUrl: 'http://relay', myFingerprint: fingerprint, signFn: () => new Uint8Array(64) };
  return { fingerprint, deps, options, disclosed };
}

const INIT = 'fp-initiator';
const RESP = 'fp-responder';
/** A responder that has consented to share `n` contacts in total: the initiator (needed to pass the consent gate) plus n-1 others. */
const responderWith = (n: number) => makeClient(RESP, [INIT, ...Array.from({ length: n - 1 }, (_, i) => `fp-r${i}`)]);

/** Initiator -> responder round; returns the relay's session so a test can read the set the responder sent. */
async function round(n: number, relayArg: ReturnType<typeof makeRelay>) {
  const initiator = makeClient(INIT, [RESP, 'fp-i1', 'fp-i2']);
  const responder = responderWith(n);
  const init = await initiateTrustSync(initiator.deps, RESP, initiator.options, 'know');
  if ('error' in init) throw new Error(`initiate failed: ${init.error}`);
  const answered = await respondToTrustSync(responder.deps, responder.options, 'know');
  return { init, initiator, responder, answered, session: relayArg.sessions.get(init.sessionId)! };
}

// ── The padding ─────────────────────────────────────────────────────────────────────────────────
for (const n of [1, 2, 17, 63, PSI_BLINDED_BUCKET_N]) {
  test(`the responder's set is exactly ${PSI_BLINDED_BUCKET_N} entries with ${n} consented contacts`, async () => {
    await withRelay(async (relay) => {
      const { session, answered } = await round(n, relay);
      assert.equal(answered.length, 1, 'the responder answered');
      assert.ok(session.responder_blinded_set, 'the relay received a responder set');
      assert.equal(session.responder_blinded_set!.length, PSI_BLINDED_BUCKET_N);
      assert.equal(new Set(session.responder_blinded_set).size, PSI_BLINDED_BUCKET_N, 'no repeated entries');
      assert.equal(new Set(session.responder_blinded_set!.map((s) => s.length)).size, 1, 'every entry has the same encoded length, padding or not');
    });
  });
}

test('the set size the relay sees does not change with the number of contacts', async () => {
  await withRelay(async (relay) => {
    const sizes: number[] = [];
    for (const n of [1, 9, 40]) {
      const { session } = await round(n, relay);
      sizes.push(session.responder_blinded_set!.length);
    }
    assert.deepEqual(sizes, [PSI_BLINDED_BUCKET_N, PSI_BLINDED_BUCKET_N, PSI_BLINDED_BUCKET_N]);
  });
});

test('padding does not change what is discovered: the shared contacts still come out exactly', async () => {
  await withRelay(async (relay) => {
    // initiator consents to {RESP, X, Y, Z}; responder consents to {INIT, Y, Z, W}. Shared third parties = {Y, Z}.
    const initiator = makeClient(INIT, [RESP, 'fp-x', 'fp-y', 'fp-z']);
    const responder = makeClient(RESP, [INIT, 'fp-y', 'fp-z', 'fp-w']);
    const init = await initiateTrustSync(initiator.deps, RESP, initiator.options, 'know');
    if ('error' in init) throw new Error(init.error);
    await respondToTrustSync(responder.deps, responder.options, 'know');
    const res = await completeTrustSync(initiator.deps, init.sessionId, RESP, init.keypair, initiator.options, init.fpOrder, 'know');
    if ('error' in res) throw new Error(res.error);
    assert.deepEqual([...(initiator.disclosed.get(RESP) ?? [])].sort(), ['fp-y', 'fp-z']);
    assert.equal(relay.sessions.get(init.sessionId)!.responder_blinded_set!.length, PSI_BLINDED_BUCKET_N);
  });
});

// ── Over the bucket ─────────────────────────────────────────────────────────────────────────────
test('a responder with more consented contacts than the bucket holds does not answer, and does not throw', async () => {
  await withRelay(async (relay) => {
    const { session, answered } = await round(PSI_BLINDED_BUCKET_N + 1, relay);
    assert.equal(answered.length, 0, 'no response was made');
    assert.equal(session.responder_blinded_set, undefined, 'the relay received no responder set (neither raw nor truncated)');
  });
});
