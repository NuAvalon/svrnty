// src/lib/trust/psi-flow-pq.integration.test.ts
//
// PQ-wrap wire-in adversarial co-verify (Apollo client-half, branch apollo/psi-wire-seal).
// psi-flow.integration.test.ts locks the CLASSICAL plaintext DH-PSI wire + intersection math.
// This file locks the SAME flow with PSISyncOptions.pqWrap set — i.e. the future
// isPSIDiscoveryLive=true wire — through a mock relay that seals/opens exactly like a real satellite
// would (Athena's satellite-side decap, mirrored here with the same psi-wire-seal.ts primitives the
// client uses). Each test refutes a property that PROTECTS the person, not "the flow runs":
//   - the WIRE carries no plaintext blinded data once pqWrap is set                [Peter's deploy gate]
//   - the PQ-wrapped flow still finds the exact same intersection as classical      [no regression]
//   - exchange 2 (pending) stays UNSEALED metadata-only, no response_pub query leak [Athena/Apollo 2026-10-02 correction]
//   - exchange 3 (get_blinded) is a POST with EXACTLY {responder_fingerprint,
//     signature, response_pub} sealed, registering a fresh PER-SESSION key          [locked contract]
//   - exchange 4 (respond) seals EXACTLY the 5 pinned fields, no response_pub/session_id leak
//   - exchange 1 (initiate) seals the pinned fields + response_pub (the initiator's first touch)
//   - a tampered / wrong-key sealed response fails CLOSED (session skipped), never throws, never
//     silently "succeeds" with garbage
//
// Run: npx tsx --test src/lib/trust/psi-flow-pq.integration.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  initiateTrustSync,
  respondToTrustSync,
  completeTrustSync,
  type OrchestratorDeps,
  type PSISyncOptions,
} from './mutual-trust-sync.js';
import { sealPsiToSatellite, openPsiFromSatellite } from '../crypto/psi-wire-seal.js';
import {
  generateMailboxKeypair,
  toPublicKeys,
  toSecretKeys,
  mailboxFpOf,
  type MailboxKeypair,
} from '../crypto/mailbox-keys.js';
import type { MailboxPublicKeys, MailboxEnvelopePackage } from '../crypto/mailbox-envelope.js';

// ── helpers ─────────────────────────────────────────────────────────────────────────────────────
type ResponsePub = { x25519_pub_b64: string; mlkem1024_pub_b64: string; mailbox_fp: string };

function pubKeysFromResponsePub(rp: ResponsePub): MailboxPublicKeys {
  return {
    x25519Pub: new Uint8Array(Buffer.from(rp.x25519_pub_b64, 'base64')),
    mlkem1024Pub: new Uint8Array(Buffer.from(rp.mlkem1024_pub_b64, 'base64')),
  };
}

function isEnvelope(x: unknown): x is MailboxEnvelopePackage {
  return !!x && typeof x === 'object' && (x as Record<string, unknown>).v === 1 &&
    typeof (x as Record<string, unknown>).alg === 'string';
}

// ── Mock satellite relay — handles BOTH classical plaintext and PQ-sealed wire shapes on the exact
// same endpoints (driven only by what the client actually sends), mirroring how a real satellite
// would branch. Stores + forwards; computes no intersection (stays blind).
interface RelaySession {
  session_id: string;
  initiator_fp: string;
  responder_fp: string;
  initiator_blinded_set: string[];
  created_at: number;
  initiator_response_pub?: ResponsePub; // registered at initiate (PQ only)
  responder_blinded_set?: string[];
  reblinded_initiator_set?: string[];
}
interface MockResponse {
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
  text: () => Promise<string>;
}
interface WireLogEntry {
  path: string;
  method: string;
  rawBody?: unknown;
  opened?: Record<string, unknown>;
}

function makeRelay(satellite: MailboxKeypair) {
  const sessions = new Map<string, RelaySession>();
  const log: WireLogEntry[] = [];
  let seq = 0;
  const reply = (obj: unknown, ok = true, status = 200): MockResponse => ({
    ok,
    status,
    json: async () => obj,
    text: async () => JSON.stringify(obj),
  });

  async function openIfSealed(raw: unknown): Promise<Record<string, unknown> | null> {
    if (!isEnvelope(raw)) return raw as Record<string, unknown>;
    const opened = await openPsiFromSatellite(raw, toSecretKeys(satellite), mailboxFpOf(satellite));
    return (opened as Record<string, unknown>) ?? null;
  }

  const fetchImpl = async (
    url: string,
    init?: { method?: string; body?: string },
  ): Promise<MockResponse> => {
    const { pathname, search } = new URL(url);
    const method = init?.method ?? 'GET';
    const rawBody = init?.body ? JSON.parse(init.body) : undefined;

    if (pathname.endsWith('/trust/psi/initiate') && method === 'POST') {
      const b = await openIfSealed(rawBody);
      log.push({ path: 'initiate', method, rawBody, opened: b ?? undefined });
      if (!b) return reply({ error: 'bad seal' }, false, 400);
      const session_id = `pq-sess-${++seq}`;
      sessions.set(session_id, {
        session_id,
        initiator_fp: b.initiator_fingerprint as string,
        responder_fp: b.responder_fingerprint as string,
        initiator_blinded_set: b.blinded_set as string[],
        created_at: Math.floor(Date.now() / 1000),
        initiator_response_pub: b.response_pub as ResponsePub | undefined,
      });
      return reply({ session_id });
    }

    const pend = pathname.match(/\/trust\/psi\/pending\/(.+)$/);
    if (pend && method === 'GET') {
      log.push({ path: 'pending', method, rawBody: search || '(no query)' });
      const fp = decodeURIComponent(pend[1]!);
      // Exchange 2 (Athena/Apollo correction, 2026-10-02): metadata-only, UNSEALED, satellite's actual
      // field names ({sessions:[...]} / initiator_fingerprint) — proves psiPending's normalization.
      const sessions_out = [...sessions.values()]
        .filter((s) => s.responder_fp === fp && !s.responder_blinded_set)
        .map((s) => ({ session_id: s.session_id, initiator_fingerprint: s.initiator_fp, created_at: s.created_at }));
      return reply({ sessions: sessions_out });
    }

    const bl = pathname.match(/\/trust\/psi\/session\/([^/]+)\/blinded$/);
    if (bl && (method === 'GET' || method === 'POST')) {
      const s = sessions.get(bl[1]!);
      if (!s) return reply({}, false, 404);
      let responsePub: ResponsePub | undefined;
      if (method === 'POST') {
        const b = await openIfSealed(rawBody);
        log.push({ path: 'get_blinded', method, rawBody, opened: b ?? undefined });
        if (!b) return reply({}, false, 400);
        responsePub = b.response_pub as ResponsePub;
      } else {
        log.push({ path: 'get_blinded', method, rawBody: search });
      }
      const respBody = { blinded_set: s.initiator_blinded_set };
      if (responsePub) {
        return reply(await sealPsiToSatellite(respBody, pubKeysFromResponsePub(responsePub)));
      }
      return reply(respBody);
    }

    const rp = pathname.match(/\/trust\/psi\/session\/([^/]+)\/respond$/);
    if (rp && method === 'POST') {
      const s = sessions.get(rp[1]!);
      if (!s) return reply({}, false, 404);
      const b = await openIfSealed(rawBody);
      log.push({ path: 'respond', method, rawBody, opened: b ?? undefined });
      if (!b) return reply({}, false, 400);
      s.responder_blinded_set = (b.responder_blinded_set ?? b.blinded_set) as string[];
      s.reblinded_initiator_set = b.reblinded_initiator_set as string[];
      return reply({ ok: true });
    }

    const rs = pathname.match(/\/trust\/psi\/session\/([^/]+)\/result$/);
    if (rs && method === 'GET') {
      const s = sessions.get(rs[1]!);
      if (!s || !s.responder_blinded_set) return reply({}, false, 404);
      const resultBody = {
        responder_blinded_set: s.responder_blinded_set,
        reblinded_initiator_set: s.reblinded_initiator_set,
      };
      log.push({ path: 'result', method, rawBody: '(GET, no body)' });
      if (s.initiator_response_pub) {
        return reply(await sealPsiToSatellite(resultBody, pubKeysFromResponsePub(s.initiator_response_pub)));
      }
      return reply(resultBody);
    }

    return reply({}, false, 404);
  };

  return { sessions, log, fetchImpl };
}

// ── Client harness (mirrors psi-flow.integration.test.ts) ─────────────────────────────────────────
interface Contact {
  fp: string;
  consented: boolean;
}

function makeClient(fingerprint: string, book: Contact[], satelliteKeys?: MailboxPublicKeys) {
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
    signFn: () => new Uint8Array(64),
    ...(satelliteKeys ? { pqWrap: { satelliteKeys } } : {}),
  };
  return { fingerprint, deps, options, disclosedByPeer };
}
type Client = ReturnType<typeof makeClient>;

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
    init.pqSession,
  );
  if ('error' in res) throw new Error(`complete failed: ${res.error}`);
  return [...(initiator.disclosedByPeer.get(responder.fingerprint) ?? [])].sort();
}

async function withRelay<T>(
  satellite: MailboxKeypair,
  fn: (relay: ReturnType<typeof makeRelay>) => Promise<T>,
): Promise<T> {
  const relay = makeRelay(satellite);
  const original = globalThis.fetch;
  (globalThis as unknown as { fetch: unknown }).fetch = relay.fetchImpl;
  try {
    return await fn(relay);
  } finally {
    (globalThis as unknown as { fetch: unknown }).fetch = original;
  }
}

const A = 'fp-alice';
const B = 'fp-bob';
const X = 'fp-xavier';
const Y = 'fp-yara';
const Z = 'fp-zed';
const W = 'fp-wren';

// ── Tests ───────────────────────────────────────────────────────────────────────────────────────

test('(gate + POSITIVE CONTROL) PQ wrap: no plaintext blinded data on the wire; classical control leaks it', async () => {
  const satellite = generateMailboxKeypair();
  const satelliteKeys = toPublicKeys(satellite);

  // PQ-wrapped round.
  const pqWires = await withRelay(satellite, async (relay) => {
    const alice = makeClient(A, [B, Y, Z].map((fp) => ({ fp, consented: true })), satelliteKeys);
    const bob = makeClient(B, [A, Y, Z, W].map((fp) => ({ fp, consented: true })), satelliteKeys);
    await runRound(alice, bob);
    return relay.log.map((e) => JSON.stringify(e.rawBody ?? ''));
  });
  const blindedPoint = /[A-Za-z0-9+/]{40,}={0,2}/; // any sizeable base64 blob is suspect
  // The ONLY thing allowed to look like base64 on a sealed wire is the envelope's own ct/epk/kem_ct —
  // so assert instead that none of the wire bodies contain a JSON array under a `blinded_set` key.
  for (const w of pqWires) {
    assert.ok(!w.includes('"blinded_set"'), `PQ wire must not carry a plaintext "blinded_set" key: ${w.slice(0, 120)}`);
  }

  // POSITIVE CONTROL: the SAME scenario WITHOUT pqWrap DOES leak "blinded_set" in the clear — proves
  // the assertion above is actually discriminating, not vacuously true.
  const classicalWires = await withRelay(satellite, async (relay) => {
    const alice = makeClient(A, [B, Y, Z].map((fp) => ({ fp, consented: true })));
    const bob = makeClient(B, [A, Y, Z, W].map((fp) => ({ fp, consented: true })));
    await runRound(alice, bob);
    return relay.log.map((e) => JSON.stringify(e.rawBody ?? ''));
  });
  assert.ok(
    classicalWires.some((w) => w.includes('"blinded_set"')),
    'control: classical (pqWrap absent) wire DOES carry plaintext blinded_set',
  );
  void blindedPoint;
});

test('(correctness) PQ-wrapped flow discovers the EXACT SAME intersection as classical', async () => {
  const satellite = generateMailboxKeypair();
  const satelliteKeys = toPublicKeys(satellite);
  const disclosed = await withRelay(satellite, async () => {
    const alice = makeClient(A, [B, X, Y, Z].map((fp) => ({ fp, consented: true })), satelliteKeys);
    const bob = makeClient(B, [A, Y, Z, W].map((fp) => ({ fp, consented: true })), satelliteKeys);
    return runRound(alice, bob);
  });
  assert.deepEqual(disclosed, [Y, Z].sort(), 'PQ wrap must not change the intersection result');
  assert.equal(disclosed.includes(A), false);
  assert.equal(disclosed.includes(B), false);
});

test('(contract) exchange 2 (pending) is UNSEALED and carries no response_pub query under pqWrap', async () => {
  const satellite = generateMailboxKeypair();
  const satelliteKeys = toPublicKeys(satellite);
  const pendingCalls = await withRelay(satellite, async (relay) => {
    const alice = makeClient(A, [B, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    const bob = makeClient(B, [A, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    await runRound(alice, bob);
    return relay.log.filter((e) => e.path === 'pending');
  });
  assert.equal(pendingCalls.length, 1, 'exactly one pending GET per responder tick');
  // No response_pub_* ever rides the pending query string (would have leaked an ML-KEM pubkey, ~2KB).
  assert.equal(pendingCalls[0]!.rawBody, '(no query)');
});

test('(contract) exchange 3 (get_blinded) is a POST with EXACTLY {responder_fingerprint, signature, response_pub}', async () => {
  const satellite = generateMailboxKeypair();
  const satelliteKeys = toPublicKeys(satellite);
  const opened = await withRelay(satellite, async (relay) => {
    const alice = makeClient(A, [B, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    const bob = makeClient(B, [A, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    await runRound(alice, bob);
    return relay.log.find((e) => e.path === 'get_blinded' && e.opened)?.opened;
  });
  assert.ok(opened, 'get_blinded must have been sealed (POST) under pqWrap');
  assert.deepEqual(
    Object.keys(opened!).sort(),
    ['responder_fingerprint', 'response_pub', 'signature'].sort(),
    'get_blinded sealed body must be exactly {responder_fingerprint, signature, response_pub}',
  );
});

test('(contract) exchange 4 (respond) seals EXACTLY the 5 pinned fields, no response_pub/session_id leak', async () => {
  const satellite = generateMailboxKeypair();
  const satelliteKeys = toPublicKeys(satellite);
  const opened = await withRelay(satellite, async (relay) => {
    const alice = makeClient(A, [B, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    const bob = makeClient(B, [A, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    await runRound(alice, bob);
    return relay.log.find((e) => e.path === 'respond')?.opened;
  });
  assert.ok(opened, 'respond must have been sealed under pqWrap');
  assert.deepEqual(
    Object.keys(opened!).sort(),
    [
      'initiator_fingerprint',
      'responder_fingerprint',
      'signature',
      'responder_blinded_set',
      'reblinded_initiator_set',
    ].sort(),
    'respond sealed body must be EXACTLY the pinned 5 fields — no response_pub, no session_id',
  );
});

test('(contract) exchange 1 (initiate) seals the pinned fields + response_pub (initiator first touch)', async () => {
  const satellite = generateMailboxKeypair();
  const satelliteKeys = toPublicKeys(satellite);
  const opened = await withRelay(satellite, async (relay) => {
    const alice = makeClient(A, [B, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    const bob = makeClient(B, [A, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    await runRound(alice, bob);
    return relay.log.find((e) => e.path === 'initiate')?.opened;
  });
  assert.ok(opened, 'initiate must have been sealed under pqWrap');
  const keys = new Set(Object.keys(opened!));
  for (const k of ['initiator_fingerprint', 'responder_fingerprint', 'signature', 'blinded_set', 'response_pub']) {
    assert.ok(keys.has(k), `initiate sealed body must contain pinned field "${k}"`);
  }
});

test('(adversarial) a TAMPERED get_blinded response fails CLOSED — session skipped, never throws', async () => {
  const satellite = generateMailboxKeypair();
  const satelliteKeys = toPublicKeys(satellite);
  await withRelay(satellite, async (relay) => {
    // Wrap fetch so the get_blinded POST response ct gets flipped before it reaches the client.
    const inner = relay.fetchImpl;
    (globalThis as unknown as { fetch: unknown }).fetch = async (url: string, init?: { method?: string; body?: string }) => {
      const res = await inner(url, init);
      if (new URL(url).pathname.endsWith('/blinded') && init?.method === 'POST') {
        const obj = (await res.json()) as Record<string, unknown>;
        if (typeof obj.ct === 'string') {
          const bytes = Buffer.from(obj.ct, 'base64');
          bytes[0] = (bytes[0] ?? 0) ^ 0xff; // flip a byte → GCM tag check must fail
          obj.ct = bytes.toString('base64');
        }
        return { ok: res.ok, status: res.status, json: async () => obj, text: async () => JSON.stringify(obj) };
      }
      return res;
    };

    const alice = makeClient(A, [B, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    const bob = makeClient(B, [A, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    await initiateTrustSync(alice.deps, B, alice.options, 'know');
    // Must not throw — openPsiSessionResponse's null-not-throw contract must survive the wiring.
    const responses = await respondToTrustSync(bob.deps, bob.options, 'know');
    assert.deepEqual(responses, [], 'tampered sealed response → responder participates in nothing, fails closed');
  });
});

test('(adversarial) get_blinded sealed to the WRONG session key cannot be opened by the real client', async () => {
  const satellite = generateMailboxKeypair();
  const satelliteKeys = toPublicKeys(satellite);
  await withRelay(satellite, async (relay) => {
    const inner = relay.fetchImpl;
    const attackerKeypair = generateMailboxKeypair();
    (globalThis as unknown as { fetch: unknown }).fetch = async (url: string, init?: { method?: string; body?: string }) => {
      if (new URL(url).pathname.endsWith('/blinded') && init?.method === 'POST') {
        // Re-seal the (correct) blinded_set to an UNRELATED keypair instead of the registered
        // response_pub — simulates a relay bug / MITM that lost the binding.
        const raw = JSON.parse(init.body!);
        const opened = await openPsiFromSatellite(raw, toSecretKeys(satellite), mailboxFpOf(satellite));
        if (!opened) return { ok: false, status: 400, json: async () => ({}), text: async () => '{}' };
        const anySession = [...relay.sessions.values()][0]!;
        const misSealed = await sealPsiToSatellite(
          { blinded_set: anySession.initiator_blinded_set },
          toPublicKeys(attackerKeypair),
        );
        return { ok: true, status: 200, json: async () => misSealed, text: async () => JSON.stringify(misSealed) };
      }
      return inner(url, init);
    };

    const alice = makeClient(A, [B, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    const bob = makeClient(B, [A, Y].map((fp) => ({ fp, consented: true })), satelliteKeys);
    await initiateTrustSync(alice.deps, B, alice.options, 'know');
    const responses = await respondToTrustSync(bob.deps, bob.options, 'know');
    assert.deepEqual(responses, [], 'wrong-key sealed response → open fails → fail-closed, no participation');
  });
});
