// src/lib/headless/know-psi.test.ts
//
// KNOW-layer PSI for a headless seat (S53). Run: npx tsx --test src/lib/headless/know-psi.test.ts
//
// What each group refutes (a property that PROTECTS someone, not "the code runs"):
//   - DEV-ONLY, FAIL CLOSED: no other satellite URL or pin passes; lookalike hosts do not pass; refusals happen before
//     any network call.
//   - the seat reaches the satellite only through the browser's bind + anti-swap-pin path, at the dev URL, with the
//     pinned dev key (a swapped key is rejected, a missing key fails closed).
//   - the two-seat run over a SEALED, ONE-SHOT-result mock relay, persisted through HeadlessStore between ticks:
//     exactly the consented intersection lands, and neither a one-sided consent nor a peer-only contact does.
//   - what a run may publish carries 8-hex prefixes and counts only.
// The mock relay below is the one from src/lib/trust/psi-flow-pq.integration.test.ts, copied verbatim, including its one-shot-result knob
// (that directory is code-owner fenced, so it is not edited or imported from here).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKey } from 'openpgp';
import { sealPsiToSatellite, openPsiFromSatellite, PINNED_SATELLITE_MAILBOX_FP_DEV } from '@/lib/crypto/psi-wire-seal';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf, type MailboxKeypair } from '@/lib/crypto/mailbox-keys';
import type { MailboxPublicKeys, MailboxEnvelopePackage } from '@/lib/crypto/mailbox-envelope';
import type { PSISyncOptions } from '@/lib/trust/mutual-trust-sync';
import type { SerializedMintArtifact } from '@/lib/identity/headless-mint';
import { HeadlessStore } from './headless-store';
import {
  DEV_SATELLITE_URL, KnowDevOnlyError, assertDevOnly, headlessKnowStore, headlessPsiOptions,
  runHeadlessKnowTick, tickCore, summarizeKnowState,
} from './know-psi';

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
  result_consumed?: boolean; // oneShotResult only: the first /result read marks the session complete
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

function makeRelay(satellite: MailboxKeypair, opts: { oneShotResult?: boolean } = {}) {
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
      // The REAL satellite (infra/svrnty/satellite.py psi_get_result) delivers a result EXACTLY ONCE: the first read marks
      // the session 'complete' whether or not the client could open what it was sealed to (Chaos #183).
      if (opts.oneShotResult) {
        if (s.result_consumed) return reply({ error: 'session complete' }, false, 410);
        s.result_consumed = true;
      }
      if (s.initiator_response_pub) {
        return reply(await sealPsiToSatellite(resultBody, pubKeysFromResponsePub(s.initiator_response_pub)));
      }
      return reply(resultBody);
    }

    return reply({}, false, 404);
  };

  return { sessions, log, fetchImpl };
}


// ── helpers for the cases below ─────────────────────────────────────────────────────────────────────────────────────
async function withRelay<T>(
  satellite: MailboxKeypair,
  fn: (relay: ReturnType<typeof makeRelay>) => Promise<T>,
): Promise<T> {
  const relay = makeRelay(satellite, { oneShotResult: true });
  const original = globalThis.fetch;
  (globalThis as unknown as { fetch: unknown }).fetch = relay.fetchImpl;
  try {
    return await fn(relay);
  } finally {
    (globalThis as unknown as { fetch: unknown }).fetch = original;
  }
}

const hex = (c: string) => c.repeat(64); // a 64-hex fingerprint
const SEAT_A = hex('a1'.slice(0, 1)), SEAT_B = hex('b');
const C1 = hex('c'), C2 = hex('d'), C3 = hex('e'), U_A = hex('1'), U_B = hex('2');

function book(opts: { consented: string[]; others: string[] }): HeadlessStore {
  const store = new HeadlessStore();
  for (const fp of [...new Set([...opts.consented, ...opts.others])]) {
    store.upsertContact({
      id: 'c-' + fp.slice(0, 8), fingerprint: fp, name: fp.slice(0, 8), public_key: 'PUB', trust_level: 'verified',
      open_visibility: opts.consented.includes(fp),
    });
  }
  return store;
}

// Drive the guarded core against the MOCK satellite: its key cannot equal the real pin, so the test supplies its own.
const tickMock = (owner: string, store: HeadlessStore, opts: PSISyncOptions, sat: MailboxKeypair) =>
  tickCore(owner, store, opts, { url: DEV_SATELLITE_URL, pin: mailboxFpOf(sat) });

function sealedOptions(owner: string, satellite: MailboxKeypair, url = DEV_SATELLITE_URL): PSISyncOptions {
  return { satelliteUrl: url, myFingerprint: owner, signFn: () => new Uint8Array(64), pqWrap: { satelliteKeys: toPublicKeys(satellite) } };
}

// ── DEV-ONLY, fail closed ───────────────────────────────────────────────────────────────────────────────────────────
test('assertDevOnly: the dev satellite + the pinned dev key pass (with or without a trailing slash)', () => {
  assertDevOnly(DEV_SATELLITE_URL, PINNED_SATELLITE_MAILBOX_FP_DEV);
  assertDevOnly(DEV_SATELLITE_URL + '/', PINNED_SATELLITE_MAILBOX_FP_DEV);
});

test('assertDevOnly: anything else is refused — prod, http, lookalike hosts, userinfo tricks, other paths, wrong pin, non-strings', () => {
  const bad = [
    'https://svrnty.is/api/satellite',                       // prod
    'http://dev.svrnty.is/api/satellite',                    // downgrade
    'https://dev.svrnty.is.evil.test/api/satellite',         // suffix lookalike
    'https://dev.svrnty.is@evil.test/api/satellite',         // userinfo trick
    'https://evil.test/https://dev.svrnty.is/api/satellite', // embedded
    'https://dev.svrnty.is/api/satellite/other',             // other path
    'https://dev.svrnty.is:8443/api/satellite',              // other port
    ' https://dev.svrnty.is/api/satellite',                  // whitespace
    '', 'dev.svrnty.is', undefined, null, 42,
  ];
  for (const u of bad) assert.throws(() => assertDevOnly(u, PINNED_SATELLITE_MAILBOX_FP_DEV), KnowDevOnlyError, `must refuse ${String(u)}`);
  for (const pin of ['', 'f'.repeat(64), PINNED_SATELLITE_MAILBOX_FP_DEV.toUpperCase(), PINNED_SATELLITE_MAILBOX_FP_DEV + ' ', undefined, null])
    assert.throws(() => assertDevOnly(DEV_SATELLITE_URL, pin), KnowDevOnlyError, `must refuse pin ${String(pin)}`);
});

test('runHeadlessKnowTick refuses a non-dev satellite, an unsealed wire and a foreign owner — BEFORE any network call', async () => {
  const sat = generateMailboxKeypair();
  let calls = 0;
  const original = globalThis.fetch;
  (globalThis as unknown as { fetch: unknown }).fetch = async () => { calls++; throw new Error('network must not be touched'); };
  try {
    const store = book({ consented: [SEAT_B], others: [] });
    await assert.rejects(runHeadlessKnowTick(SEAT_A, store, sealedOptions(SEAT_A, sat, 'https://svrnty.is/api/satellite')), KnowDevOnlyError);
    await assert.rejects(runHeadlessKnowTick(SEAT_A, store, { ...sealedOptions(SEAT_A, sat), pqWrap: undefined }), KnowDevOnlyError);
    await assert.rejects(tickMock(SEAT_A, store, sealedOptions(SEAT_B, sat), sat), /not the owner/);
  } finally {
    (globalThis as unknown as { fetch: unknown }).fetch = original;
  }
  assert.equal(calls, 0);
});

// ── the seat's options: the browser's bind + pin path, at the dev URL only ──────────────────────────────────────────
let armored: { privateKey: string; passphrase: string } | null = null;
async function artifact(): Promise<SerializedMintArtifact> {
  if (!armored) {
    const passphrase = 'know-psi-test-pass';
    const g = (await generateKey({ type: 'ecc', curve: 'ed25519', userIDs: [{ name: 'Seat', email: 'seat@example.test' }], passphrase, format: 'armored' } as unknown as Parameters<typeof generateKey>[0])) as unknown as { privateKey: string };
    armored = { privateKey: g.privateKey, passphrase };
  }
  return { public: { durable_id: SEAT_A }, private: { classical_private_key: armored.privateKey, classical_kpass: armored.passphrase } } as unknown as SerializedMintArtifact;
}

function spyFetch(satelliteKeyBody: Record<string, string> | null) {
  const urls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    urls.push(`${init?.method ?? 'GET'} ${url}`);
    if (url.includes('/trust/psi/satellite-key')) {
      return satelliteKeyBody ? new Response(JSON.stringify(satelliteKeyBody), { status: 200 }) : new Response('nope', { status: 404 });
    }
    return new Response(JSON.stringify({ status: 'bound' }), { status: 200 });
  }) as typeof fetch;
  return { fetchImpl, urls };
}

test('headlessPsiOptions: an artifact without signing material yields null and touches no network', async () => {
  const { fetchImpl, urls } = spyFetch(null);
  assert.equal(await headlessPsiOptions({ public: {}, private: {} } as unknown as SerializedMintArtifact, { fetchImpl }), null);
  assert.equal(await headlessPsiOptions(undefined as unknown as SerializedMintArtifact, { fetchImpl }), null);
  assert.deepEqual(urls, []);
});

test('headlessPsiOptions: binds with the artifact key at the DEV URL only, and fails CLOSED when the satellite key is missing', async () => {
  const { fetchImpl, urls } = spyFetch(null);
  assert.equal(await headlessPsiOptions(await artifact(), { fetchImpl }), null, 'no satellite key => no options (never an unsealed wire)');
  assert.ok(urls.some((u) => u.startsWith(`POST ${DEV_SATELLITE_URL}/bind`)), `it bound at the dev URL: ${urls.join(' | ')}`);
  assert.ok(urls.every((u) => u.split(' ')[1].startsWith(DEV_SATELLITE_URL + '/')), `every request stays on the dev satellite: ${urls.join(' | ')}`);
});

test('headlessPsiOptions: a satellite key that is NOT the pinned dev key is rejected (anti-swap), options are null', async () => {
  const swapped = generateMailboxKeypair();
  const pub = toPublicKeys(swapped);
  const body = {
    x25519_pk: Buffer.from(pub.x25519Pub).toString('hex'),
    mlkem1024_pk: Buffer.from(pub.mlkem1024Pub).toString('hex'),
    mailbox_fp: mailboxFpOf(swapped),
  };
  assert.notEqual(body.mailbox_fp, PINNED_SATELLITE_MAILBOX_FP_DEV);
  const { fetchImpl } = spyFetch(body);
  assert.equal(await headlessPsiOptions(await artifact(), { fetchImpl }), null);
});

// Flint #453: the tick must refuse options whose satellite key is not the PINNED dev key, however they were built.
test('runHeadlessKnowTick refuses a sealed wire to ANY satellite key but the pinned dev key, before any network call', async () => {
  const other = generateMailboxKeypair();   // a perfectly valid key pair that is simply not the dev satellite's
  let calls = 0;
  const original = globalThis.fetch;
  (globalThis as unknown as { fetch: unknown }).fetch = async () => { calls++; throw new Error('network must not be touched'); };
  try {
    const store = book({ consented: [SEAT_B], others: [] });
    const opts = sealedOptions(SEAT_A, other);                       // dev URL, sealed, owner right, WRONG key
    await assert.rejects(runHeadlessKnowTick(SEAT_A, store, opts), (e: unknown) => e instanceof KnowDevOnlyError && /pinned dev key/.test((e as Error).message));
    // a truncated / malformed key must not slip through either
    const bad = { ...opts, pqWrap: { satelliteKeys: { x25519Pub: new Uint8Array(8), mlkem1024Pub: new Uint8Array(8) } } } as PSISyncOptions;
    await assert.rejects(runHeadlessKnowTick(SEAT_A, store, bad), KnowDevOnlyError);
  } finally {
    (globalThis as unknown as { fetch: unknown }).fetch = original;
  }
  assert.equal(calls, 0);
});

test('CONTROL: the same options pass the core when its pin names that key (so the refusal above is the pin, not something else)', async () => {
  const sat = generateMailboxKeypair();
  await withRelay(sat, async () => {
    const store = book({ consented: [SEAT_B], others: [] });
    const r = await tickMock(SEAT_A, store, sealedOptions(SEAT_A, sat), sat);   // must not throw KnowDevOnlyError
    assert.ok(r.initiated.length >= 1);
  });
});

test('tickCore (the target-taking core) is imported by nothing in the app, only by this module and tests', () => {
  const root = new URL('../../../', import.meta.url).pathname;
  const hits: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === 'node_modules' || e.name === '.next' || e.name === '.git') continue;
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(ts|tsx|mjs|js)$/.test(e.name) && !/\.test\.(ts|tsx)$/.test(e.name) && !/\.spec\./.test(e.name) && /\btickCore\b/.test(readFileSync(p, 'utf8'))) hits.push(p.slice(root.length));
    }
  };
  for (const d of ['src', 'app', 'scripts']) { try { walk(join(root, d)); } catch { /* dir absent */ } }
  assert.deepEqual(hits, ['src/lib/headless/know-psi.ts'], `tickCore must stay internal; found in: ${hits.join(', ')}`);
});

// ── the store adapter ──────────────────────────────────────────────────────────────────────────────────────────────
test('headlessKnowStore: reads the book, applies patches, and a patch to undefined clears the field', async () => {
  const store = book({ consented: [SEAT_B], others: [] });
  const kos = headlessKnowStore(store);
  const [c] = await kos.getAllContacts(SEAT_A);
  assert.equal(c.fingerprint, SEAT_B);
  await kos.updateContact(c.id, { psi_session_id: 's1', psi_sk_A: 'sk' } as never);
  assert.equal(store.listContacts()[0].psi_session_id, 's1');
  await kos.updateContact(c.id, { psi_session_id: undefined, psi_sk_A: undefined } as never);
  assert.equal(store.listContacts()[0].psi_sk_A, undefined);
  await assert.rejects(kos.updateContact('no-such-id', {} as never), /not found/);
});

// ── the two-seat run: sealed wire, one-shot result, state persisted in HeadlessStore between ticks ───────────────────
test('two seats over the sealed one-shot relay: A learns EXACTLY the consented intersection {C1,C2}', async () => {
  const sat = generateMailboxKeypair();
  await withRelay(sat, async () => {
    // A consents to B, C1, C2, C3 and holds U_A; B consents to A, C1, C2, U_B and holds C3 WITHOUT consent.
    const a = book({ consented: [SEAT_B, C1, C2, C3], others: [U_A] });
    const b = book({ consented: [SEAT_A, C1, C2, U_B], others: [C3] });
    const optA = sealedOptions(SEAT_A, sat), optB = sealedOptions(SEAT_B, sat);

    const a1 = await tickMock(SEAT_A, a, optA, sat); // A initiates toward B and persists the session
    assert.ok(a1.initiated.length >= 1, 'A initiated');
    assert.ok(summarizeKnowState(a).some((r) => r.peer === SEAT_B.slice(0, 8) && r.sessionInFlight), 'the in-flight session survives in the store');
    const firstSession = a.getContactByFingerprint(SEAT_B)!.psi_session_id;
    await tickMock(SEAT_B, b, optB, sat);            // B responds (and initiates toward A)
    await tickMock(SEAT_A, a, optA, sat);            // A completes on a LATER tick, from persisted state only

    const forB = a.getContactByFingerprint(SEAT_B)!;
    assert.deepEqual([...(forB.disclosed_circle as string[])].sort(), [C1, C2].sort(), 'exactly the consented intersection');
    // The tick that completed the session also re-initiates (as the browser loop does), so what is left on the record
    // is a NEW session with its own response key; the completed one is gone.
    assert.notEqual(forB.psi_session_id, firstSession, 'the completed session was replaced, not kept');
    assert.ok(![C3, U_A, U_B].some((x) => (forB.disclosed_circle as string[]).includes(x)), 'one-sided consent and peer-only contacts never appear');
  });
});

test('revocation: when A withdraws consent for B, the next tick clears B\'s circle and any session (forward-revocation)', async () => {
  const sat = generateMailboxKeypair();
  await withRelay(sat, async () => {
    const a = book({ consented: [SEAT_B, C1], others: [] });
    const b = book({ consented: [SEAT_A, C1], others: [] });
    const optA = sealedOptions(SEAT_A, sat), optB = sealedOptions(SEAT_B, sat);
    await tickMock(SEAT_A, a, optA, sat); await tickMock(SEAT_B, b, optB, sat); await tickMock(SEAT_A, a, optA, sat);
    assert.deepEqual(a.getContactByFingerprint(SEAT_B)!.disclosed_circle, [C1], 'control: it landed first');
    a.updateContact(a.getContactByFingerprint(SEAT_B)!.id, { open_visibility: false });
    await tickMock(SEAT_A, a, optA, sat);
    assert.deepEqual(a.getContactByFingerprint(SEAT_B)!.disclosed_circle ?? [], []);
  });
});

// ── what a run may publish ─────────────────────────────────────────────────────────────────────────────────────────
test('summarizeKnowState carries 8-hex prefixes and counts only — no full fingerprint anywhere in what a run publishes', () => {
  const store = book({ consented: [SEAT_B, C1], others: [U_A] });
  store.updateContact(store.getContactByFingerprint(SEAT_B)!.id, { disclosed_circle: [C1, C2], psi_session_id: 'sess-secret', psi_sk_A: 'SECRET-SCALAR' });
  const rows = summarizeKnowState(store);
  const json = JSON.stringify(rows);
  for (const fp of [SEAT_A, SEAT_B, C1, C2, C3, U_A, U_B]) assert.ok(!json.includes(fp), `full fingerprint leaked: ${fp.slice(0, 8)}…`);
  assert.ok(!json.includes('SECRET-SCALAR') && !json.includes('sess-secret'), 'no session id or key material');
  const b = rows.find((r) => r.peer === SEAT_B.slice(0, 8))!;
  assert.deepEqual(b, { peer: SEAT_B.slice(0, 8), consented: true, sessionInFlight: true, disclosed: 2, disclosedPeers: [C1.slice(0, 8), C2.slice(0, 8)].sort() });
  assert.ok(!rows.some((r) => r.peer === U_A.slice(0, 8)), 'a contact with no consent, session or circle is not listed');
});
