// src/lib/relay/owner-route-guards.test.ts
// Owner-route abuse guards (availability, rated HIGH): the poll / ack / claim routes had NO rate limiter, and a signed owner
// request was accepted again and again inside its freshness window (no nonce store). A key costs nothing to make, so one
// requester could replay one header to make every request cost the relay a full signature verify for free.
// Guards pinned here:
//   (a) a per-IP limiter at the TOP of queue/ack/claim, before any decode or verify, answering a uniform 429;
//   (b) a replay cache on (mailbox_id, nonce) for the freshness window, for v1 owner auth: a replay gets the SAME 401 as a non-owner.
//       Full → fail OPEN, logged;
//   (c) v2 (mbx2_) owner requests refused with the uniform non-owner 401 unless RELAY_OWNER_V2_ENABLED is set, before any signature check;
//   and IPv6 budgets keyed by /64.
// Required NEGs: replay → same 401 shape as a non-owner; N+1 requests from one IP → 429 before any verify (a counting test);
// the 429 does not depend on whether the mailbox exists.
//
// Run: npx tsx --test src/lib/relay/owner-route-guards.test.ts

process.env.RELAY_DB_PATH = ':memory:';
import { test, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { mintCanonicalFingerprint } from '@/lib/identity/fingerprint';
import { depositEnvelope, resetMailboxStore } from './mailbox-store';
import { deriveMailboxId, signMailboxPollRequest, signMailboxAckRequest } from './mailbox-auth';
import { generateMailboxAuthKeypair, signOwnerRequestV2, deriveMailboxIdV2, type MailboxAuthKeypair } from './mailbox-auth-v2';
import { resetDeposit429Counts } from './deposit-429-log';
import { budgetKeyOf, checkOwnerRouteBudget } from './owner-route-budget';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { OWNER_AUTH_HEADER } from './mailbox-auth';
import { CLIENT_IP_HEADER } from './client-ip';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { HeadlessStore } from '@/lib/headless/headless-store';
import { pollHeadlessOnce } from '@/lib/headless/headless-client';

// The guard modules are new: load them softly, so on the old code these tests fail on BEHAVIOUR, not on an import.
type Resettable = { [k: string]: unknown };
let limiterMod: Resettable | null = null;
let replayMod: Resettable | null = null;
function resetGuards() {
  (limiterMod?.resetOwnerRouteBudgets as (() => void) | undefined)?.();
  (replayMod?.resetOwnerReplayCache as (() => void) | undefined)?.();
}

interface Canon { fp: string; pub: string; priv: string; pass: string; kemB64: string; sigB64: string }
async function mkCanon(name: string): Promise<Canon> {
  const pass = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase: pass,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return { fp: fingerprint, pub: publicKey, priv: privateKey, pass, kemB64: uint8ToBase64(pq.kem.publicKey), sigB64: uint8ToBase64(pq.signing.publicKey) };
}
const v1Args = (c: Canon) => ({ fingerprint: c.fp, publicKeyArmored: c.pub, privateKeyArmored: c.priv, passphrase: c.pass, kemPublicKey: c.kemB64, sigPublicKey: c.sigB64 });

const routeDir = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'app', 'api', 'relay');

let OWNER: Canon;
let V2: MailboxAuthKeypair;
before(async () => {
  limiterMod = await import('./owner-route-budget').catch(() => null);
  replayMod = await import('./owner-replay-cache').catch(() => null);
  OWNER = await mkCanon('owner');
  V2 = generateMailboxAuthKeypair();
});
beforeEach(() => {
  resetMailboxStore();
  resetGuards();
  resetDeposit429Counts();
  for (const k of ['RELAY_OWNER_RATE_LIMIT_MAX', 'RELAY_OWNER_RATE_LIMIT_WINDOW_MS', 'RELAY_REPLAY_CACHE_MAX', 'RELAY_OWNER_RATE_LIMIT_IP_CAP', 'RELAY_OWNER_V2_ENABLED', 'INVITE_REQUIRED']) delete process.env[k];
});

const routes = async () => ({
  queue: (await import('../../../app/api/relay/queue/route')).GET,
  ack: (await import('../../../app/api/relay/ack/route')).POST,
  envelope: (await import('../../../app/api/relay/envelope/route')).POST,
  claim: (await import('../../../app/api/relay/claim/route')).POST,
});
const ipHeaders = (ip: string, extra: Record<string, string> = {}) => ({ [CLIENT_IP_HEADER]: ip, ...extra });
const queueReq = (mailboxId: string, ip: string, auth: Record<string, string> = {}) =>
  new Request(`http://r.test/api/relay/queue?mailbox_id=${encodeURIComponent(mailboxId)}`, { headers: ipHeaders(ip, auth) });
const ackReq = (mailboxId: string, ids: string[], ip: string, auth: Record<string, string> = {}) =>
  new Request('http://r.test/api/relay/ack', { method: 'POST', headers: ipHeaders(ip, { 'content-type': 'application/json', ...auth }), body: JSON.stringify({ mailbox_id: mailboxId, envelope_ids: ids }) });
const claimReq = (ip: string) =>
  new Request('http://r.test/api/relay/claim', { method: 'POST', headers: ipHeaders(ip, { 'content-type': 'application/json' }), body: JSON.stringify({ token: 'x' }) });
async function snap(res: Response) { return { status: res.status, body: await res.text() }; }

// ---------------- (a) per-IP limiter ----------------

test('A1 N+1: the (N+1)th owner-route request from one IP is 429, even carrying a VALID signature for a non-empty mailbox', async () => {
  process.env.RELAY_OWNER_RATE_LIMIT_MAX = '3';
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  depositEnvelope(mbx, 'SECRET-BLOB', Date.now());
  for (let i = 0; i < 3; i++) assert.equal((await queue(queueReq(mbx, '198.51.100.7'))).status, 401, `request ${i + 1}: unauthenticated → 401`);
  const auth = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
  const r = await snap(await queue(queueReq(mbx, '198.51.100.7', auth)));
  assert.equal(r.status, 429, 'the 4th request is refused by the limiter');
  assert.ok(!r.body.includes('SECRET-BLOB'), 'a refused request never reaches the store');
});

test('A2 counting: a limited request never reaches a verifier: its signed bundle stays unused', async () => {
  process.env.RELAY_OWNER_RATE_LIMIT_MAX = '1';
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  const auth = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
  assert.equal((await queue(queueReq(mbx, '198.51.100.8'))).status, 401);
  // Bound by construction: the route reads the limiter BEFORE it parses the URL or any header. A limited request with a valid
  // bundle is still 429, and its bundle stays unused: sending it from another IP afterwards is accepted ONCE (it was never seen).
  assert.equal((await queue(queueReq(mbx, '198.51.100.8', auth))).status, 429);
  assert.equal((await queue(queueReq(mbx, '198.51.100.9', auth))).status, 200, 'the bundle was never verified or recorded while limited');
});

test('A3 the 429 does not depend on the mailbox: an existing non-empty mailbox and a never-used one give identical bytes', async () => {
  process.env.RELAY_OWNER_RATE_LIMIT_MAX = '1';
  const { queue } = await routes();
  const real = deriveMailboxId(OWNER.fp);
  depositEnvelope(real, 'BLOB', Date.now());
  await queue(queueReq(real, '198.51.100.10'));
  const a = await snap(await queue(queueReq(real, '198.51.100.10')));
  const b = await snap(await queue(queueReq('0'.repeat(64), '198.51.100.10')));
  assert.equal(a.status, 429);
  assert.deepEqual(a, b, 'same status and body for an existing and a non-existent mailbox');
});

test('A4 one budget per IP across queue, ack and claim; another IP is unaffected', async () => {
  process.env.RELAY_OWNER_RATE_LIMIT_MAX = '2';
  const { queue, ack, claim } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  await queue(queueReq(mbx, '203.0.113.1'));
  await queue(queueReq(mbx, '203.0.113.1'));
  assert.equal((await ack(ackReq(mbx, ['e1'], '203.0.113.1'))).status, 429, 'ack shares the exhausted budget');
  assert.equal((await claim(claimReq('203.0.113.1'))).status, 429, 'claim shares the exhausted budget');
  assert.equal((await queue(queueReq(mbx, '203.0.113.2'))).status, 401, 'a different IP still reaches auth');
});

test('A6 a forged X-Forwarded-For does not buy a fresh owner budget: only the header the edge sets counts', async () => {
  process.env.RELAY_OWNER_RATE_LIMIT_MAX = '1';
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  const req = (forged: string) => new Request(`http://r.test/api/relay/queue?mailbox_id=${encodeURIComponent(mbx)}`, { headers: { [CLIENT_IP_HEADER]: '192.0.2.60', 'x-forwarded-for': forged } });
  assert.equal((await queue(req('198.51.100.1'))).status, 401, 'first request is within budget');
  assert.equal((await queue(req('198.51.100.2'))).status, 429, 'a new forged address is the same client');
  const other = new Request(`http://r.test/api/relay/queue?mailbox_id=${encodeURIComponent(mbx)}`, { headers: { [CLIENT_IP_HEADER]: '192.0.2.61' } });
  assert.equal((await queue(other)).status, 401, 'another real client has its own budget');
});

test('A5 the default budget is NOT the deposit limit (10/min): 40 polls in a minute from one IP all reach auth', async () => {
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  for (let i = 0; i < 40; i++) assert.equal((await queue(queueReq(mbx, '203.0.113.3'))).status, 401, `poll ${i + 1}`);
});

// ---------------- (b) replay cache ----------------

test('B2 v1 replay: the same signed poll twice → 200 then the SAME 401 as a non-owner', async () => {
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  depositEnvelope(mbx, 'V1-BLOB', Date.now());
  const auth = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
  assert.equal((await queue(queueReq(mbx, '192.0.2.4', auth))).status, 200);
  const replay = await snap(await queue(queueReq(mbx, '192.0.2.5', auth)));
  assert.deepEqual(replay, await snap(await queue(queueReq(mbx, '192.0.2.6'))));
});

test('B3 v1 concurrent replay: two identical requests in flight together → exactly one 200', async () => {
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  const auth = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
  const rs = await Promise.all([queue(queueReq(mbx, '192.0.2.7', auth)), queue(queueReq(mbx, '192.0.2.8', auth))]);
  assert.deepEqual(rs.map((r) => r.status).sort(), [200, 401]);
});

test('B4 a replayed ack deletes nothing more and gets the non-owner 401', async () => {
  const { queue, ack } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  depositEnvelope(mbx, 'KEEP', Date.now());
  const poll = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
  const list = JSON.parse(await (await queue(queueReq(mbx, '192.0.2.9', poll))).text()) as Array<{ envelope_id: string }>;
  const ids = list.map((e) => e.envelope_id);
  const auth = await signMailboxAckRequest({ mailboxId: mbx, envelopeIds: ids, now: Date.now(), ...v1Args(OWNER) });
  const first = await ack(ackReq(mbx, ids, '192.0.2.9', auth));
  assert.equal(first.status, 200);
  const replay = await snap(await ack(ackReq(mbx, ids, '192.0.2.10', auth)));
  assert.deepEqual(replay, { status: 401, body: JSON.stringify({ error: 'unauthorized' }) });
});

test('B5 fresh signatures (new nonces) keep working: 5 separately signed polls → 5 × 200', async () => {
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  for (let i = 0; i < 5; i++) {
    const auth = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
    assert.equal((await queue(queueReq(mbx, '192.0.2.11', auth))).status, 200, `fresh poll ${i + 1}`);
  }
});

test('B7 the cache is bounded and fails OPEN when full: no refusal, no eviction, logged once', async () => {
  process.env.RELAY_REPLAY_CACHE_MAX = '2';
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  const signed = [];
  for (let i = 0; i < 3; i++) signed.push(await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) }));
  const lines: string[] = [];
  const orig = console.warn;
  console.warn = (...a: unknown[]) => { lines.push(a.map(String).join(' ')); };
  try {
    for (const s of signed.slice(0, 2)) assert.equal((await queue(queueReq(mbx, '192.0.2.12', s))).status, 200);
    assert.equal((await queue(queueReq(mbx, '192.0.2.12', signed[2]))).status, 200, 'full → the one-time check is skipped, not a refusal');
    assert.equal((await queue(queueReq(mbx, '192.0.2.13', signed[0]))).status, 401, 'a RECORDED nonce is still refused: nothing was evicted');
    assert.equal((await queue(queueReq(mbx, '192.0.2.14', signed[2]))).status, 200, 'the stated cost of failing open: the unrecorded one can be replayed');
  } finally { console.warn = orig; }
  assert.equal(lines.filter((l) => l.includes('reason=replay_cache_full')).length, 1, 'logged, one line per window');
});

test('B8 entries expire with the freshness window (the store does not grow forever)', async () => {
  assert.ok(replayMod, 'owner-replay-cache module exists');
  const claim = replayMod!.claimOwnerNonce as (m: string, n: string, expiresAt: number, now: number) => boolean;
  const size = replayMod!.ownerReplayCacheSize as (now: number) => number;
  assert.equal(claim('mbx', 'a'.repeat(32), 1_000, 0), true);
  assert.equal(claim('mbx', 'a'.repeat(32), 1_000, 10), false, 'seen within its window');
  assert.equal(size(10), 1);
  assert.equal(size(1_001), 0, 'swept after its expiry');
  assert.equal(claim('mbx', 'a'.repeat(32), 3_000, 1_001), true, 'after expiry the slot is free (freshness already refuses that old ts)');
});

test('C1 an owner-route refusal is logged as reason=owner_rate_limit: one line per window, no IP, no mailbox id', async () => {
  process.env.RELAY_OWNER_RATE_LIMIT_MAX = '1';
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  const lines: string[] = [];
  const orig = console.warn;
  console.warn = (...a: unknown[]) => { lines.push(a.map(String).join(' ')); };
  try {
    await queue(queueReq(mbx, '198.51.100.77'));
    for (let i = 0; i < 50; i++) assert.equal((await queue(queueReq(mbx, '198.51.100.77'))).status, 429);
  } finally { console.warn = orig; }
  const ours = lines.filter((l) => l.includes('reason=owner_rate_limit'));
  assert.equal(ours.length, 1, '50 refusals in one window = 1 line');
  assert.ok(!ours[0].includes('198.51.100.77') && !ours[0].includes(mbx), 'the line carries no IP and no mailbox id');
  assert.ok(!lines.some((l) => /reason=rate_limit\b/.test(l)), 'not counted as a deposit rate_limit');
});

test('E1 the budget key: IPv4 as is, IPv6 by its /64 (any spelling), IPv4-mapped as IPv4, junk as given', () => {
  assert.equal(budgetKeyOf('198.51.100.7'), '198.51.100.7');
  assert.equal(budgetKeyOf('2001:db8:1:2::1'), budgetKeyOf('2001:0db8:0001:0002:ffff:0:0:9'));
  assert.equal(budgetKeyOf('[2001:db8:1:2::5]'), '2001:db8:1:2::/64');
  assert.notEqual(budgetKeyOf('2001:db8:1:2::1'), budgetKeyOf('2001:db8:1:3::1'));
  assert.equal(budgetKeyOf('::ffff:198.51.100.1'), '198.51.100.1');
  assert.equal(budgetKeyOf('unknown'), 'unknown');
});

test('E2 two addresses in one IPv6 /64 share one budget; the next /64 has its own', async () => {
  process.env.RELAY_OWNER_RATE_LIMIT_MAX = '1';
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  assert.equal((await queue(queueReq(mbx, '2001:db8:1:2::1'))).status, 401);
  assert.equal((await queue(queueReq(mbx, '2001:db8:1:2:abcd::77'))).status, 429, 'same /64');
  assert.equal((await queue(queueReq(mbx, '2001:db8:1:3::1'))).status, 401, 'another /64');
});

// ---------------- clients sign fresh per attempt (one-time nonces must not break a real client) ----------------

test('F1 the real poll path signs a FRESH owner bundle for every poll (two polls → two different nonces)', async () => {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  const owner = {
    fingerprint: id.fingerprint, publicKeyArmored: id.public_key, privateKeyArmored: a.secret_material.classicalPrivateKey,
    passphrase: a.secret_material.classicalKpass, kemPublicKey: id.pq_kem_public_key, kemSecretKey: uint8ToBase64(a.secret_material.mlkem1024Sec),
    sigPublicKey: id.pq_sig_public_key,
  };
  const nonces: string[] = [];
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/queue')) {
      const h = new Headers(init?.headers).get(OWNER_AUTH_HEADER) ?? '';
      nonces.push(JSON.parse(Buffer.from(h.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')).nonce);
      return new Response('[]', { status: 200 });
    }
    return new Response('{}', { status: 200 });
  }) as typeof fetch;
  const store = new HeadlessStore();
  await pollHeadlessOnce(owner, store, { relayBase: 'http://relay.test/api/relay', fetchImpl });
  await pollHeadlessOnce(owner, store, { relayBase: 'http://relay.test/api/relay', fetchImpl });
  assert.equal(nonces.length, 2);
  assert.notEqual(nonces[0], nonces[1], 'each poll is signed fresh, so the one-time check never refuses a real client');
});
const T0 = 1_000_000;

test('G9 the route limiter sweep is throttled, and at the cap new addresses share one bucket', () => {
  process.env.RELAY_OWNER_RATE_LIMIT_IP_CAP = '2';
  process.env.RELAY_OWNER_RATE_LIMIT_MAX = '1';
  process.env.RELAY_OWNER_RATE_LIMIT_WINDOW_MS = '1000';
  assert.equal(checkOwnerRouteBudget('192.0.2.1', T0), true);
  assert.equal(checkOwnerRouteBudget('192.0.2.2', T0), true);
  assert.equal(checkOwnerRouteBudget('192.0.2.3', T0 + 500), true, 'overflow bucket, sweep done at T0+500');
  assert.equal(checkOwnerRouteBudget('192.0.2.4', T0 + 1001), false, 'expired buckets, but no sweep within 1 s: shares the used overflow bucket');
});

test('B9 a v1 replay stops BEFORE the key parse and signature verify (the seen-check comes first in the verifier)', () => {
  // Outcome can't show this: the later nonce claim refuses a replay too, so without the seen-check a replay would cost a full verify and still read 401.
  const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'mailbox-auth.ts'), 'utf8');
  const body = src.slice(src.indexOf('async function verifyOwner('));
  const seen = body.indexOf('isOwnerNonceSeen(mailboxId, bundle.nonce, now)');
  assert.ok(seen > 0 && seen < body.indexOf('fingerprintMatchesKey(') && seen < body.indexOf('verifyWithEnvelope('));
});

test('B10 only a request whose signature checked out is recorded: a wrong signature leaves no nonce behind, and the owner can still use it', async () => {
  // Mailbox id and fingerprint are public. If a bad signature were recorded, a stranger could fill the cache for free, which switches replay protection off.
  assert.ok(replayMod, 'owner-replay-cache module exists');
  const size = replayMod!.ownerReplayCacheSize as (now: number) => number;
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  depositEnvelope(mbx, 'V1-BLOB', Date.now());
  const good = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
  const other = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
  const decode = (h: Record<string, string>) => JSON.parse(Buffer.from(h[OWNER_AUTH_HEADER], 'base64url').toString('utf8'));
  const g = decode(good);
  const o = decode(other);
  assert.notEqual(g.nonce, o.nonce, 'two signings, two nonces');
  // Right timestamp, fingerprint and key; a real signature, but over a different nonce, so it does not cover this request.
  const wrong = { [OWNER_AUTH_HEADER]: Buffer.from(JSON.stringify({ ...g, signature: o.signature, pq_signature: o.pq_signature }), 'utf8').toString('base64url') };
  const before = size(Date.now());
  const refused = await snap(await queue(queueReq(mbx, '192.0.2.40', wrong)));
  assert.deepEqual(refused, await snap(await queue(queueReq(mbx, '192.0.2.41'))), 'the same 401 as a non-owner');
  assert.equal(size(Date.now()), before, 'a refused signature records no nonce');
  assert.equal((await queue(queueReq(mbx, '192.0.2.42', good))).status, 200, 'the real signature over that same nonce still works');
});

test('B11 the full-cache sweep runs at most once a second, and the next allowed sweep reclaims expired entries', () => {
  assert.ok(replayMod, 'owner-replay-cache module exists');
  process.env.RELAY_REPLAY_CACHE_MAX = '6';
  const claim = replayMod!.claimOwnerNonce as (m: string, n: string, expiresAt: number, now: number) => boolean;
  const T = 5_000_000;
  const far = T + 60_000;
  const n = (c: string) => c.repeat(32);
  const warn = console.warn;
  console.warn = () => {};
  try {
    // The oldest four outlive the test, so the small per-call trim cannot free anything; only a full sweep can.
    for (const c of 'abcd') assert.equal(claim('mbx', n(c), far, T), true);
    for (const c of 'ef') assert.equal(claim('mbx', n(c), T + 100, T), true);
    assert.equal(claim('mbx', n('g'), far, T + 1), true, 'full: the first sweep frees nothing, so the check is skipped');
    assert.equal(claim('mbx', n('h'), far, T + 200), true, 'e and f have expired, but a sweep ran under a second ago');
    assert.equal(claim('mbx', n('h'), far, T + 201), true, 'not recorded: no sweep ran, so the cache is still full');
    assert.equal(claim('mbx', n('h'), far, T + 1_002), true, 'over a second later a sweep frees e and f, and h is recorded');
    assert.equal(claim('mbx', n('h'), far, T + 1_003), false, 'recorded: its replay is refused');
  } finally { console.warn = warn; }
});

// ---------------- v2 owner requests: refused until clients move to v2 ----------------

test('V1 by default a validly signed v2 poll and ack get the SAME bytes as a non-owner', async () => {
  const { queue, ack } = await routes();
  const p = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  depositEnvelope(p.mailboxId, 'V2-BLOB', Date.now());
  const nonOwner = await snap(await queue(queueReq(p.mailboxId, '192.0.2.40')));
  const a = signOwnerRequestV2({ keypair: V2, op: 'ack', now: Date.now(), envelopeIds: ['e1'] });
  const result = {
    poll: await snap(await queue(queueReq(p.mailboxId, '192.0.2.41', p.headers))),
    ack: await snap(await ack(ackReq(a.mailboxId, ['e1'], '192.0.2.42', a.headers))),
  };
  assert.equal(nonOwner.status, 401);
  assert.deepEqual(result.poll, nonOwner);
  assert.deepEqual(result.ack, nonOwner);
  assert.ok(!result.poll.body.includes('V2-BLOB'));
});

test('V2 with RELAY_OWNER_V2_ENABLED a v2 poll and ack work', async () => {
  process.env.RELAY_OWNER_V2_ENABLED = '1';
  const { queue, ack } = await routes();
  const p = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  depositEnvelope(p.mailboxId, 'V2-BLOB', Date.now());
  const result = await snap(await queue(queueReq(p.mailboxId, '192.0.2.43', p.headers)));
  assert.equal(result.status, 200);
  assert.ok(result.body.includes('V2-BLOB'));
  const id = JSON.parse(result.body)[0].envelope_id;
  const a = signOwnerRequestV2({ keypair: V2, op: 'ack', now: Date.now(), envelopeIds: [id] });
  assert.equal((await ack(ackReq(a.mailboxId, [id], '192.0.2.44', a.headers))).status, 200);
});

test('V1b the refusal comes BEFORE any verify: both routes read the flag first and short-circuit', () => {
  // The verify functions' owners are frozen objects, so the check count can't be observed from a test. Pin the short-circuit instead:
  // a route that verified first and then read the flag would still answer 401, and would still do the costly work on every request.
  for (const [route, op] of [['queue', 'poll'], ['ack', 'ack']] as const) {
    const src = readFileSync(join(routeDir, route, 'route.ts'), 'utf8');
    assert.match(src, new RegExp(`mailboxConfig\\(\\)\\.ownerV2Enabled && \\(await verifyOwnerRequestV2\\(request, '${op}'`), route);
  }
});

test('V3 v1 owners are unaffected by the v2 refusal', async () => {
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  depositEnvelope(mbx, 'V1-BLOB', Date.now());
  const auth = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
  const r = await snap(await queue(queueReq(mbx, '192.0.2.45', auth)));
  assert.equal(r.status, 200);
  assert.ok(r.body.includes('V1-BLOB'));
});

test('V4 deposits to a v2 mailbox are still accepted: only the owner routes refuse v2', async () => {
  const { envelope } = await routes();
  const id = deriveMailboxIdV2(V2);
  const r = await envelope(new Request('http://r.test/api/relay/envelope', { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': '192.0.2.46' }, body: JSON.stringify({ mailbox_id: id, blob: 'QUJD' }) }));
  assert.ok(r.ok, `status ${r.status}`);
});

test('V5 the limiter still runs first on a v2 id: past its budget it is 429, like any owner request', async () => {
  process.env.RELAY_OWNER_RATE_LIMIT_MAX = '1';
  const { queue } = await routes();
  const id = deriveMailboxIdV2(V2);
  assert.equal((await queue(queueReq(id, '192.0.2.47'))).status, 401);
  assert.equal((await queue(queueReq(id, '192.0.2.47'))).status, 429);
});

