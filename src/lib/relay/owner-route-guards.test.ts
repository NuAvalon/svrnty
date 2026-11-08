// src/lib/relay/owner-route-guards.test.ts
// Owner-route abuse guards (availability, rated HIGH): the poll / ack / claim routes had NO rate limiter, and a signed owner
// request was accepted again and again inside its freshness window (no nonce store). A key costs nothing to make, so one
// requester could replay one header to make every request cost the relay a full ML-DSA-87 verify (~22 ms) for free.
// Guards pinned here:
//   (a) a per-IP limiter at the TOP of queue/ack/claim, before any decode or verify, answering a uniform 429;
//   (b) a replay cache on (mailbox_id, nonce) for the freshness window: a replay gets the SAME 401 as a non-owner, and for
//       v2 it is refused after Ed25519 and BEFORE ML-DSA (so a replay costs microseconds, not ~22 ms).
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
import { generateMailboxAuthKeypair, signOwnerRequestV2, verifyOwnerRequestV2, type MailboxAuthKeypair } from './mailbox-auth-v2';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

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
  for (const k of ['RELAY_OWNER_RATE_LIMIT_MAX', 'RELAY_OWNER_RATE_LIMIT_WINDOW_MS', 'RELAY_REPLAY_CACHE_MAX', 'INVITE_REQUIRED']) delete process.env[k];
});

const routes = async () => ({
  queue: (await import('../../../app/api/relay/queue/route')).GET,
  ack: (await import('../../../app/api/relay/ack/route')).POST,
  claim: (await import('../../../app/api/relay/claim/route')).POST,
});
const ipHeaders = (ip: string, extra: Record<string, string> = {}) => ({ 'x-forwarded-for': ip, ...extra });
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

test('A2 counting: a limited request never reaches a verifier (no ML-DSA verify, no store)', async () => {
  process.env.RELAY_OWNER_RATE_LIMIT_MAX = '1';
  const { queue } = await routes();
  const { mailboxId, headers } = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  assert.equal((await queue(queueReq(mailboxId, '198.51.100.8'))).status, 401);
  // Bound by construction: the route reads the limiter BEFORE it parses the URL or any header. A limited request with a valid v2
  // bundle is still 429, and its bundle stays unused: replaying it from another IP afterwards is accepted ONCE (it was never seen).
  assert.equal((await queue(queueReq(mailboxId, '198.51.100.8', headers))).status, 429);
  assert.equal((await queue(queueReq(mailboxId, '198.51.100.9', headers))).status, 200, 'the bundle was never verified or recorded while limited');
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

test('A5 the default budget is NOT the deposit limit (10/min): 40 polls in a minute from one IP all reach auth', async () => {
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  for (let i = 0; i < 40; i++) assert.equal((await queue(queueReq(mbx, '203.0.113.3'))).status, 401, `poll ${i + 1}`);
});

// ---------------- (b) replay cache ----------------

test('B1 v2 replay: the same signed poll twice → 200 then the SAME 401 as a non-owner', async () => {
  const { queue } = await routes();
  const { mailboxId, headers } = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  depositEnvelope(mailboxId, 'V2-BLOB', Date.now());
  const first = await snap(await queue(queueReq(mailboxId, '192.0.2.1', headers)));
  assert.equal(first.status, 200);
  assert.ok(first.body.includes('V2-BLOB'));
  const replay = await snap(await queue(queueReq(mailboxId, '192.0.2.2', headers)));
  const nonOwner = await snap(await queue(queueReq(mailboxId, '192.0.2.3')));
  assert.deepEqual(replay, nonOwner, 'a replay is indistinguishable from a non-owner');
  assert.equal(replay.status, 401);
});

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
  for (let i = 0; i < 5; i++) {
    const { mailboxId, headers } = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
    assert.equal((await queue(queueReq(mailboxId, '192.0.2.11', headers))).status, 200, `fresh poll ${i + 1}`);
  }
});

test('B6 counting: a v2 replay is refused BEFORE ML-DSA (the injected ML-DSA verifier runs once, not twice)', async () => {
  let mlDsaCalls = 0;
  const deps = { mlDsaVerify: (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => { mlDsaCalls++; return realMlDsa(sig, msg, pub); } };
  const { mailboxId, headers } = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  const req = () => new Request(`http://r.test/api/relay/queue?mailbox_id=${mailboxId}`, { headers });
  // the 6th (deps) parameter is the ML-DSA injection point (counting test)
  assert.equal(await verifyOwnerRequestV2(req(), 'poll', mailboxId, Date.now(), undefined, deps), true);
  assert.equal(await verifyOwnerRequestV2(req(), 'poll', mailboxId, Date.now(), undefined, deps), false, 'the replay is refused');
  assert.equal(mlDsaCalls, 1, 'ML-DSA ran for the first request only');
});
const realMlDsa = (sig: Uint8Array, msg: Uint8Array, pub: Uint8Array) => ml_dsa87.verify(sig, msg, pub);

test('B7 the cache is bounded: at RELAY_REPLAY_CACHE_MAX live entries a new request fails CLOSED (non-owner 401), never evicts', async () => {
  process.env.RELAY_REPLAY_CACHE_MAX = '2';
  const { queue } = await routes();
  for (let i = 0; i < 2; i++) {
    const { mailboxId, headers } = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
    assert.equal((await queue(queueReq(mailboxId, '192.0.2.12', headers))).status, 200);
  }
  const { mailboxId, headers } = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  assert.equal((await queue(queueReq(mailboxId, '192.0.2.12', headers))).status, 401, 'full → refuse; evicting would re-open replay');
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
