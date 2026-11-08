// src/lib/relay/owner-route-guards.test.ts
// Owner-route abuse guards (availability, rated HIGH): the poll / ack / claim routes had NO rate limiter, and a signed owner
// request was accepted again and again inside its freshness window (no nonce store). A key costs nothing to make, so one
// requester could replay one header to make every request cost the relay a full signature verify for free.
// Guards pinned here:
//   (a) a per-IP limiter at the TOP of queue/ack/claim, before any decode or verify, answering a uniform 429;
//   (b) a replay cache on (mailbox_id, nonce) for the freshness window: a replay gets the SAME 401 as a non-owner, and for
//       v2 it is refused before EITHER signature check, so a replay costs a Map lookup. Full → fail OPEN, logged;
//   (c) a process-wide budget on the expensive verify step (a fresh request with a valid Ed25519 sig and a GARBAGE pq_sig is free
//       to make and still forces a full ML-DSA verify): past it, a uniform 503 before the expensive step, so the site stays up.
//       Fair share: a request within its address's share may empty the budget, one beyond it only spends above the reserve;
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
import { generateMailboxAuthKeypair, signOwnerRequestV2, verifyOwnerRequestV2, type MailboxAuthKeypair } from './mailbox-auth-v2';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { resetDeposit429Counts } from './deposit-429-log';
import { OwnerVerifyBusyError, resetOwnerVerifyBudget, takeOwnerVerifyToken } from './owner-verify-budget';
import { checkOwnerRouteBudget, ownerClientKey } from './owner-route-budget';
import { budgetKeyOf } from './owner-route-budget';
import { OWNER_AUTH_HEADER } from './mailbox-auth';
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
  resetOwnerVerifyBudget();
  for (const k of ['RELAY_OWNER_RATE_LIMIT_MAX', 'RELAY_OWNER_RATE_LIMIT_WINDOW_MS', 'RELAY_REPLAY_CACHE_MAX', 'RELAY_OWNER_VERIFY_PER_SEC', 'RELAY_OWNER_VERIFY_BURST', 'RELAY_OWNER_VERIFY_FAIR_PER_SEC', 'RELAY_OWNER_VERIFY_FAIR_BURST', 'RELAY_OWNER_RATE_LIMIT_IP_CAP', 'INVITE_REQUIRED']) delete process.env[k];
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

test('B7 the cache is bounded and fails OPEN when full: no refusal, no eviction, logged once', async () => {
  process.env.RELAY_REPLAY_CACHE_MAX = '2';
  const { queue } = await routes();
  const signed = Array.from({ length: 3 }, () => signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() }));
  const lines: string[] = [];
  const orig = console.warn;
  console.warn = (...a: unknown[]) => { lines.push(a.map(String).join(' ')); };
  try {
    for (const s of signed.slice(0, 2)) assert.equal((await queue(queueReq(s.mailboxId, '192.0.2.12', s.headers))).status, 200);
    const third = signed[2];
    assert.equal((await queue(queueReq(third.mailboxId, '192.0.2.12', third.headers))).status, 200, 'full → the one-time check is skipped, not a refusal');
    assert.equal((await queue(queueReq(signed[0].mailboxId, '192.0.2.13', signed[0].headers))).status, 401, 'a RECORDED nonce is still refused: nothing was evicted');
    assert.equal((await queue(queueReq(third.mailboxId, '192.0.2.14', third.headers))).status, 200, 'the stated cost of failing open: the unrecorded one can be replayed');
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

// ---------------- (c) the process-wide budget on the expensive verify ----------------

/** A v2 poll bundle with a VALID Ed25519 signature and a GARBAGE pq_sig of the right length: free to make, forces a full ML-DSA verify. */
function garbagePq(op: 'poll' = 'poll') {
  const { mailboxId, headers } = signOwnerRequestV2({ keypair: V2, op, now: Date.now() });
  const key = Object.keys(headers)[0];
  const raw = Buffer.from(headers[key].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
  const b = JSON.parse(raw);
  const pqLen = Buffer.from(b.pq_sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64').length;
  b.pq_sig = Buffer.alloc(pqLen, 7).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return { mailboxId, headers: { [key]: Buffer.from(JSON.stringify(b)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') } };
}

test('D1 the C0 attack is bounded: valid-Ed25519 + garbage-pq requests spend the budget, then are shed with 503 BEFORE ML-DSA', async () => {
  process.env.RELAY_OWNER_VERIFY_BURST = '2';
  process.env.RELAY_OWNER_VERIFY_PER_SEC = '1';
  let mlDsaCalls = 0;
  const deps = { mlDsaVerify: (s: Uint8Array, m: Uint8Array, k: Uint8Array) => { mlDsaCalls++; return realMlDsa(s, m, k); } };
  const call = (g: ReturnType<typeof garbagePq>) =>
    verifyOwnerRequestV2(new Request(`http://r.test/q?mailbox_id=${g.mailboxId}`, { headers: g.headers }), 'poll', g.mailboxId, Date.now(), undefined, deps);
  assert.equal(await call(garbagePq()), false);
  assert.equal(await call(garbagePq()), false);
  assert.equal(mlDsaCalls, 2, 'the two budgeted attempts ran (and failed) ML-DSA');
  await assert.rejects(call(garbagePq()), OwnerVerifyBusyError, 'the third is shed');
  assert.equal(mlDsaCalls, 2, 'and the shed one never reached ML-DSA');
});

test('D2 the shed answer is a uniform 503 that does not depend on the mailbox (a non-empty one and an empty one give the same bytes)', async () => {
  process.env.RELAY_OWNER_VERIFY_BURST = '1';
  process.env.RELAY_OWNER_VERIFY_PER_SEC = '1';
  const { queue } = await routes();
  const other = generateMailboxAuthKeypair();
  const first = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  depositEnvelope(first.mailboxId, 'FULL', Date.now());
  assert.equal((await queue(queueReq(first.mailboxId, '192.0.2.20', first.headers))).status, 200);
  const a = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  const b = signOwnerRequestV2({ keypair: other, op: 'poll', now: Date.now() });
  const ra = await queue(queueReq(a.mailboxId, '192.0.2.21', a.headers));
  const rb = await queue(queueReq(b.mailboxId, '192.0.2.22', b.headers));
  assert.equal(ra.status, 503);
  assert.equal(ra.headers.get('retry-after'), '1');
  assert.deepEqual(await snap(ra), await snap(rb));
  assert.ok(!(await snap(await queue(queueReq(a.mailboxId, '192.0.2.21', a.headers)))).body.includes('FULL'));
});

test('D3 a replay spends no budget: with one token used, a replay is the non-owner 401, not a 503', async () => {
  process.env.RELAY_OWNER_VERIFY_BURST = '1';
  process.env.RELAY_OWNER_VERIFY_PER_SEC = '1';
  const { queue } = await routes();
  const s = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  assert.equal((await queue(queueReq(s.mailboxId, '192.0.2.23', s.headers))).status, 200);
  assert.equal((await queue(queueReq(s.mailboxId, '192.0.2.24', s.headers))).status, 401);
});

test('D4 v1 poll and ack are shed too (claim runs the same v1 verifier), and the 503 is logged as owner_verify_busy', async () => {
  process.env.RELAY_OWNER_VERIFY_BURST = '1';
  process.env.RELAY_OWNER_VERIFY_PER_SEC = '1';
  const { queue, ack } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  const lines: string[] = [];
  const orig = console.warn;
  console.warn = (...a: unknown[]) => { lines.push(a.map(String).join(' ')); };
  try {
    const p1 = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
    assert.equal((await queue(queueReq(mbx, '192.0.2.25', p1))).status, 200);
    const p2 = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
    assert.equal((await queue(queueReq(mbx, '192.0.2.25', p2))).status, 503, 'v1 poll shed');
    const a1 = await signMailboxAckRequest({ mailboxId: mbx, envelopeIds: ['e1'], now: Date.now(), ...v1Args(OWNER) });
    assert.equal((await ack(ackReq(mbx, ['e1'], '192.0.2.25', a1))).status, 503, 'v1 ack shed');
  } finally { console.warn = orig; }
  const busy = lines.filter((l) => l.includes('reason=owner_verify_busy'));
  assert.equal(busy.length, 1);
  assert.match(busy[0], /^relay owner 503 /);
});

test('D5 the budget refills at its rate and never exceeds its burst', () => {
  process.env.RELAY_OWNER_VERIFY_BURST = '2';
  process.env.RELAY_OWNER_VERIFY_PER_SEC = '4';
  const t0 = 1_000_000;
  takeOwnerVerifyToken(t0, 'k'); takeOwnerVerifyToken(t0, 'k');
  assert.throws(() => takeOwnerVerifyToken(t0, 'k'), OwnerVerifyBusyError);
  takeOwnerVerifyToken(t0 + 250, 'k'); // 4/s → one token back after 250 ms
  assert.throws(() => takeOwnerVerifyToken(t0 + 250, 'k'), OwnerVerifyBusyError);
  takeOwnerVerifyToken(t0 + 60_000, 'k'); takeOwnerVerifyToken(t0 + 60_000, 'k'); // a long idle refills to the burst, not beyond
  assert.throws(() => takeOwnerVerifyToken(t0 + 60_000, 'k'), OwnerVerifyBusyError);
});

// ---------------- fair share: priority over the reserve, never past the hard cap ----------------

const T0 = 1_000_000;
function setBudget(perSec: number, burst: number, fairPerSec: number, fairBurst: number) {
  process.env.RELAY_OWNER_VERIFY_PER_SEC = String(perSec);
  process.env.RELAY_OWNER_VERIFY_BURST = String(burst);
  process.env.RELAY_OWNER_VERIFY_FAIR_PER_SEC = String(fairPerSec);
  process.env.RELAY_OWNER_VERIFY_FAIR_BURST = String(fairBurst);
}
function takes(now: number, key: string): boolean {
  try { takeOwnerVerifyToken(now, key); return true; } catch (e) { assert.ok(e instanceof OwnerVerifyBusyError); return false; }
}

test('G1 beyond its share an address spends only the top of the bucket; within their share others can still use the reserve', () => {
  setBudget(1, 4, 1, 1); // reserve 2: over-share needs ≥ 3 tokens
  assert.equal(takes(T0, 'a'), true, 'in share, 4 → 3');
  assert.equal(takes(T0, 'a'), true, 'over share, above the reserve, 3 → 2');
  assert.equal(takes(T0, 'a'), false, 'over share, at the reserve: shed');
  assert.equal(takes(T0, 'b'), true, 'another address, in share: uses the reserve, 2 → 1');
  assert.equal(takes(T0, 'c'), true, 'and another, 1 → 0');
  assert.equal(takes(T0, 'd'), false, 'an empty bucket refuses even in share');
});

test('G2 no number of addresses gets past the hard cap (a spoofed address buys priority, never more total work)', () => {
  setBudget(1, 10, 1, 1);
  let admitted = 0;
  for (let i = 0; i < 100; i++) if (takes(T0, `ip-${i}`)) admitted++;
  assert.equal(admitted, 10);
});

test('G3 a share refills at its own rate', () => {
  setBudget(1, 2, 2, 1); // reserve 1: over-share needs ≥ 2 tokens
  assert.equal(takes(T0, 'a'), true, 'in share, 2 → 1');
  assert.equal(takes(T0, 'a'), false, 'over share at the reserve');
  assert.equal(takes(T0 + 500, 'a'), true, 'share back after 500 ms at 2/s: in share again (1.5 tokens, under the over-share floor)');
});

/** A v2 poll whose Ed25519 signature is wrong (one byte flipped, right length). Everything else is valid, the nonce included. */
function wrongEd(signed: { mailboxId: string; headers: Record<string, string> }) {
  const key = Object.keys(signed.headers)[0];
  const b64u = (x: Buffer) => x.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const b = JSON.parse(Buffer.from(signed.headers[key].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  const sig = Buffer.from(b.sig.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
  sig[0] ^= 1;
  b.sig = b64u(sig);
  return { mailboxId: signed.mailboxId, headers: { [key]: b64u(Buffer.from(JSON.stringify(b))) } };
}
const v2Verify = (s: { mailboxId: string; headers: Record<string, string> }) =>
  verifyOwnerRequestV2(new Request(`http://r.test/q?mailbox_id=${s.mailboxId}`, { headers: s.headers }), 'poll', s.mailboxId, Date.now());

test('G4 a wrong Ed25519 signature spends the budget: the token is taken BEFORE the Ed25519 check', async () => {
  setBudget(1, 1, 1, 4);
  assert.equal(await v2Verify(wrongEd(signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() }))), false);
  await assert.rejects(v2Verify(signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() })), OwnerVerifyBusyError, 'that attempt used the only token');
});

test('G5 NEG: a wrong Ed25519 signature does not burn the nonce: the real request with that nonce still passes', async () => {
  const signed = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  assert.equal(await v2Verify(wrongEd(signed)), false);
  assert.equal(await v2Verify(signed), true);
  assert.equal(await v2Verify(signed), false, 'and then it is a replay');
});

test('G6 at the map cap, new addresses share ONE overflow share (memory stays bounded)', () => {
  setBudget(1, 4, 1, 1); // reserve 2: over-share needs ≥ 3 tokens
  process.env.RELAY_OWNER_RATE_LIMIT_IP_CAP = '2';
  assert.equal(takes(T0, 'k1'), true, '4 → 3');
  assert.equal(takes(T0, 'k2'), true, '3 → 2');
  assert.equal(takes(T0, 'k3'), true, 'first overflow address, in share, 2 → 1');
  assert.equal(takes(T0, 'k4'), false, 'second overflow address shares that bucket, so it is over share');
});

test('G7 a sweep drops refilled shares so new addresses get their own again', () => {
  setBudget(1, 4, 1, 1);
  process.env.RELAY_OWNER_RATE_LIMIT_IP_CAP = '2';
  takes(T0, 'k1'); takes(T0, 'k2'); // 2 tokens left; after 1 s: 3, and both shares are full again
  assert.equal(takes(T0 + 1000, 'k3'), true);
  assert.equal(takes(T0 + 1000, 'k4'), true, 'its own share, not the overflow one (1 token left is under the over-share floor)');
});

test('G8 the share sweep runs at most once a second (a full map cannot make every new address pay O(n))', () => {
  setBudget(1, 4, 1, 1);
  process.env.RELAY_OWNER_RATE_LIMIT_IP_CAP = '2';
  takes(T0, 'k1'); takes(T0, 'k2');
  assert.equal(takes(T0 + 10, 'k3'), true, 'swept here (nothing to drop), goes to overflow');
  assert.equal(takes(T0 + 1005, 'k4'), false, 'k1/k2 have refilled, but no sweep yet: k4 shares the spent overflow bucket, so it is over share');
});

test('G9 the route limiter sweep is throttled too, and at the cap new addresses share one bucket', () => {
  process.env.RELAY_OWNER_RATE_LIMIT_IP_CAP = '2';
  process.env.RELAY_OWNER_RATE_LIMIT_MAX = '1';
  process.env.RELAY_OWNER_RATE_LIMIT_WINDOW_MS = '1000';
  assert.equal(checkOwnerRouteBudget('192.0.2.1', T0), true);
  assert.equal(checkOwnerRouteBudget('192.0.2.2', T0), true);
  assert.equal(checkOwnerRouteBudget('192.0.2.3', T0 + 500), true, 'overflow bucket, sweep done at T0+500');
  assert.equal(checkOwnerRouteBudget('192.0.2.4', T0 + 1001), false, 'expired buckets, but no sweep within 1 s: shares the used overflow bucket');
});

test('G10 both verifiers key the share by client address: a second address is in share, on v1 and on v2', async () => {
  setBudget(1, 2, 1, 1); // reserve 1: over-share needs ≥ 2 tokens
  const { queue } = await routes();
  const mbx = deriveMailboxId(OWNER.fp);
  const p1 = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
  assert.equal((await queue(queueReq(mbx, '192.0.2.30', p1))).status, 200, 'v1 in share, 2 → 1');
  const p2 = await signMailboxPollRequest({ mailboxId: mbx, now: Date.now(), ...v1Args(OWNER) });
  assert.equal((await queue(queueReq(mbx, '192.0.2.31', p2))).status, 200, 'v1 from another address: in share, uses the reserve');
  resetOwnerVerifyBudget();
  const v1 = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  assert.equal((await queue(queueReq(v1.mailboxId, '192.0.2.32', v1.headers))).status, 200, 'v2 in share, 2 → 1');
  const v2 = signOwnerRequestV2({ keypair: V2, op: 'poll', now: Date.now() });
  assert.equal((await queue(queueReq(v2.mailboxId, '192.0.2.33', v2.headers))).status, 200, 'v2 from another address: in share, uses the reserve');
});

test('G11 the share key is the budget key: two addresses in one IPv6 /64 are one client', () => {
  const key = (ip: string) => ownerClientKey(new Request('http://r.test/', { headers: { 'x-forwarded-for': ip } }));
  assert.equal(key('2001:db8:1:2::a'), key('2001:db8:1:2:ffff::b'));
  assert.notEqual(key('2001:db8:1:2::a'), key('2001:db8:1:3::a'));
  assert.equal(key('203.0.113.9'), '203.0.113.9');
});

// ---------------- IPv6 keyed by /64 ----------------

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
