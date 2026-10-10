// Shared onion transport — wire + compose/decompose + §F5 cadence (cover→real swap).
// Proves (not asserts): a fan-out trickles one-cell-per-slot (never a burst), the full seal→peel→open→unframe
// stack round-trips through the REAL server peel, and every failure path fails CLOSED (under-reveal).
// Run: npx tsx --test src/lib/sync/onion-transport.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  httpOnionRelay,
  sealForRoute,
  receiveFromRoute,
  routeIdForPeer,
  isValidRouteId,
  CadenceEmitter,
} from './onion-transport.js';
import { peelOnion } from '../crypto/onion-envelope.js';
import { frameUniform, unframeUniform, FRAME_MAX_PAYLOAD, type FrameType } from '../crypto/uniform-frame.js';
import type { MailboxEnvelopePackage } from '../crypto/mailbox-envelope.js';
import {
  generateMailboxKeypair,
  toPublicKeys,
  toSecretKeys,
  mailboxFpOf,
} from '../crypto/mailbox-keys.js';

const VALID_ID = 'deadbeef'.repeat(4); // 32 lowercase hex
const enc = (s: string) => new TextEncoder().encode(s);

// A fresh device/satellite mailbox identity (real keys — these tests do real crypto).
function identity() {
  const kp = generateMailboxKeypair();
  return { pub: toPublicKeys(kp), sec: toSecretKeys(kp), fp: mailboxFpOf(kp) };
}

function stubFetch(status: number, body: unknown): { calls: { url: string; init?: RequestInit }[]; restore: () => void } {
  const calls: { url: string; init?: RequestInit }[] = [];
  const orig = globalThis.fetch;
  globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), init });
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = orig; } };
}

// ── new 'visible-affirm' frame type ──────────────────────────────────────────────────────────────────────

test('visible-affirm round-trips through the uniform frame (new code 5, no collision)', () => {
  const payload = enc('B-sees-C');
  const cell = frameUniform(payload, 'visible-affirm');
  assert.equal(cell.length, 2048); // uniform size, identical to every other kind
  const framed = unframeUniform(cell);
  assert.ok(framed);
  assert.equal(framed!.type, 'visible-affirm');
  assert.deepEqual(framed!.payload, payload);
  // existing kinds still frame (additive change didn't renumber)
  assert.equal(unframeUniform(frameUniform(enc('x'), 'cover'))!.type, 'cover');
  assert.equal(unframeUniform(frameUniform(enc('x'), 'consent-delta'))!.type, 'consent-delta');
});

// ── route-id validity + derivation ───────────────────────────────────────────────────────────────────────

test('isValidRouteId: 32 lowercase hex only (stricter than the proxy — matches the satellite)', () => {
  assert.equal(isValidRouteId(VALID_ID), true);
  assert.equal(isValidRouteId(VALID_ID.toUpperCase()), false); // uppercase rejected client-side
  assert.equal(isValidRouteId('short'), false);
  assert.equal(isValidRouteId(VALID_ID + 'ff'), false);
  assert.equal(isValidRouteId('g'.repeat(32)), false);
  assert.equal(isValidRouteId(123 as unknown as string), false);
});

test('routeIdForPeer: deterministic 32-hex; direction-asymmetric', () => {
  const rootSecret = new Uint8Array(32).fill(7);
  const a = routeIdForPeer({ rootSecret, senderFp: 'aa', recipientFp: 'bb', anchorWindow: 100, nowWindow: 100 });
  const b = routeIdForPeer({ rootSecret, senderFp: 'aa', recipientFp: 'bb', anchorWindow: 100, nowWindow: 100 });
  assert.equal(a, b); // deterministic
  assert.equal(isValidRouteId(a), true);
  // opposite direction (sender/recipient swapped) must route differently — recipient polls the other lane
  const rev = routeIdForPeer({ rootSecret, senderFp: 'bb', recipientFp: 'aa', anchorWindow: 100, nowWindow: 100 });
  assert.notEqual(a, rev);
});

// ── full stack: sealForRoute → (real server peel) → receiveFromRoute ─────────────────────────────────────

test('e2e: a visible-affirm seals, peels at the satellite, and opens only at the recipient device', async () => {
  const recip = identity();
  const sat = identity();
  const payload = enc('affirm:B<->C@epoch42');

  const outer = await sealForRoute({
    payload,
    frameType: 'visible-affirm',
    recipientDevice: recip.pub,
    satellite: sat.pub,
    routeId: VALID_ID,
  });
  // the outer is a well-formed MailboxEnvelopePackage sealed to the satellite
  assert.equal(outer.v, 1);
  for (const k of ['alg', 'mailbox_fp', 'epk', 'kem_ct', 'nonce', 'ct'] as const) {
    assert.equal(typeof outer[k], 'string');
  }

  // satellite peels with ITS key → learns only the route + an fp-stripped inner (cannot read content)
  const peeled = await peelOnion(outer, sat.sec, sat.fp);
  assert.ok(peeled);
  assert.equal(peeled!.route, VALID_ID);
  assert.equal('mailbox_fp' in peeled!.inner, false); // K0-1 blinding enforced

  // recipient polls its route and recovers the affirmative
  const got = await receiveFromRoute({
    routeId: VALID_ID,
    deviceSecrets: recip.sec,
    deviceMailboxFpHex: recip.fp,
    frameType: 'visible-affirm',
    relay: { poll: async () => [peeled!.inner] },
  });
  assert.equal(got.length, 1);
  assert.equal(got[0].type, 'visible-affirm');
  assert.deepEqual(got[0].payload, payload);
});

test('receiveFromRoute: an inner sealed to a DIFFERENT device does not open (dropped, under-reveal)', async () => {
  const recip = identity();
  const other = identity();
  const sat = identity();
  const outer = await sealForRoute({
    payload: enc('for-other'),
    frameType: 'visible-affirm',
    recipientDevice: other.pub, // sealed to someone else
    satellite: sat.pub,
    routeId: VALID_ID,
  });
  const peeled = await peelOnion(outer, sat.sec, sat.fp);
  const got = await receiveFromRoute({
    routeId: VALID_ID,
    deviceSecrets: recip.sec, // our device can't open it
    deviceMailboxFpHex: recip.fp,
    relay: { poll: async () => [peeled!.inner] },
  });
  assert.deepEqual(got, []);
});

test('receiveFromRoute: frameType filter keeps only the requested kind', async () => {
  const recip = identity();
  const sat = identity();
  const mkInner = async (ft: FrameType) => {
    const outer = await sealForRoute({ payload: enc(ft), frameType: ft, recipientDevice: recip.pub, satellite: sat.pub, routeId: VALID_ID });
    return (await peelOnion(outer, sat.sec, sat.fp))!.inner;
  };
  const inners = [await mkInner('visible-affirm'), await mkInner('cover'), await mkInner('visible-affirm')];
  const got = await receiveFromRoute({
    routeId: VALID_ID,
    deviceSecrets: recip.sec,
    deviceMailboxFpHex: recip.fp,
    frameType: 'visible-affirm',
    relay: { poll: async () => inners },
  });
  assert.equal(got.length, 2);
  assert.ok(got.every((c) => c.type === 'visible-affirm'));
});

test('receiveFromRoute fail-closed: bad id / transport error / garbage inner all surface nothing', async () => {
  const recip = identity();
  const base = { deviceSecrets: recip.sec, deviceMailboxFpHex: recip.fp };
  // bad route id → [] without ever polling
  let polled = false;
  assert.deepEqual(
    await receiveFromRoute({ ...base, routeId: 'BAD', relay: { poll: async () => { polled = true; return []; } } }),
    [],
  );
  assert.equal(polled, false);
  // transport throw → []
  assert.deepEqual(
    await receiveFromRoute({ ...base, routeId: VALID_ID, relay: { poll: async () => { throw new Error('net'); } } }),
    [],
  );
  // garbage inner (not an openable envelope) → dropped, no throw
  assert.deepEqual(
    await receiveFromRoute({ ...base, routeId: VALID_ID, relay: { poll: async () => [{ junk: true } as never] } }),
    [],
  );
});

// ── sealForRoute fail-closed (no silent truncation, no unsealed fallback) ────────────────────────────────

test('sealForRoute throws on an oversize payload (never truncates a signed payload)', async () => {
  const recip = identity();
  const sat = identity();
  const tooBig = new Uint8Array(FRAME_MAX_PAYLOAD + 1);
  await assert.rejects(
    () => sealForRoute({ payload: tooBig, frameType: 'visible-affirm', recipientDevice: recip.pub, satellite: sat.pub, routeId: VALID_ID }),
    /exceeds one cell/,
  );
});

test('sealForRoute throws on a bad route_id (before any sealing)', async () => {
  const recip = identity();
  const sat = identity();
  await assert.rejects(
    () => sealForRoute({ payload: enc('x'), frameType: 'visible-affirm', recipientDevice: recip.pub, satellite: sat.pub, routeId: 'nope' }),
    /invalid route_id/,
  );
});

test('sealForRoute throws on an unknown frame type (runtime guard behind the TS type)', async () => {
  const recip = identity();
  const sat = identity();
  await assert.rejects(
    () => sealForRoute({ payload: enc('x'), frameType: 'bogus' as FrameType, recipientDevice: recip.pub, satellite: sat.pub, routeId: VALID_ID }),
    /unknown frame type/,
  );
});

// ── httpOnionRelay wire ──────────────────────────────────────────────────────────────────────────────────

const fakeOuter = (): MailboxEnvelopePackage => ({
  v: 1, alg: 'x25519-mlkem1024-aes256gcm', mailbox_fp: 'a'.repeat(64),
  epk: 'ZXBr', kem_ct: 'a2VtX2N0', nonce: 'bm9uY2U', ct: 'Y2lwaGVydGV4dA',
});

test('httpOnionRelay.deposit POSTs the outer to the same-origin proxy; throws on non-OK', async () => {
  const f = stubFetch(200, { deposited: true });
  try {
    await httpOnionRelay.deposit(fakeOuter());
    assert.equal(f.calls.length, 1);
    assert.equal(f.calls[0].url, '/api/satellite/onion');
    assert.equal(f.calls[0].init!.method, 'POST');
    assert.deepEqual(JSON.parse(f.calls[0].init!.body as string), fakeOuter());
  } finally { f.restore(); }
  const bad = stubFetch(400, { error: 'bad cell' });
  try {
    await assert.rejects(() => httpOnionRelay.deposit(fakeOuter()), /HTTP 400/);
  } finally { bad.restore(); }
});

test('httpOnionRelay.poll reads .inners; [] when absent/non-array; rejects bad id with no fetch', async () => {
  const f = stubFetch(200, { inners: [{ alg: 'x' }, { alg: 'y' }] });
  try {
    const inners = await httpOnionRelay.poll(VALID_ID);
    assert.equal(inners.length, 2);
    assert.equal(f.calls[0].url, `/api/satellite/route/${VALID_ID}`);
  } finally { f.restore(); }
  const empty = stubFetch(200, { somethingElse: 1 });
  try {
    assert.deepEqual(await httpOnionRelay.poll(VALID_ID), []);
  } finally { empty.restore(); }
  // bad id: throws BEFORE any network call
  const none = stubFetch(200, { inners: [] });
  try {
    await assert.rejects(() => httpOnionRelay.poll('BAD'), /invalid route_id/);
    assert.equal(none.calls.length, 0);
  } finally { none.restore(); }
});

// ── §F5 cadence: the cover→real swap, one cell per slot, NEVER a burst ───────────────────────────────────

function countingEmitter(opts?: { coverThrows?: boolean; depositThrows?: boolean }) {
  const deposited: Array<'real' | 'cover'> = [];
  let coverCount = 0;
  const em = new CadenceEmitter({
    makeCover: () => {
      coverCount++;
      if (opts?.coverThrows) throw new Error('cover-build-fail');
      return fakeOuter(); // a cover cell is wire-indistinguishable from a real one
    },
    deposit: async (outer) => {
      if (opts?.depositThrows) throw new Error('deposit-fail');
      // tag by identity so the test can see real-vs-cover ordering (reals are the enqueued refs)
      deposited.push(reals.has(outer) ? 'real' : 'cover');
    },
  });
  const reals = new WeakSet<MailboxEnvelopePackage>();
  const enqueueReal = () => { const r = { ...fakeOuter() }; reals.add(r); em.enqueue(r); return r; };
  return { em, deposited, enqueueReal, get coverCount() { return coverCount; } };
}

test('drainSlot: idle slot emits a COVER cell (cover→real swap baseline)', async () => {
  const h = countingEmitter();
  const r = await h.em.drainSlot();
  assert.equal(r.emittedReal, false);
  assert.equal(h.coverCount, 1);
  assert.deepEqual(h.deposited, ['cover']);
});

test('drainSlot: a fan-out of N reals trickles ONE-PER-SLOT in FIFO order — never a burst', async () => {
  const h = countingEmitter();
  h.enqueueReal(); h.enqueueReal(); h.enqueueReal(); // fan-out to 3 recipients enqueued "at once"
  assert.equal(h.em.pending(), 3);

  const s1 = await h.em.drainSlot();
  const s2 = await h.em.drainSlot();
  const s3 = await h.em.drainSlot();
  const s4 = await h.em.drainSlot(); // queue now empty → cover

  assert.deepEqual([s1, s2, s3].map((s) => s.emittedReal), [true, true, true]);
  assert.equal(s4.emittedReal, false);
  // THE §F5 INVARIANT: exactly one deposit per slot, reals before cover, no cover made while reals pending
  assert.deepEqual(h.deposited, ['real', 'real', 'real', 'cover']);
  assert.equal(h.coverCount, 1); // cover only built for the one idle slot
});

test('drainSlot: exactly ONE deposit per call across a mixed sequence (no slot ever bursts)', async () => {
  const h = countingEmitter();
  let totalDeposits = 0;
  const origLen = () => h.deposited.length;
  h.enqueueReal();
  for (let i = 0; i < 5; i++) {
    const before = origLen();
    await h.em.drainSlot();
    const after = origLen();
    assert.equal(after - before, 1, 'each slot emits exactly one cell'); // the anti-burst guarantee
    totalDeposits += after - before;
    if (i === 2) h.enqueueReal(); // more reals arrive mid-stream — still one-per-slot
  }
  assert.equal(totalDeposits, 5);
});

test('drainSlot fail-closed: a deposit error is swallowed (under-reveal), never throws', async () => {
  const h = countingEmitter({ depositThrows: true });
  h.enqueueReal();
  const r = await h.em.drainSlot(); // must not reject
  assert.equal(r.emittedReal, true); // the real cell was consumed for this slot
});

test('drainSlot: a cover-build failure on an idle slot emits nothing, does not throw', async () => {
  const h = countingEmitter({ coverThrows: true });
  const r = await h.em.drainSlot();
  assert.equal(r.emittedReal, false);
  assert.deepEqual(h.deposited, []); // nothing deposited, no crash
});

test('enqueue is bounded: oldest real is dropped past maxQueue (bounded memory; dropped = under-reveal)', () => {
  const em = new CadenceEmitter({ makeCover: () => fakeOuter(), deposit: async () => {}, maxQueue: 2 });
  em.enqueue(fakeOuter()); em.enqueue(fakeOuter()); em.enqueue(fakeOuter());
  assert.equal(em.pending(), 2);
});

// ── start/stop runner (the gated §8-DEPLOYED seam) ───────────────────────────────────────────────────────

test('start validates the cadence period/jitter', () => {
  const em = new CadenceEmitter({ makeCover: () => fakeOuter(), deposit: async () => {} });
  assert.throws(() => em.start({ periodMs: 0 }), /periodMs must be > 0/);
  assert.throws(() => em.start({ periodMs: 1000, jitterMs: 1000 }), /jitterMs must be in/);
  em.stop(); // safe even though never started
});

test('start drives drainSlot on the cadence (one slot/period); stop halts it', async () => {
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const deposited: number[] = [];
  const em = new CadenceEmitter({
    makeCover: () => fakeOuter(),
    deposit: async () => { deposited.push(1); },
  });
  em.enqueue({ ...fakeOuter() }); // one real; the rest of the slots are cover
  em.start({ periodMs: 10 }); // no jitter → ~one slot every 10ms
  await sleep(55); // ~5 slots elapse
  const whileRunning = deposited.length;
  assert.ok(whileRunning >= 2, `runner should fire multiple slots, got ${whileRunning}`);
  em.stop();
  const atStop = deposited.length;
  await sleep(40); // after stop, the cadence must go silent
  assert.equal(deposited.length, atStop, 'no slots emitted after stop()');
});
