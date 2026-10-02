// src/lib/sync/consent-delta-transport.test.ts
// ADVERSARIAL refutation gate for the consent-delta TRANSPORT (deposit over POST /onion, consume over
// GET /route/{route_id} across a window RANGE, and the real K1 route_id derivation anchored at the global
// ANCHOR_EPOCH_WEEK). Mirrors consent-delta-emit.test.ts's convention: each security-relevant test refutes
// a PROTECT-THE-PERSON property, with a positive control alongside it.
// Run: npx tsx --test src/lib/sync/consent-delta-transport.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from '../crypto/mailbox-keys.js';
import { frameUniform } from '../crypto/uniform-frame.js';
import { buildConsentDelta, CONSENT_GO_PRIVATE } from '../crypto/consent-delta.js';
import type { MailboxEnvelopePackage } from '../crypto/mailbox-envelope.js';
import { deriveSharedSecret } from '../crypto/mutual-trust.js';
import { directionTag, deriveRootRatchetKey, deriveRouteId } from '../crypto/route-ratchet.js';
import type { ApplyConsentDeltaDeps, EmitPeerTarget } from './consent-delta-emit.js';
import {
  httpOnionRelay,
  depositConsentDeltas,
  consumeConsentDeltas,
  deriveRotatingRouteId,
  deriveRouteIdWindowRange,
  createInMemoryRouteRatchetCache,
  epochWeekToAnchorWindow,
  ANCHOR_EPOCH_WEEK,
  HORIZON_WINDOWS,
  type OnionRelay,
  type ConsumeContactCandidate,
} from './consent-delta-transport.js';

const enc = new TextEncoder();
const fill = (byte: number, n: number) => new Uint8Array(n).fill(byte);
const HOUR_MS = 3600 * 1000;

// A timestamp safely AFTER the global anchor regardless of its exact value (deriveRotatingRouteId /
// deriveRouteIdWindowRange throw if asked for a window before the anchor) — 500 hours (~3 weeks) past the
// anchor's window start: comfortably larger than most test offsets, small enough to stay fast (~500 hops).
const SAFE_NOW = (epochWeekToAnchorWindow(ANCHOR_EPOCH_WEEK) + 500) * HOUR_MS;

// C = consent-changer (signer/depositor). P = recipient peer (device consuming/applying). Both now need a
// real Ed25519 IDENTITY keypair (not just a mailbox keypair) because K1 route_id derivation needs both
// sides' identity pubkeys, not just P's — new since the route_id became a real per-pair derivation.
const cSeed = fill(0xc0, 32);
const cSignPub = ed25519.getPublicKey(cSeed); // C's identity pubkey — doubles as consent-delta signer AND K1 DH input
const cFp = 'cc'.repeat(32); // C's own stable identity fp (route derivation + the local-book label P uses for C)
const pSeed = fill(0xf0, 32);
const pPub = ed25519.getPublicKey(pSeed);
const pFingerprintHex = 'ab'.repeat(32); // P's own stable identity fp (recipientBinding)

function recordingDeps(): ApplyConsentDeltaDeps & { calls: Array<[string, 'know' | 'trust', string[]]> } {
  const calls: Array<[string, 'know' | 'trust', string[]]> = [];
  return {
    calls,
    applyMutualResult: async (peerFingerprint, layer, disclosed) => {
      calls.push([peerFingerprint, layer, disclosed]);
    },
  };
}

/** Reproduces the OLD (now-removed) v1 "anchor at your own now" bug for a non-vacuous negative control:
 *  anchoring a ratchet at anchorWindow=targetWindow (zero hops) collapses to deriveRouteId applied directly
 *  to the ROOT key — a value with NO window dependence at all (deriveRootRatchetKey doesn't take a window).
 *  A session-local/per-party anchor computed this way can therefore NEVER match a correctly-rotating,
 *  globally-anchored route_id for ANY window — proving the global-anchor fix is what makes recovery work,
 *  not coincidence. */
function legacyPerPartyAnchorRoute(myEdPriv: Uint8Array, peerEdPub: Uint8Array, dir: 'lh' | 'hl'): string {
  const sAB = deriveSharedSecret(myEdPriv, peerEdPub);
  return deriveRouteId(deriveRootRatchetKey(sAB, dir));
}

/** An in-memory relay double that actually implements /onion + /route bucketing (route_id -> queue of
 *  deposited inner cells), standing in for the real S1 relay's documented behavior: peel outer, bucket
 *  inner by route_id, serve on poll. Lets the round-trip test exercise depositConsentDeltas AND
 *  consumeConsentDeltas against the SAME shared state, the way the live S1 relay will. */
function mockBlindRelay(satelliteKeys: ReturnType<typeof generateMailboxKeypair>): OnionRelay {
  const buckets = new Map<string, MailboxEnvelopePackage[]>();
  return {
    async deposit(cell) {
      // Simulate the relay peeling the OUTER with ITS OWN secret keys (this is the server-side operation —
      // peelOnion belongs here, in the relay double, never in client code; see consent-delta-transport.ts
      // module header).
      const { peelOnion } = await import('../crypto/onion-envelope.js');
      const peeled = await peelOnion(cell, toSecretKeys(satelliteKeys), mailboxFpOf(satelliteKeys));
      if (!peeled) return false;
      const bucket = buckets.get(peeled.route) ?? [];
      bucket.push(peeled.inner as unknown as MailboxEnvelopePackage);
      buckets.set(peeled.route, bucket);
      return true;
    },
    async poll(routeId) {
      return (buckets.get(routeId) ?? []) as unknown as Awaited<ReturnType<OnionRelay['poll']>>;
    },
  };
}

function onePeer(overrides: Partial<EmitPeerTarget> = {}): EmitPeerTarget {
  const device = generateMailboxKeypair();
  return {
    fingerprint: pFingerprintHex,
    deviceMailbox: toPublicKeys(device),
    epoch: 1,
    ...overrides,
  };
}

// ════════════════════════════════════════════════════════════════════════
// (HAPPY PATH, positive control) — a real go-private deposit, through a relay double that actually buckets
// by route_id, survives deposit -> poll -> open -> unframe -> apply end to end, using the REAL derived K1
// route_id (not a hand-picked literal) on both the deposit and consume sides.
// ════════════════════════════════════════════════════════════════════════
test('(ROUND TRIP) depositConsentDeltas -> mock S1 relay -> consumeConsentDeltas clears disclosed_circle', async () => {
  const satellite = generateMailboxKeypair();
  const device = generateMailboxKeypair();
  const relay = mockBlindRelay(satellite);
  const deps = recordingDeps();

  const routeId = deriveRotatingRouteId({
    myEdPriv: cSeed, myFp: cFp, peerEdPub: pPub, peerFp: pFingerprintHex,
    direction: 'outbound', cache: createInMemoryRouteRatchetCache(), now: SAFE_NOW,
  });

  const peer: EmitPeerTarget = {
    fingerprint: pFingerprintHex,
    deviceMailbox: toPublicKeys(device),
    epoch: 7,
    route: routeId,
  };

  const depositResult = await depositConsentDeltas({
    relay,
    withdrawal: { kind: 'go-private' },
    peers: [peer],
    signerSeed: cSeed,
    satellite: toPublicKeys(satellite),
  });
  assert.equal(depositResult.skipped.length, 0);
  assert.equal(depositResult.failed.length, 0);
  assert.deepEqual(depositResult.deposited, [{ fingerprint: pFingerprintHex, route: routeId }]);

  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const contacts: ConsumeContactCandidate[] = [
    { peerFingerprint: cFp, signerSignPub: cSignPub, lastSeenEpoch: -1 },
  ];
  const consumeResult = await consumeConsentDeltas({
    relay,
    contacts,
    myEdPriv: pSeed,
    myFp: pFingerprintHex,
    myDeviceSecrets: toSecretKeys(device),
    myDeviceMailboxFpHex: mailboxFpOf(device),
    myRecipientBinding: recipientBinding,
    deps,
    horizonWindows: 0, // live poll, same moment as the deposit — no catch-up needed (that's a separate test)
    now: SAFE_NOW,
  });

  assert.deepEqual(consumeResult.applied, [{ peerFingerprint: cFp, epoch: 7 }]);
  assert.equal(consumeResult.skipped.length, 0);
  assert.deepEqual(deps.calls, [[cFp, 'know', []]], 'disclosed_circle clear reached the sink exactly once');
});

// ════════════════════════════════════════════════════════════════════════
// (BLOCK MUST NEVER DEPOSIT) — through the transport wrapper, not just the raw emit leaf: a BLOCK
// withdrawal never reaches relay.deposit at all. Positive control: identical args with 'unfriend' DOES.
// ════════════════════════════════════════════════════════════════════════
test('(HARD GUARD through transport) BLOCK never calls relay.deposit; unfriend (same args) does', async () => {
  const satellite = generateMailboxKeypair();
  let depositCalls = 0;
  const countingRelay: OnionRelay = {
    deposit: async () => {
      depositCalls++;
      return true;
    },
    poll: async () => [],
  };
  const peer = onePeer();

  await assert.rejects(
    () =>
      depositConsentDeltas({
        relay: countingRelay,
        withdrawal: { kind: 'block' },
        peers: [peer],
        signerSeed: cSeed,
        satellite: toPublicKeys(satellite),
      }),
    /refus/i,
  );
  assert.equal(depositCalls, 0, 'the relay must never see a cell for a BLOCK withdrawal');

  const control = await depositConsentDeltas({
    relay: countingRelay,
    withdrawal: { kind: 'unfriend' },
    peers: [peer],
    signerSeed: cSeed,
    satellite: toPublicKeys(satellite),
  });
  assert.equal(control.deposited.length, 1);
  assert.equal(depositCalls, 1, 'unfriend (not block) legitimately reaches the relay — the guard is targeted');
});

// ════════════════════════════════════════════════════════════════════════
// (HOSTILE CELLS SKIPPED, NEVER THROW) — a relay bucket full of garbage/tampered/foreign cells must not
// crash consumeConsentDeltas and must not falsely apply; a genuine cell in the SAME batch still applies.
// ════════════════════════════════════════════════════════════════════════
test('(HOSTILE BATCH) malformed/tampered/wrong-signer cells are skipped with a reason; a genuine cell in the same batch still applies', async () => {
  const device = generateMailboxKeypair();
  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const routeId = deriveRotatingRouteId({
    myEdPriv: pSeed, myFp: pFingerprintHex, peerEdPub: cSignPub, peerFp: cFp,
    direction: 'inbound', cache: createInMemoryRouteRatchetCache(), now: SAFE_NOW,
  });

  // 1) Garbage bytes dressed up as a StrippedInner shape (valid base64 fields, meaningless content).
  const garbageCell = {
    v: 1 as const,
    alg: 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM',
    epk: Buffer.from(fill(0x01, 32)).toString('base64'),
    kem_ct: Buffer.from(fill(0x02, 1568)).toString('base64'),
    nonce: Buffer.from(fill(0x03, 12)).toString('base64'),
    ct: Buffer.from(fill(0x04, 48)).toString('base64'),
  };

  // 2) A genuine onion-sealed consent-delta cell for a DIFFERENT device (openOnionInner must fail: wrong
  //    recipient key — this simulates a cell from another pair's bucket / a confused relay).
  const otherDevice = generateMailboxKeypair();
  const wrongRecipientPayload = buildConsentDelta(
    { typ: CONSENT_GO_PRIVATE, epoch: 1, scope: enc.encode('all') },
    cSeed,
    recipientBinding,
  );
  const wrongRecipientCell = frameUniform(wrongRecipientPayload, 'consent-delta');
  const { sealToMailbox } = await import('../crypto/mailbox-envelope.js');
  const wrongRecipientInner = await sealToMailbox(wrongRecipientCell, toPublicKeys(otherDevice));
  const { mailbox_fp: _drop, ...wrongRecipientStripped } = wrongRecipientInner;
  void _drop;

  // 3) A genuine cell, correctly addressed to MY device, but signed by an IMPOSTOR (forged consent-delta).
  const impostorSeed = fill(0xee, 32);
  const impostorPayload = buildConsentDelta(
    { typ: CONSENT_GO_PRIVATE, epoch: 1, scope: enc.encode('all') },
    impostorSeed,
    recipientBinding,
  );
  const impostorCell = frameUniform(impostorPayload, 'consent-delta');
  const impostorInner = await sealToMailbox(impostorCell, toPublicKeys(device));
  const { mailbox_fp: _drop2, ...impostorStripped } = impostorInner;
  void _drop2;

  // 4) A genuine, correctly-signed, correctly-addressed cell (positive control).
  const genuinePayload = buildConsentDelta(
    { typ: CONSENT_GO_PRIVATE, epoch: 9, scope: enc.encode('all') },
    cSeed,
    recipientBinding,
  );
  const genuineCell = frameUniform(genuinePayload, 'consent-delta');
  const genuineInner = await sealToMailbox(genuineCell, toPublicKeys(device));
  const { mailbox_fp: _drop3, ...genuineStripped } = genuineInner;
  void _drop3;

  const relay: OnionRelay = {
    deposit: async () => true,
    poll: async (id) =>
      id === routeId
        ? [
            garbageCell,
            wrongRecipientStripped as never,
            impostorStripped as never,
            genuineStripped as never,
          ]
        : [],
  };

  const deps = recordingDeps();
  const contacts: ConsumeContactCandidate[] = [
    { peerFingerprint: cFp, signerSignPub: cSignPub, lastSeenEpoch: -1 },
  ];

  const result = await consumeConsentDeltas({
    relay,
    contacts,
    myEdPriv: pSeed,
    myFp: pFingerprintHex,
    myDeviceSecrets: toSecretKeys(device),
    myDeviceMailboxFpHex: mailboxFpOf(device),
    myRecipientBinding: recipientBinding,
    deps,
    horizonWindows: 0,
    now: SAFE_NOW,
  });

  assert.deepEqual(result.applied, [{ peerFingerprint: cFp, epoch: 9 }], 'only the genuine cell applied');
  assert.equal(result.skipped.length, 3, 'garbage + wrong-recipient + impostor are all skipped, never thrown');
  assert.ok(result.skipped.some((s) => s.reason === 'open-failed'), 'garbage/wrong-recipient cells fail to open');
  assert.ok(result.skipped.some((s) => s.reason === 'verify-failed'), 'impostor signature fails verification');
  assert.deepEqual(deps.calls, [[cFp, 'know', []]], 'the sink was invoked exactly once, for the genuine cell only');
});

// ── a relay that throws/errors on poll never propagates — the contact is skipped, not the whole batch ──
test('(ROBUSTNESS) a relay poll failure for one contact does not abort other contacts', async () => {
  const device = generateMailboxKeypair();
  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const badSeed = fill(0xba, 32);
  const badPub = ed25519.getPublicKey(badSeed);
  const badFp = 'ba'.repeat(32);

  const badRouteId = deriveRotatingRouteId({ myEdPriv: pSeed, myFp: pFingerprintHex, peerEdPub: badPub, peerFp: badFp, direction: 'inbound', cache: createInMemoryRouteRatchetCache(), now: SAFE_NOW });
  const goodRouteId = deriveRotatingRouteId({ myEdPriv: pSeed, myFp: pFingerprintHex, peerEdPub: cSignPub, peerFp: cFp, direction: 'inbound', cache: createInMemoryRouteRatchetCache(), now: SAFE_NOW });

  const genuinePayload = buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: 1, scope: enc.encode('all') }, cSeed, recipientBinding);
  const genuineCell = frameUniform(genuinePayload, 'consent-delta');
  const { sealToMailbox } = await import('../crypto/mailbox-envelope.js');
  const genuineInner = await sealToMailbox(genuineCell, toPublicKeys(device));
  const { mailbox_fp: _drop, ...genuineStripped } = genuineInner;
  void _drop;

  const relay: OnionRelay = {
    deposit: async () => true,
    poll: async (id) => {
      if (id === badRouteId) throw new Error('relay unreachable');
      if (id === goodRouteId) return [genuineStripped as never];
      return [];
    },
  };

  const deps = recordingDeps();
  const result = await consumeConsentDeltas({
    relay,
    contacts: [
      { peerFingerprint: badFp, signerSignPub: badPub, lastSeenEpoch: -1 },
      { peerFingerprint: cFp, signerSignPub: cSignPub, lastSeenEpoch: -1 },
    ],
    myEdPriv: pSeed,
    myFp: pFingerprintHex,
    myDeviceSecrets: toSecretKeys(device),
    myDeviceMailboxFpHex: mailboxFpOf(device),
    myRecipientBinding: recipientBinding,
    deps,
    horizonWindows: 0,
    now: SAFE_NOW,
  });

  assert.deepEqual(result.applied, [{ peerFingerprint: cFp, epoch: 1 }]);
  assert.ok(result.skipped.some((s) => s.peerFingerprint === badFp && s.reason === 'relay-poll-failed'));
});

// ════════════════════════════════════════════════════════════════════════
// (httpOnionRelay wire plumbing) — POSTs the bare sealed cell to /onion, GETs /route/{id}, and is fail-soft.
// ════════════════════════════════════════════════════════════════════════
test('httpOnionRelay — deposit POSTs the bare cell to /onion; poll GETs /route/{id} and filters non-cell entries', async () => {
  const calls: Array<{ url: string; init?: unknown }> = [];
  const cell = { v: 1, mailbox_fp: 'x'.repeat(64), epk: 'A', kem_ct: 'B', nonce: 'C', ct: 'D' } as unknown as MailboxEnvelopePackage;
  const innerLike = { v: 1, alg: 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM', epk: 'A', kem_ct: 'B', nonce: 'C', ct: 'D' };

  const fetchImpl = (async (url: unknown, init?: unknown) => {
    calls.push({ url: String(url), init });
    if (String(url).endsWith('/onion')) {
      return { ok: true, json: async () => ({}) } as unknown as Response;
    }
    if (String(url).includes('/route/')) {
      return { ok: true, json: async () => ({ cells: [innerLike, 'not-a-cell', 42, null] }) } as unknown as Response;
    }
    throw new Error('unexpected url ' + url);
  }) as unknown as typeof fetch;

  const relay = httpOnionRelay('https://sat.example/', fetchImpl);

  const ok = await relay.deposit(cell);
  assert.equal(ok, true);
  assert.equal(calls[0].url, 'https://sat.example/onion');
  assert.deepEqual(JSON.parse((calls[0].init as { body: string }).body), cell, 'POST body is the bare cell, no wrapper');

  const cells = await relay.poll('route-abc');
  assert.equal(calls[1].url, 'https://sat.example/route/route-abc');
  assert.deepEqual(cells, [innerLike], 'non-cell-shaped entries (string/number/null) are filtered, never thrown');
});

test('httpOnionRelay — fail-soft: non-2xx deposit -> false, thrown/non-2xx poll -> []', async () => {
  const relay403 = httpOnionRelay('https://sat.example', (async () => ({ ok: false, json: async () => ({}) })) as unknown as typeof fetch);
  assert.equal(await relay403.deposit({} as MailboxEnvelopePackage), false);

  const relayThrows = httpOnionRelay(
    'https://sat.example',
    (async () => {
      throw new Error('network down');
    }) as unknown as typeof fetch,
  );
  assert.equal(await relayThrows.deposit({} as MailboxEnvelopePackage), false);
  assert.deepEqual(await relayThrows.poll('r'), []);

  const relay404 = httpOnionRelay('https://sat.example', (async () => ({ ok: false, json: async () => ({}) })) as unknown as typeof fetch);
  assert.deepEqual(await relay404.poll('r'), []);
});

// ════════════════════════════════════════════════════════════════════════
// (ROUTE_ID — the real K1 derivation, anchored at the GLOBAL ANCHOR_EPOCH_WEEK; see
// consent-delta-transport.ts ★★★ ROUTE_ID GROUNDING v3 for the full finding.)
// ════════════════════════════════════════════════════════════════════════
test('(K1 ROUTE_ID) same pair+window: sender outbound and recipient inbound derive the IDENTICAL route_id', () => {
  const aSeed = fill(0xa1, 32);
  const bSeed = fill(0xb2, 32);
  const aPub = ed25519.getPublicKey(aSeed);
  const bPub = ed25519.getPublicKey(bSeed);
  const aFp = 'aa'.repeat(32);
  const bFp = 'bb'.repeat(32);

  const aOutbound = deriveRotatingRouteId({
    myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp,
    direction: 'outbound', cache: createInMemoryRouteRatchetCache(), now: SAFE_NOW,
  });
  const bInbound = deriveRotatingRouteId({
    myEdPriv: bSeed, myFp: bFp, peerEdPub: aPub, peerFp: aFp,
    direction: 'inbound', cache: createInMemoryRouteRatchetCache(), now: SAFE_NOW,
  });
  assert.equal(aOutbound, bInbound, 'A->B outbound must equal B-side inbound-from-A, same window');
  assert.match(aOutbound, /^[0-9a-f]{32}$/, '128-bit hex route_id');
});

test('(K1 ROUTE_ID) different peers -> different route_ids; same peer across windows -> rotates', () => {
  const aSeed = fill(0xa1, 32);
  const aFp = 'aa'.repeat(32);
  const bPub = ed25519.getPublicKey(fill(0xb2, 32));
  const cPub = ed25519.getPublicKey(fill(0xc3, 32));
  const bFp = 'bb'.repeat(32);
  const cFpLocal = 'cc'.repeat(32);

  const toB = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', cache: createInMemoryRouteRatchetCache(), now: SAFE_NOW });
  const toC = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: cPub, peerFp: cFpLocal, direction: 'outbound', cache: createInMemoryRouteRatchetCache(), now: SAFE_NOW });
  assert.notEqual(toB, toC, 'unlinkability: distinct peers never share a route_id');

  const cache = createInMemoryRouteRatchetCache();
  const w0 = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', cache, now: SAFE_NOW });
  const w1 = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', cache, now: SAFE_NOW + HOUR_MS });
  const w2 = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', cache, now: SAFE_NOW + 2 * HOUR_MS });
  assert.notEqual(w0, w1);
  assert.notEqual(w1, w2);
  assert.notEqual(w0, w2, 'rotates across multiple elapsed windows, not just a 2-cycle toggle');
});

test('(K1 ROUTE_ID) outbound (A->B) and inbound-as-seen-by-A are DIFFERENT chains (independent directions)', () => {
  const aSeed = fill(0xa1, 32);
  const aFp = 'aa'.repeat(32);
  const bPub = ed25519.getPublicKey(fill(0xb2, 32));
  const bFp = 'bb'.repeat(32);

  const outbound = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', cache: createInMemoryRouteRatchetCache(), now: SAFE_NOW });
  const inbound = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'inbound', cache: createInMemoryRouteRatchetCache(), now: SAFE_NOW });
  assert.notEqual(outbound, inbound, 'A->B traffic and B->A traffic must never collide on one route_id');
});

// ════════════════════════════════════════════════════════════════════════
// (deriveRouteIdWindowRange — ★ OFFLINE-POLL-DEPTH mechanics)
// ════════════════════════════════════════════════════════════════════════
test('(WINDOW RANGE) returns horizon+1 ids ending at the current window; clipped at the global anchor near launch', () => {
  const range = deriveRouteIdWindowRange({
    myEdPriv: cSeed, myFp: cFp, peerEdPub: pPub, peerFp: pFingerprintHex,
    direction: 'outbound', horizonWindows: 5, now: SAFE_NOW,
  });
  assert.equal(range.length, 6, 'inclusive [target-5, target] = 6 windows');

  const liveNow = deriveRotatingRouteId({
    myEdPriv: cSeed, myFp: cFp, peerEdPub: pPub, peerFp: pFingerprintHex,
    direction: 'outbound', cache: createInMemoryRouteRatchetCache(), now: SAFE_NOW,
  });
  assert.equal(range[range.length - 1], liveNow, 'the LAST entry in the range is the current-window route_id');
  assert.equal(new Set(range).size, 6, 'every window in the range is a distinct route_id (real rotation)');

  // Clipped at the anchor: a horizon larger than "hops since anchor" must not go negative/before it.
  const anchorWindow = epochWeekToAnchorWindow(ANCHOR_EPOCH_WEEK);
  const nearAnchorNow = (anchorWindow + 3) * HOUR_MS;
  const clipped = deriveRouteIdWindowRange({
    myEdPriv: cSeed, myFp: cFp, peerEdPub: pPub, peerFp: pFingerprintHex,
    direction: 'outbound', horizonWindows: 1000, now: nearAnchorNow,
  });
  assert.equal(clipped.length, 4, 'only 4 windows exist between the anchor and nearAnchorNow (inclusive) — cannot extend before the anchor');
});

// ════════════════════════════════════════════════════════════════════════
// (CROSS-SESSION OFFLINE, Flint's seal-critical non-vacuous test) — a deposit made at window W while the
// recipient is OFFLINE, found and applied when the recipient returns k windows later and polls the RANGE
// (fresh/independent cache — no shared runtime state beyond the global anchor). Non-vacuous controls: (1)
// polling only the current window at return-time would have missed it; (2) a session-local/per-party
// anchor (the bug this replaces) cannot recover it either, even in principle; (3) the route_id is the real
// K1 output, never a mailbox_fp/identity-fp stand-in.
// ════════════════════════════════════════════════════════════════════════
test('(CROSS-SESSION OFFLINE) recipient offline through the deposit window, returns k windows later, range-polls and finds+applies the stale deposit', async () => {
  const depositNow = SAFE_NOW;
  const offlineWindows = 10;
  const returnNow = depositNow + offlineWindows * HOUR_MS;

  const satellite = generateMailboxKeypair();
  const device = generateMailboxKeypair();
  const relay = mockBlindRelay(satellite);
  const deps = recordingDeps();

  // C deposits a real withdrawal "live" at depositNow — P is offline and never polls at this moment.
  const routeAtDeposit = deriveRotatingRouteId({
    myEdPriv: cSeed, myFp: cFp, peerEdPub: pPub, peerFp: pFingerprintHex,
    direction: 'outbound', cache: createInMemoryRouteRatchetCache(), now: depositNow,
  });
  const peer: EmitPeerTarget = { fingerprint: pFingerprintHex, deviceMailbox: toPublicKeys(device), epoch: 3, route: routeAtDeposit };
  const depositResult = await depositConsentDeltas({
    relay, withdrawal: { kind: 'unfriend' }, peers: [peer], signerSeed: cSeed, satellite: toPublicKeys(satellite),
  });
  assert.equal(depositResult.deposited.length, 1);

  // P comes online at returnNow with a FRESH process (new relay poll call, no cache/state carried over from
  // the deposit above) and range-polls — this is the real consumeConsentDeltas catch-up path.
  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const contacts: ConsumeContactCandidate[] = [{ peerFingerprint: cFp, signerSignPub: cSignPub, lastSeenEpoch: -1 }];
  const consumeResult = await consumeConsentDeltas({
    relay,
    contacts,
    myEdPriv: pSeed,
    myFp: pFingerprintHex,
    myDeviceSecrets: toSecretKeys(device),
    myDeviceMailboxFpHex: mailboxFpOf(device),
    myRecipientBinding: recipientBinding,
    deps,
    horizonWindows: HORIZON_WINDOWS,
    now: returnNow,
  });

  assert.deepEqual(consumeResult.applied, [{ peerFingerprint: cFp, epoch: 3 }], 'the while-offline deposit IS found and applied via the range poll');
  assert.deepEqual(deps.calls, [[cFp, 'know', []]]);

  // NON-VACUOUS CONTROL 1: polling ONLY the current window at returnNow would have MISSED it — the tag
  // rotated during the 10-window absence, so this isn't "it would have worked anyway".
  const currentOnlyAtReturn = deriveRotatingRouteId({
    myEdPriv: pSeed, myFp: pFingerprintHex, peerEdPub: cSignPub, peerFp: cFp,
    direction: 'inbound', cache: createInMemoryRouteRatchetCache(), now: returnNow,
  });
  assert.notEqual(currentOnlyAtReturn, routeAtDeposit, 'current-window-only polling at return time misses the stale deposit — range polling is what finds it');

  // NON-VACUOUS CONTROL 2: a session-local/per-party anchor (the v1 bug this fixes) cannot recover the
  // deposit even in principle — it is not merely "a different window", it is a fundamentally different,
  // non-rotating chain.
  const dirCtoP = directionTag(cFp, pFingerprintHex);
  const legacyRoute = legacyPerPartyAnchorRoute(pSeed, cSignPub, dirCtoP);
  assert.notEqual(legacyRoute, routeAtDeposit, 'a session-local (per-party) anchor cannot recover the deposit — this is exactly what the global anchor fixes');

  // route_id sanity: the REAL K1 derivation output (128-bit hex), never a mailbox_fp/identity-fp stand-in.
  assert.match(routeAtDeposit, /^[0-9a-f]{32}$/, '128-bit K1 route_id, structurally distinct from a 64-hex fingerprint');
  assert.notEqual(routeAtDeposit, cFp);
  assert.notEqual(routeAtDeposit, pFingerprintHex);
  assert.notEqual(routeAtDeposit, mailboxFpOf(device));
});
