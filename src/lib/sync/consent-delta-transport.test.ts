// src/lib/sync/consent-delta-transport.test.ts
// ADVERSARIAL refutation gate for the consent-delta TRANSPORT (deposit over POST /onion, consume over
// GET /route/{route_id}, and the real K1 route_id derivation). Mirrors consent-delta-emit.test.ts's
// convention: each security-relevant test refutes a PROTECT-THE-PERSON property, with a positive control
// alongside it.
// Run: npx tsx --test src/lib/sync/consent-delta-transport.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from '../crypto/mailbox-keys.js';
import { frameUniform } from '../crypto/uniform-frame.js';
import { buildConsentDelta, CONSENT_GO_PRIVATE } from '../crypto/consent-delta.js';
import type { MailboxEnvelopePackage } from '../crypto/mailbox-envelope.js';
import type { ApplyConsentDeltaDeps, EmitPeerTarget } from './consent-delta-emit.js';
import {
  httpOnionRelay,
  depositConsentDeltas,
  consumeConsentDeltas,
  deriveRotatingRouteId,
  createInMemoryRouteRatchetCache,
  type OnionRelay,
  type ConsumeContactCandidate,
} from './consent-delta-transport.js';

const enc = new TextEncoder();
const fill = (byte: number, n: number) => new Uint8Array(n).fill(byte);

// C = consent-changer (signer/depositor). P = recipient peer (device consuming/applying).
const cSeed = fill(0xc0, 32);
const cSignPub = ed25519.getPublicKey(cSeed);
const pFingerprintHex = 'ab'.repeat(32); // P's own stable identity fp (recipientBinding)
const cFingerprintInPBook = 'cd'.repeat(32); // how P's local book identifies C

function recordingDeps(): ApplyConsentDeltaDeps & { calls: Array<[string, 'know' | 'trust', string[]]> } {
  const calls: Array<[string, 'know' | 'trust', string[]]> = [];
  return {
    calls,
    applyMutualResult: async (peerFingerprint, layer, disclosed) => {
      calls.push([peerFingerprint, layer, disclosed]);
    },
  };
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
// by route_id, survives deposit -> poll -> open -> unframe -> apply end to end.
// ════════════════════════════════════════════════════════════════════════
test('(ROUND TRIP) depositConsentDeltas -> mock S1 relay -> consumeConsentDeltas clears disclosed_circle', async () => {
  const satellite = generateMailboxKeypair();
  const device = generateMailboxKeypair();
  const relay = mockBlindRelay(satellite);
  const deps = recordingDeps();

  const peer: EmitPeerTarget = {
    fingerprint: pFingerprintHex,
    deviceMailbox: toPublicKeys(device),
    epoch: 7,
    route: 'pair-c-to-p-window-123', // a real per-pair route_id would be computed by deriveRotatingRouteId;
    // a fixed literal here isolates THIS test to transport plumbing (the route-id derivation itself is
    // proven separately below).
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
  assert.deepEqual(depositResult.deposited, [{ fingerprint: pFingerprintHex, route: 'pair-c-to-p-window-123' }]);

  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const contacts: ConsumeContactCandidate[] = [
    { peerFingerprint: cFingerprintInPBook, signerSignPub: cSignPub, lastSeenEpoch: -1, routeId: 'pair-c-to-p-window-123' },
  ];
  const consumeResult = await consumeConsentDeltas({
    relay,
    contacts,
    myDeviceSecrets: toSecretKeys(device),
    myDeviceMailboxFpHex: mailboxFpOf(device),
    myRecipientBinding: recipientBinding,
    deps,
  });

  assert.deepEqual(consumeResult.applied, [{ peerFingerprint: cFingerprintInPBook, epoch: 7 }]);
  assert.equal(consumeResult.skipped.length, 0);
  assert.deepEqual(deps.calls, [[cFingerprintInPBook, 'know', []]], 'disclosed_circle clear reached the sink exactly once');
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
  const satellite = generateMailboxKeypair();
  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const routeId = 'hostile-batch-route';

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
    { peerFingerprint: cFingerprintInPBook, signerSignPub: cSignPub, lastSeenEpoch: -1, routeId },
  ];

  const result = await consumeConsentDeltas({
    relay,
    contacts,
    myDeviceSecrets: toSecretKeys(device),
    myDeviceMailboxFpHex: mailboxFpOf(device),
    myRecipientBinding: recipientBinding,
    deps,
  });

  assert.deepEqual(result.applied, [{ peerFingerprint: cFingerprintInPBook, epoch: 9 }], 'only the genuine cell applied');
  assert.equal(result.skipped.length, 3, 'garbage + wrong-recipient + impostor are all skipped, never thrown');
  assert.ok(result.skipped.some((s) => s.reason === 'open-failed'), 'garbage/wrong-recipient cells fail to open');
  assert.ok(result.skipped.some((s) => s.reason === 'verify-failed'), 'impostor signature fails verification');
  assert.deepEqual(deps.calls, [[cFingerprintInPBook, 'know', []]], 'the sink was invoked exactly once, for the genuine cell only');
});

// ── a relay that throws/errors on poll never propagates — the contact is skipped, not the whole batch ──
test('(ROBUSTNESS) a relay poll failure for one contact does not abort other contacts', async () => {
  const device = generateMailboxKeypair();
  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const goodRouteId = 'good-route';
  const badRouteId = 'bad-route';

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
      return [genuineStripped as never];
    },
  };

  const deps = recordingDeps();
  const result = await consumeConsentDeltas({
    relay,
    contacts: [
      { peerFingerprint: 'bad-contact', signerSignPub: cSignPub, lastSeenEpoch: -1, routeId: badRouteId },
      { peerFingerprint: cFingerprintInPBook, signerSignPub: cSignPub, lastSeenEpoch: -1, routeId: goodRouteId },
    ],
    myDeviceSecrets: toSecretKeys(device),
    myDeviceMailboxFpHex: mailboxFpOf(device),
    myRecipientBinding: recipientBinding,
    deps,
  });

  assert.deepEqual(result.applied, [{ peerFingerprint: cFingerprintInPBook, epoch: 1 }]);
  assert.ok(result.skipped.some((s) => s.peerFingerprint === 'bad-contact' && s.reason === 'relay-poll-failed'));
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
// (ROUTE_ID — the real K1 derivation, anchored at establishedEpochWeek; see consent-delta-transport.ts
// ★★★ ROUTE_ID GROUNDING v2 for the full finding, including the TrustCommitment-is-dead-code gap.)
// ════════════════════════════════════════════════════════════════════════
const EPOCH_WEEK_SECONDS = 604_800; // mirrors mutual-trust.ts's non-exported constant (see module header)
function epochWeekOf(nowMs: number): number {
  return Math.floor(nowMs / 1000 / EPOCH_WEEK_SECONDS);
}

test('(K1 ROUTE_ID) same pair+window: sender outbound and recipient inbound derive the IDENTICAL route_id', () => {
  const aSeed = fill(0xa1, 32);
  const bSeed = fill(0xb2, 32);
  const aPub = ed25519.getPublicKey(aSeed);
  const bPub = ed25519.getPublicKey(bSeed);
  const aFp = 'aa'.repeat(32);
  const bFp = 'bb'.repeat(32);
  const now = 1_780_000_000_000;
  const establishedEpochWeek = epochWeekOf(now) - 1; // established a week before "now"

  const aOutbound = deriveRotatingRouteId({
    myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp,
    direction: 'outbound', establishedEpochWeek, cache: createInMemoryRouteRatchetCache(), now,
  });
  const bInbound = deriveRotatingRouteId({
    myEdPriv: bSeed, myFp: bFp, peerEdPub: aPub, peerFp: aFp,
    direction: 'inbound', establishedEpochWeek, cache: createInMemoryRouteRatchetCache(), now,
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
  const cFp = 'cc'.repeat(32);
  const now = 1_780_000_000_000;
  const establishedEpochWeek = epochWeekOf(now) - 1;

  const toB = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', establishedEpochWeek, cache: createInMemoryRouteRatchetCache(), now });
  const toC = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: cPub, peerFp: cFp, direction: 'outbound', establishedEpochWeek, cache: createInMemoryRouteRatchetCache(), now });
  assert.notEqual(toB, toC, 'unlinkability: distinct peers never share a route_id');

  const cache = createInMemoryRouteRatchetCache();
  const windowMs = 3600 * 1000;
  const w0 = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', establishedEpochWeek, cache, now });
  const w1 = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', establishedEpochWeek, cache, now: now + windowMs });
  const w2 = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', establishedEpochWeek, cache, now: now + 2 * windowMs });
  assert.notEqual(w0, w1);
  assert.notEqual(w1, w2);
  assert.notEqual(w0, w2, 'rotates across multiple elapsed windows, not just a 2-cycle toggle');
});

test('(K1 ROUTE_ID) outbound (A->B) and inbound-as-seen-by-A are DIFFERENT chains (independent directions)', () => {
  const aSeed = fill(0xa1, 32);
  const aFp = 'aa'.repeat(32);
  const bPub = ed25519.getPublicKey(fill(0xb2, 32));
  const bFp = 'bb'.repeat(32);
  const now = 1_780_000_000_000;
  const establishedEpochWeek = epochWeekOf(now) - 1;

  const outbound = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', establishedEpochWeek, cache: createInMemoryRouteRatchetCache(), now });
  const inbound = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'inbound', establishedEpochWeek, cache: createInMemoryRouteRatchetCache(), now });
  assert.notEqual(outbound, inbound, 'A->B traffic and B->A traffic must never collide on one route_id');
});

// ════════════════════════════════════════════════════════════════════════
// (CROSS-SESSION — the non-vacuous seal criterion) — two parties who bootstrap their RouteRatchet at
// COMPLETELY DIFFERENT real moments (fresh, independent in-memory caches — no shared runtime state
// whatsoever beyond the shared establishedEpochWeek) MUST derive the SAME route_id for the SAME target
// window. This is the property v1 (anchor-at-"now") provably did NOT have.
// ════════════════════════════════════════════════════════════════════════
test('(CROSS-SESSION) recipient offline during deposit, polls days later — same establishedEpochWeek, fresh independent caches, still matches', () => {
  const aSeed = fill(0xa1, 32); // depositor (goes private)
  const bSeed = fill(0xb2, 32); // recipient (was offline)
  const aPub = ed25519.getPublicKey(aSeed);
  const bPub = ed25519.getPublicKey(bSeed);
  const aFp = 'aa'.repeat(32);
  const bFp = 'bb'.repeat(32);

  const depositMoment = 1_780_000_000_000; // A deposits "live", right now
  const establishedEpochWeek = epochWeekOf(depositMoment) - 3; // contact established 3 weeks earlier
  const DAY_MS = 24 * 3600 * 1000;
  const pollMomentDaysLater = depositMoment + 4 * DAY_MS; // B only resumes polling 4 days later

  // A: a fresh process/cache depositing live at depositMoment.
  const routeAtDeposit = deriveRotatingRouteId({
    myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp,
    direction: 'outbound', establishedEpochWeek, cache: createInMemoryRouteRatchetCache(), now: depositMoment,
  });

  // B: a TOTALLY SEPARATE fresh cache (simulating a different process/session with zero runtime state
  // carried over from A's computation) going back to check the EXACT window A deposited in — exactly what
  // a real consume-with-backfill loop does after being offline. B's ratchet object is constructed for the
  // first time HERE, days after A's, yet must reproduce A's bucket.
  const routeBForDepositWindow = deriveRotatingRouteId({
    myEdPriv: bSeed, myFp: bFp, peerEdPub: aPub, peerFp: aFp,
    direction: 'inbound', establishedEpochWeek, cache: createInMemoryRouteRatchetCache(), now: depositMoment,
  });
  assert.equal(
    routeBForDepositWindow,
    routeAtDeposit,
    'B, bootstrapping its ratchet days later in a fresh independent cache, must still reconstruct the EXACT bucket A deposited to',
  );

  // And B's OWN current-window query (days later) is a genuinely DIFFERENT, rotated-forward bucket — proof
  // this isn't a non-rotating constant masquerading as a fix.
  const routeBNow = deriveRotatingRouteId({
    myEdPriv: bSeed, myFp: bFp, peerEdPub: aPub, peerFp: aFp,
    direction: 'inbound', establishedEpochWeek, cache: createInMemoryRouteRatchetCache(), now: pollMomentDaysLater,
  });
  assert.notEqual(routeBNow, routeBForDepositWindow, "B's current (4-days-later) bucket has rotated away from the deposit-time bucket");
});

test('(NEGATIVE CONTROL) a different establishedEpochWeek for the same pair+window yields a DIFFERENT route_id', () => {
  const aSeed = fill(0xa1, 32);
  const aFp = 'aa'.repeat(32);
  const bPub = ed25519.getPublicKey(fill(0xb2, 32));
  const bFp = 'bb'.repeat(32);
  const now = 1_780_000_000_000;
  const weekX = epochWeekOf(now) - 3;

  const r1 = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', establishedEpochWeek: weekX, cache: createInMemoryRouteRatchetCache(), now });
  const r2 = deriveRotatingRouteId({ myEdPriv: aSeed, myFp: aFp, peerEdPub: bPub, peerFp: bFp, direction: 'outbound', establishedEpochWeek: weekX - 1, cache: createInMemoryRouteRatchetCache(), now });
  assert.notEqual(r1, r2, 'the anchor actually matters — a wrong/mismatched establishedEpochWeek does not accidentally still match');
});
