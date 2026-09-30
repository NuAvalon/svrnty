// src/lib/crypto/consent-delta.test.ts
// ADVERSARIAL refutation gate for the #558 keystone K2 §6 consent-delta.
// Each test refutes a PROTECT-THE-PERSON property — "an adversary who [X] CANNOT [Y]" — not the mechanic
// "a delta round-trips": anti-rollback (a replayed old delta can't un-private you), unforgeability (only C
// can sign C's revocation), and anti cross-peer replay (a delta for peer Y can't be redirected to peer X).
// The delivery axis (relay-blindness) is proven end-to-end through the real uniform frame + K0 seal.
// Run: npx tsx --test src/lib/crypto/consent-delta.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from './mailbox-keys.js';
import { sealToMailbox } from './mailbox-envelope.js';
import { sealOnion, peelOnion, openOnionInner } from './onion-envelope.js';
import { frameUniform, unframeUniform } from './uniform-frame.js';
import {
  buildConsentDelta,
  verifyConsentDelta,
  CONSENT_GO_PRIVATE,
  CONSENT_SCOPE_CHANGE,
  CONSENT_DELTA_WIRE_VERSION,
  type ConsentDelta,
} from './consent-delta.js';

const enc = new TextEncoder();
const fill = (byte: number, n: number) => new Uint8Array(n).fill(byte);

// C = the consent-changer (signer); peer = the recipient whose fp binds the delta.
const cSeed = fill(0xc0, 32);
const cSignPub = ed25519.getPublicKey(cSeed);
const peerBinding = ed25519.getPublicKey(fill(0x9e, 32)); // the recipient's stable identity fp bytes
const scope = enc.encode('all');

const baseDelta: ConsentDelta = { typ: CONSENT_GO_PRIVATE, epoch: 5, scope };

// ── sanity: build → verify recovers the delta; a fresh epoch over "never seen" (-1) is accepted ──────
test('sanity: a well-formed delta verifies and recovers { typ, epoch, scope }', () => {
  const payload = buildConsentDelta(baseDelta, cSeed, peerBinding);
  assert.equal(payload[0], CONSENT_DELTA_WIRE_VERSION, 'wire version byte');
  const got = verifyConsentDelta(payload, cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: -1 });
  assert.ok(got, 'verifies over a never-seen counter');
  assert.equal(got.typ, CONSENT_GO_PRIVATE);
  assert.equal(got.epoch, 5);
  assert.deepEqual(got.scope, scope);
});

// ════════════════════════════════════════════════════════════════════════
// (ANTI-ROLLBACK §6a) — a relay/attacker who REPLAYS an old "public" delta to roll back a "private" one
// CANNOT: the per-(C→peer) monotonic epoch makes the verifier reject epoch <= last-seen.
// ════════════════════════════════════════════════════════════════════════
test('(ANTI-ROLLBACK) a delta with epoch <= last-seen is rejected (a replay cannot un-private you)', () => {
  const goPrivate = buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: 7, scope }, cSeed, peerBinding);
  // The peer accepted epoch 7 (went private). An attacker now replays an OLD public-scope delta at epoch 6.
  const staleReplay = buildConsentDelta({ typ: CONSENT_SCOPE_CHANGE, epoch: 6, scope }, cSeed, peerBinding);

  assert.ok(verifyConsentDelta(goPrivate, cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: -1 }), 'epoch 7 accepted');
  assert.equal(
    verifyConsentDelta(staleReplay, cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: 7 }),
    null,
    'a replayed epoch 6 (< last-seen 7) is rejected — no rollback',
  );
  // Boundary: EQUAL epoch is also rejected (strictly monotonic — a re-send at the same counter cannot flip state).
  const equalEpoch = buildConsentDelta({ typ: CONSENT_SCOPE_CHANGE, epoch: 7, scope }, cSeed, peerBinding);
  assert.equal(
    verifyConsentDelta(equalEpoch, cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: 7 }),
    null,
    'epoch == last-seen is rejected (strictly greater required)',
  );
  // A genuine LATER change (epoch 8) is accepted — liveness preserved.
  const later = buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: 8, scope }, cSeed, peerBinding);
  assert.ok(verifyConsentDelta(later, cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: 7 }), 'epoch 8 accepted');
});

// ════════════════════════════════════════════════════════════════════════
// (UNFORGEABILITY) — an adversary who does NOT hold C's signing seed CANNOT forge or tamper a delta:
// any wrong signer key, or any mutation of typ/epoch/scope/sig, fails verification.
// ════════════════════════════════════════════════════════════════════════
test('(UNFORGEABILITY) wrong signer key and any tampered field/sig fail verification', () => {
  const payload = buildConsentDelta(baseDelta, cSeed, peerBinding);
  const wrongPub = ed25519.getPublicKey(fill(0xbad % 256, 32));

  assert.equal(
    verifyConsentDelta(payload, wrongPub, { recipientBinding: peerBinding, lastSeenEpoch: -1 }),
    null,
    'a different signer key cannot validate C\'s delta',
  );

  // Flip a byte in the SCOPE region (offset: 1 ver + [4 len + 3 "all"] typ=... ) — locate + flip inside the payload
  // body, then confirm the signature no longer covers it. We mutate the last scope byte region deterministically.
  const tamperScope = payload.slice();
  // scope bytes sit just before the trailing 64-byte sig; flip the byte right before the sig.
  tamperScope[tamperScope.length - 64 - 1] ^= 0xff;
  assert.equal(
    verifyConsentDelta(tamperScope, cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: -1 }),
    null,
    'a mutated scope byte breaks the signature',
  );

  // Tamper the signature itself.
  const tamperSig = payload.slice();
  tamperSig[tamperSig.length - 1] ^= 0x01;
  assert.equal(
    verifyConsentDelta(tamperSig, cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: -1 }),
    null,
    'a mutated signature is rejected',
  );

  // Tamper the epoch counter (8-byte BE right after the LP typ) — the signature covers it.
  const tamperEpoch = payload.slice();
  // typ = "consent/go-private" (18 bytes) → epoch starts at 1 + 4 + 18 = 23, spans 23..30; bump the low byte.
  tamperEpoch[30] ^= 0x01;
  assert.equal(
    verifyConsentDelta(tamperEpoch, cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: -1 }),
    null,
    'a mutated epoch breaks the signature',
  );
});

// ════════════════════════════════════════════════════════════════════════
// (ANTI CROSS-PEER REPLAY) — an adversary who lifts a delta C signed for peer Y and delivers it to peer X
// CANNOT get X to accept it: the recipient binding is signed, and X reconstructs the preimage with X's fp.
// ════════════════════════════════════════════════════════════════════════
test('(ANTI CROSS-PEER REPLAY) a delta bound to peer Y does not verify at peer X', () => {
  const peerY = ed25519.getPublicKey(fill(0x59, 32));
  const peerX = ed25519.getPublicKey(fill(0x58, 32));
  const forY = buildConsentDelta(baseDelta, cSeed, peerY);

  assert.ok(verifyConsentDelta(forY, cSignPub, { recipientBinding: peerY, lastSeenEpoch: -1 }), 'peer Y accepts its own delta');
  assert.equal(
    verifyConsentDelta(forY, cSignPub, { recipientBinding: peerX, lastSeenEpoch: -1 }),
    null,
    'peer X rejects a delta bound to peer Y (no cross-peer replay)',
  );
});

// ════════════════════════════════════════════════════════════════════════
// (DELIVERY / relay-blind) — end-to-end: a consent-delta rides the uniform frame + K0 seal, so the satellite
// routes it BLIND (peels routing, cannot read it is a consent change), and only the peer's DEVICE verifies it.
// ════════════════════════════════════════════════════════════════════════
test('(DELIVERY) consent-delta survives frame→inner-seal→onion→peel→open→unframe→verify, relay-blind', async () => {
  const device = generateMailboxKeypair();
  const satellite = generateMailboxKeypair();

  const payload = buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: 3, scope }, cSeed, peerBinding);
  const cell = frameUniform(payload, 'consent-delta');
  const inner = await sealToMailbox(cell, toPublicKeys(device));
  const outer = await sealOnion(inner, toPublicKeys(satellite), 'route-blinded-tag');

  // Relay peels routing but cannot read the consent semantics (inner is device-sealed).
  const peeled = await peelOnion(outer, toSecretKeys(satellite), mailboxFpOf(satellite));
  assert.ok(peeled, 'satellite peels the outer');
  assert.ok(!('mailbox_fp' in peeled.inner), 'no stable recipient id rides the peel (K0-1 blinding holds)');

  // Only the device opens + unframes + verifies.
  const openedCell = await openOnionInner(peeled.inner, toSecretKeys(device), mailboxFpOf(device));
  assert.ok(openedCell, 'device opens the inner cell');
  const un = unframeUniform(openedCell);
  assert.ok(un && un.type === 'consent-delta', 'device unframes a consent-delta cell');
  const got = verifyConsentDelta(un.payload, cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: -1 });
  assert.ok(got, 'device verifies the delta');
  assert.equal(got.epoch, 3);
});

// ── robustness + guards ────────────────────────────────────────────────────
test('robustness: verifyConsentDelta returns null (never throws) on malformed wire', () => {
  const payload = buildConsentDelta(baseDelta, cSeed, peerBinding);
  assert.equal(verifyConsentDelta(new Uint8Array(0), cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: -1 }), null, 'empty → null');
  assert.equal(verifyConsentDelta(payload.subarray(0, 10), cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: -1 }), null, 'truncated → null');
  const badVer = payload.slice(); badVer[0] = 9;
  assert.equal(verifyConsentDelta(badVer, cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: -1 }), null, 'wrong wire version → null');
  const trailing = new Uint8Array(payload.length + 1); trailing.set(payload);
  assert.equal(verifyConsentDelta(trailing, cSignPub, { recipientBinding: peerBinding, lastSeenEpoch: -1 }), null, 'trailing byte (parser ambiguity) → null');
});

test('guards: buildConsentDelta rejects oversize fields, bad epoch, empty binding', () => {
  assert.throws(() => buildConsentDelta({ typ: 'x'.repeat(65), epoch: 1, scope }, cSeed, peerBinding), /typ exceeds/);
  assert.throws(() => buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: 1, scope: fill(0, 257) }, cSeed, peerBinding), /scope exceeds/);
  assert.throws(() => buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: -1, scope }, cSeed, peerBinding), /non-negative/);
  assert.throws(() => buildConsentDelta(baseDelta, cSeed, new Uint8Array(0)), /recipientBinding/);
});
