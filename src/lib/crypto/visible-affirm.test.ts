// src/lib/crypto/visible-affirm.test.ts
// ADVERSARIAL refutation gate for the piece-2 mutual-block payload (task #579, spec KB#92246, §F seal KB#92252).
// Each test refutes a PROTECT-THE-SURVIVOR property — "an adversary who [X] CANNOT [Y]" — not the mechanic
// "an affirmative round-trips":
//   · anti-rollback (a replayed stale affirmative can't extend/resurrect a shorter-lived one),
//   · unforgeability (only F can sign F's visible-affirm),
//   · anti cross-peer replay (an affirm for peer Y can't be redirected to surface F at peer X),
//   · §F1a tamper-proof validity (valid_until is INSIDE the signature — a relay can't extend it),
//   · §F1b expiry (an EXPIRED affirmative surfaces no one — the block bites by absence),
//   · §F1c cap (a far-future validity is rejected — the ≤20min block-latency bound holds BY CONSTRUCTION).
// Run: npx tsx --test src/lib/crypto/visible-affirm.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  buildVisibleAffirm,
  verifyVisibleAffirm,
  isAffirmFresh,
  MAX_AFFIRM_TTL_SECONDS,
  VISIBLE_AFFIRM_WIRE_VERSION,
  type VisibleAffirm,
} from './visible-affirm.js';

const fill = (byte: number, n: number) => new Uint8Array(n).fill(byte);

// F = the party affirming visibility (signer); recipient = the viewer whose fp binds the affirm.
const fSeed = fill(0xf0, 32);
const fSignPub = ed25519.getPublicKey(fSeed);
const recipientBinding = ed25519.getPublicKey(fill(0x9e, 32)); // the viewer's stable identity fp bytes

// A deterministic "now" (unix seconds) — the test drives the clock explicitly (the module reads no wall-clock).
const NOW = 1_700_000_000;
const EMIT_TTL = MAX_AFFIRM_TTL_SECONDS - 60; // emit headroom under the cap for clock skew (emit-side policy)
const base: VisibleAffirm = { epoch: 5, validUntil: NOW + EMIT_TTL };

// ── sanity: build → verify recovers the affirmative over a never-seen counter + a live clock ──────────
test('sanity: a well-formed, unexpired affirm verifies and recovers { epoch, validUntil }', () => {
  const payload = buildVisibleAffirm(base, fSeed, recipientBinding);
  assert.equal(payload[0], VISIBLE_AFFIRM_WIRE_VERSION, 'wire version byte');
  assert.equal(payload.length, 81, 'fixed 81-byte payload — no variable field, length-uniform before frame');
  const got = verifyVisibleAffirm(payload, fSignPub, { recipientBinding, lastSeenEpoch: -1, now: NOW });
  assert.ok(got, 'verifies over a never-seen counter + a live clock');
  assert.equal(got.epoch, 5);
  assert.equal(got.validUntil, NOW + EMIT_TTL);
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (ANTI-ROLLBACK §F1b) — a relay/attacker who REPLAYS an older affirmative CANNOT use it to override a
// fresher one: the per-(F→recipient) monotonic epoch makes the verifier reject epoch <= last-seen. (With
// epoch coupled to valid_until, this is what stops a stale near-expiry affirm being replayed over a renewal.)
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(ANTI-ROLLBACK) an affirm with epoch <= last-seen is rejected (a replay cannot override a renewal)', () => {
  const renewal = buildVisibleAffirm({ epoch: 7, validUntil: NOW + EMIT_TTL }, fSeed, recipientBinding);
  assert.ok(verifyVisibleAffirm(renewal, fSignPub, { recipientBinding, lastSeenEpoch: -1, now: NOW }), 'epoch 7 accepted');
  // The viewer has now accepted epoch 7. A relay replays an OLD epoch-6 affirmative.
  const staleReplay = buildVisibleAffirm({ epoch: 6, validUntil: NOW + EMIT_TTL }, fSeed, recipientBinding);
  assert.equal(
    verifyVisibleAffirm(staleReplay, fSignPub, { recipientBinding, lastSeenEpoch: 7, now: NOW }),
    null,
    'epoch 6 <= last-seen 7 → rejected',
  );
  // Equal epoch is also rejected (strict monotonic).
  const equalEpoch = buildVisibleAffirm({ epoch: 7, validUntil: NOW + EMIT_TTL }, fSeed, recipientBinding);
  assert.equal(verifyVisibleAffirm(equalEpoch, fSignPub, { recipientBinding, lastSeenEpoch: 7, now: NOW }), null, 'epoch == last-seen → rejected');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (UNFORGEABILITY) — an adversary who does NOT hold F's seed CANNOT mint an affirmative that surfaces F:
// the signature verifies only under F's real signing pubkey.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(UNFORGEABILITY) an affirm signed by a non-F seed does not verify under F pubkey', () => {
  const impostorSeed = fill(0xbb, 32);
  const forged = buildVisibleAffirm(base, impostorSeed, recipientBinding);
  assert.equal(verifyVisibleAffirm(forged, fSignPub, { recipientBinding, lastSeenEpoch: -1, now: NOW }), null, 'wrong signer → null');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (ANTI CROSS-PEER REPLAY) — an affirmative F signs FOR peer Y CANNOT be redirected to surface F at peer X:
// the recipient binding is signed (not on the wire); X reconstructs the preimage with X's own binding → fail.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(ANTI CROSS-PEER REPLAY) an affirm bound to peer Y fails at peer X', () => {
  const peerY = recipientBinding;
  const peerX = ed25519.getPublicKey(fill(0x11, 32));
  const forPeerY = buildVisibleAffirm(base, fSeed, peerY);
  assert.ok(verifyVisibleAffirm(forPeerY, fSignPub, { recipientBinding: peerY, lastSeenEpoch: -1, now: NOW }), 'verifies at Y');
  assert.equal(
    verifyVisibleAffirm(forPeerY, fSignPub, { recipientBinding: peerX, lastSeenEpoch: -1, now: NOW }),
    null,
    'same bytes fail at X — cannot redirect F’s visibility to an unintended viewer',
  );
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (§F1a TAMPER-PROOF VALIDITY) — a relay who flips bytes of valid_until on the wire to EXTEND an affirm's
// life CANNOT: valid_until is inside the signed preimage, so any edit breaks the signature.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(§F1a) tampering valid_until on the wire breaks the signature', () => {
  const payload = buildVisibleAffirm(base, fSeed, recipientBinding);
  // valid_until occupies bytes [9..17). Bump the low byte → a later expiry.
  const tampered = payload.slice();
  tampered[16] = (tampered[16] + 1) & 0xff;
  assert.equal(verifyVisibleAffirm(tampered, fSignPub, { recipientBinding, lastSeenEpoch: -1, now: NOW }), null, 'extended validity → sig fails');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (§F1b EXPIRY) — once F stops renewing, the held affirmative EXPIRES and surfaces no one. An expired
// affirmative (now >= valid_until) is rejected at accept time; the pure predicate hides F at reveal time.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(§F1b EXPIRY) an expired affirmative is rejected at accept and hidden at reveal', () => {
  const payload = buildVisibleAffirm({ epoch: 5, validUntil: NOW + 10 }, fSeed, recipientBinding);
  // Accept-time: a clock past valid_until rejects it.
  assert.equal(verifyVisibleAffirm(payload, fSignPub, { recipientBinding, lastSeenEpoch: -1, now: NOW + 10 }), null, 'now == valid_until → expired');
  assert.equal(verifyVisibleAffirm(payload, fSignPub, { recipientBinding, lastSeenEpoch: -1, now: NOW + 11 }), null, 'now > valid_until → expired');
  // Reveal-time predicate: fresh while now < valid_until, hidden once reached.
  assert.equal(isAffirmFresh(NOW + 10, NOW + 9), true, 'fresh just before expiry');
  assert.equal(isAffirmFresh(NOW + 10, NOW + 10), false, 'hidden at expiry (block bites by absence)');
  assert.equal(isAffirmFresh(NOW + 10, NOW + 100), false, 'hidden well past expiry');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (§F1c CAP — THE BLOCK-LATENCY BOUND) — a buggy/hostile emitter who signs a FAR-FUTURE valid_until to keep
// itself surfaceable past a block CANNOT: the verifier rejects valid_until > now + MAX_AFFIRM_TTL. This is
// what makes block-latency ≤ 20min BY CONSTRUCTION (Hypatia copy KB#92254).
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(§F1c CAP) a valid_until beyond now + MAX_AFFIRM_TTL is rejected (block-latency bound holds)', () => {
  const atCap = buildVisibleAffirm({ epoch: 5, validUntil: NOW + MAX_AFFIRM_TTL_SECONDS }, fSeed, recipientBinding);
  assert.ok(verifyVisibleAffirm(atCap, fSignPub, { recipientBinding, lastSeenEpoch: -1, now: NOW }), 'exactly at cap accepted');
  const pastCap = buildVisibleAffirm({ epoch: 5, validUntil: NOW + MAX_AFFIRM_TTL_SECONDS + 1 }, fSeed, recipientBinding);
  assert.equal(verifyVisibleAffirm(pastCap, fSignPub, { recipientBinding, lastSeenEpoch: -1, now: NOW }), null, '1s past cap → rejected');
  const farFuture = buildVisibleAffirm({ epoch: 5, validUntil: NOW + 365 * 24 * 3600 }, fSeed, recipientBinding);
  assert.equal(verifyVisibleAffirm(farFuture, fSignPub, { recipientBinding, lastSeenEpoch: -1, now: NOW }), null, 'a year out → rejected');
});

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// (HOSTILE INPUT) — the relay controls these bytes; verify never throws, returns null on any malformation.
// ════════════════════════════════════════════════════════════════════════════════════════════════════
test('(HOSTILE INPUT) malformed payloads return null, never throw', () => {
  const good = buildVisibleAffirm(base, fSignPub && base ? fSeed : fSeed, recipientBinding);
  const opts = { recipientBinding, lastSeenEpoch: -1, now: NOW };
  assert.equal(verifyVisibleAffirm(new Uint8Array(0), fSignPub, opts), null, 'empty');
  assert.equal(verifyVisibleAffirm(good.slice(0, 80), fSignPub, opts), null, 'truncated (80 bytes)');
  assert.equal(verifyVisibleAffirm(new Uint8Array(82), fSignPub, opts), null, 'overlong (82 bytes)');
  const badVer = good.slice(); badVer[0] = 2;
  assert.equal(verifyVisibleAffirm(badVer, fSignPub, opts), null, 'unknown version');
  assert.equal(verifyVisibleAffirm(good, new Uint8Array(31), opts), null, 'bad pubkey length');
  assert.equal(verifyVisibleAffirm(good, fSignPub, { recipientBinding: new Uint8Array(0), lastSeenEpoch: -1, now: NOW }), null, 'empty binding');
  // A non-integer lastSeenEpoch is rejected at runtime (never coerced into a wider accept).
  assert.equal(verifyVisibleAffirm(good, fSignPub, { recipientBinding, lastSeenEpoch: 0.5, now: NOW }), null, 'non-int epoch floor');
  assert.equal(verifyVisibleAffirm(good, fSignPub, { recipientBinding, lastSeenEpoch: -1, now: Number.NaN }), null, 'NaN clock → fail-closed');
});

// ── build-side guardrails: the emitter can't mint a structurally invalid affirmative ──────────────────
test('build rejects malformed inputs (negative/oversize counters, bad seed/binding)', () => {
  assert.throws(() => buildVisibleAffirm({ epoch: -1, validUntil: NOW }, fSeed, recipientBinding), /epoch/);
  assert.throws(() => buildVisibleAffirm({ epoch: 0, validUntil: -5 }, fSeed, recipientBinding), /validUntil/);
  assert.throws(() => buildVisibleAffirm(base, fill(0, 31), recipientBinding), /seed/i);
  assert.throws(() => buildVisibleAffirm(base, fSeed, new Uint8Array(0)), /recipientBinding/);
});
