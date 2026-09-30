// src/lib/crypto/uniform-frame.test.ts
// ADVERSARIAL refutation gate for the #558 keystone K2 uniform frame (Flint Finding-#1, KB#91381).
// Each test refutes a PROTECT-THE-PERSON property — "an adversary who PEELS the outer shell CANNOT [X]" —
// across the THREE axes Flint flagged (type / SIZE / fwd-pointer), NOT the mechanic "the frame pads."
// SIZE is the green-flatter (a type-tag-stripped-but-unpadded frame still fingerprints the kind by LENGTH),
// so it is proven with MAXIMALLY size-divergent inputs + a POSITIVE CONTROL that the unframed path DOES leak.
// Everything is sealed through the REAL K0 sealOnion (onion-envelope.ts) + K1 route_id (route-ratchet.ts) —
// the wire a hosted satellite actually sees — never a stand-in.
// Run: npx tsx --test src/lib/crypto/uniform-frame.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from './mailbox-keys.js';
import { sealToMailbox, openMailboxEnvelope } from './mailbox-envelope.js';
import { sealOnion, peelOnion, openOnionInner } from './onion-envelope.js';
import { deriveSharedSecret } from './mutual-trust.js';
import { RouteRatchet, directionTag } from './route-ratchet.js';
import {
  frameUniform,
  unframeUniform,
  FRAME_BYTES,
  FRAME_MAX_PAYLOAD,
  FRAME_VERSION,
  type FrameType,
} from './uniform-frame.js';

// ── fixtures ─────────────────────────────────────────────────────────────
const fill = (byte: number, n: number) => new Uint8Array(n).fill(byte);
const ANCHOR = 480_000;
const W = ANCHOR + 7;

/** A sender A and a recipient identity, with the recipient's DEVICE + SATELLITE mailbox keypairs and the
 *  K1 route_id(A→recipient) for this window — everything needed to put a framed payload on the real wire. */
function makeChannel(senderSeedByte: number, recipSeedByte: number) {
  const senderSeed = fill(senderSeedByte, 32);
  const recipSeed = fill(recipSeedByte, 32);
  const senderFp = bytesToHex(ed25519.getPublicKey(senderSeed));
  const recipFp = bytesToHex(ed25519.getPublicKey(recipSeed));
  const s_AB = deriveSharedSecret(senderSeed, ed25519.getPublicKey(recipSeed));
  const routeId = RouteRatchet.init(s_AB, directionTag(senderFp, recipFp), ANCHOR, W).currentRouteId();
  return { device: generateMailboxKeypair(), satellite: generateMailboxKeypair(), routeId };
}

/** Put a framed cell on the real wire: frame → inner-seal to DEVICE → onion-seal to SATELLITE by route_id. */
async function toWire(payload: Uint8Array, type: FrameType, ch: ReturnType<typeof makeChannel>) {
  const cell = frameUniform(payload, type);
  const inner = await sealToMailbox(cell, toPublicKeys(ch.device));
  return sealOnion(inner, toPublicKeys(ch.satellite), ch.routeId);
}

// The three sensitive kinds, at MAXIMALLY divergent raw sizes (the adversarial size spread):
const CONSENT = { payload: fill(0xc1, 90), type: 'consent-delta' as FrameType };   // small signed record
const DISTRESS = { payload: fill(0xd1, 1), type: 'distress' as FrameType };        // a 1-byte cry
const MESSAGE = { payload: fill(0x11, FRAME_MAX_PAYLOAD), type: 'message' as FrameType }; // a full single cell

// ── sanity: the frame is a constant-size cell and round-trips through the whole K0 stack ───────────────
test('sanity: frame is constant-size and round-trips frame→seal→peel→open→unframe byte-exact', async () => {
  const ch = makeChannel(0x11, 0x22);
  for (const kind of [CONSENT, DISTRESS, MESSAGE]) {
    const cell = frameUniform(kind.payload, kind.type);
    assert.equal(cell.length, FRAME_BYTES, 'every cell is exactly FRAME_BYTES');

    const outer = await toWire(kind.payload, kind.type, ch);
    const peeled = await peelOnion(outer, toSecretKeys(ch.satellite), mailboxFpOf(ch.satellite));
    assert.ok(peeled, 'satellite peels the outer');
    const openedCell = await openOnionInner(peeled.inner, toSecretKeys(ch.device), mailboxFpOf(ch.device));
    assert.ok(openedCell, 'device opens the inner cell');
    const un = unframeUniform(openedCell);
    assert.ok(un, 'device unframes the cell');
    assert.equal(un.type, kind.type, 'kind recovered exactly');
    assert.deepEqual(un.payload, kind.payload, 'payload recovered byte-exact');
  }
});

// ════════════════════════════════════════════════════════════════════════
// (SIZE) — the green-flatter axis, adversarial.
// An adversary who PEELS the outer shell CANNOT tell a tiny consent-delta from a full message from a 1-byte
// distress by LENGTH: every kind seals to a byte-length-IDENTICAL wire. Proven with maximally size-divergent
// inputs, and a POSITIVE CONTROL that the UNFRAMED path DOES leak (so the test can actually fail).
// ════════════════════════════════════════════════════════════════════════
test('(SIZE) framed consent/message/distress are byte-length-identical on the wire AND to a peeling satellite', async () => {
  const ch = makeChannel(0x11, 0x22);
  const outers = await Promise.all([
    toWire(CONSENT.payload, CONSENT.type, ch),
    toWire(MESSAGE.payload, MESSAGE.type, ch),
    toWire(DISTRESS.payload, DISTRESS.type, ch),
  ]);

  // What an on-path observer sees: the OUTER package. Every field length identical across the three kinds.
  const [oc, om, od] = outers;
  for (const f of ['ct', 'epk', 'kem_ct', 'nonce'] as const) {
    assert.equal(oc[f].length, om[f].length, `outer.${f} length identical: consent vs message`);
    assert.equal(oc[f].length, od[f].length, `outer.${f} length identical: consent vs distress`);
  }

  // What a PEELING hosted satellite sees: the inner.ct it routes. Identical length across kinds → the peel
  // reveals no size fingerprint either (this is the axis a "type-tag-stripped" frame would still leak).
  const peels = await Promise.all(
    outers.map((o) => peelOnion(o, toSecretKeys(ch.satellite), mailboxFpOf(ch.satellite))),
  );
  assert.ok(peels.every(Boolean), 'satellite peels all three');
  const innerCtLens = peels.map((p) => p!.inner.ct.length);
  assert.equal(innerCtLens[0], innerCtLens[1], 'peeled inner.ct length identical: consent vs message');
  assert.equal(innerCtLens[0], innerCtLens[2], 'peeled inner.ct length identical: consent vs distress');

  // POSITIVE CONTROL — the test is not vacuous: WITHOUT the frame, the same three payloads seal to DIFFERENT
  // inner.ct lengths (raw size leaks the kind). The frame is what removes the signal; if it stopped padding,
  // this asserts the leak reappears and the test fails.
  const rawConsent = await sealToMailbox(CONSENT.payload, toPublicKeys(ch.device));
  const rawMessage = await sealToMailbox(MESSAGE.payload, toPublicKeys(ch.device));
  assert.notEqual(rawConsent.ct.length, rawMessage.ct.length, 'unframed payloads DO leak size (control holds)');
});

// ════════════════════════════════════════════════════════════════════════
// (TYPE) — type-opacity.
// An adversary who PEELS the outer shell CANNOT recover the kind: the type byte lives INSIDE the device-sealed
// cell. Two DIFFERENT kinds of the SAME length are indistinguishable to the satellite; only the DEVICE reads
// the kind (positive control).
// ════════════════════════════════════════════════════════════════════════
test('(TYPE) a peeling satellite cannot read the kind; only the device can', async () => {
  const ch = makeChannel(0x11, 0x22);
  const samePayload = fill(0x77, 90);
  const asConsent = await toWire(samePayload, 'consent-delta', ch);
  const asDistress = await toWire(samePayload, 'distress', ch);

  const pConsent = await peelOnion(asConsent, toSecretKeys(ch.satellite), mailboxFpOf(ch.satellite));
  const pDistress = await peelOnion(asDistress, toSecretKeys(ch.satellite), mailboxFpOf(ch.satellite));
  assert.ok(pConsent && pDistress);

  // The satellite holds the peeled inner but its OWN secrets cannot open it → it cannot read the type byte.
  const satRead = await openMailboxEnvelope(
    { ...pConsent.inner, mailbox_fp: mailboxFpOf(ch.satellite) },
    toSecretKeys(ch.satellite),
    mailboxFpOf(ch.satellite),
  );
  assert.equal(satRead, null, 'satellite cannot open the inner cell → cannot read the kind');

  // Same length either way (kind carries no size signal); the peeled inner.ct is the same length for both.
  assert.equal(pConsent.inner.ct.length, pDistress.inner.ct.length, 'consent vs distress: identical peeled length');

  // POSITIVE CONTROL — the DEVICE recovers the kind correctly (the property is "hidden from the relay", not
  // "destroyed"): each opens to its true type.
  const cCell = await openOnionInner(pConsent.inner, toSecretKeys(ch.device), mailboxFpOf(ch.device));
  const dCell = await openOnionInner(pDistress.inner, toSecretKeys(ch.device), mailboxFpOf(ch.device));
  assert.equal(unframeUniform(cCell!)!.type, 'consent-delta', 'device reads consent-delta');
  assert.equal(unframeUniform(dCell!)!.type, 'distress', 'device reads distress');
});

// ════════════════════════════════════════════════════════════════════════
// (FWD-POINTER) — fan-out blinding.
// An adversary who sees a consent-delta FANNED OUT to N contacts CANNOT link the N envelopes as one event:
// each rides its own K1 route_id (blinded, per-edge, per-window), and all N are byte-length-identical. A
// synchronized broadcast is indistinguishable from N independent single-cell deliveries.
// ════════════════════════════════════════════════════════════════════════
test('(FWD-POINTER) a consent-delta fanned out to 3 contacts is unlinkable + length-uniform across recipients', async () => {
  // One sender A; three recipients B, C, D — distinct edges ⇒ distinct s_AB ⇒ distinct route_ids (K1 unlinkability).
  const chB = makeChannel(0x11, 0x22);
  const chC = makeChannel(0x11, 0x33);
  const chD = makeChannel(0x11, 0x44);
  const delta = fill(0xc1, 90); // the SAME consent-delta to all three

  const outers = await Promise.all([
    toWire(delta, 'consent-delta', chB),
    toWire(delta, 'consent-delta', chC),
    toWire(delta, 'consent-delta', chD),
  ]);

  // Fwd-pointer axis: the route_ids the satellite routes by are pairwise DISTINCT and share no derivable
  // relation (K1 property: distinct s_AB per edge). No stable cleartext groups the fan-out.
  const routes = [chB.routeId, chC.routeId, chD.routeId];
  assert.equal(new Set(routes).size, 3, 'three recipients ⇒ three distinct blinded route_ids');
  for (const r of routes) assert.equal(r.length, 32, 'each route_id is a 16-byte blinded tag (no identity)');

  // Size axis holds ACROSS the fan-out: every recipient's envelope is byte-length-identical → the fan-out
  // cannot be picked out by a per-recipient size difference.
  const cts = outers.map((o) => o.ct.length);
  assert.equal(cts[0], cts[1], 'fan-out envelope length identical: B vs C');
  assert.equal(cts[0], cts[2], 'fan-out envelope length identical: B vs D');

  // And the route each envelope actually carries is the blinded id, not any recipient identity fingerprint.
  const peeled = await Promise.all([
    peelOnion(outers[0], toSecretKeys(chB.satellite), mailboxFpOf(chB.satellite)),
    peelOnion(outers[1], toSecretKeys(chC.satellite), mailboxFpOf(chC.satellite)),
    peelOnion(outers[2], toSecretKeys(chD.satellite), mailboxFpOf(chD.satellite)),
  ]);
  assert.deepEqual(peeled.map((p) => p!.route), routes, 'each outer routes by its blinded route_id');
});

// ── robustness: hostile input never throws; oversize never silently truncates ─────────────────────────
test('robustness: unframeUniform returns null (never throws) on every malformation', () => {
  const good = frameUniform(fill(0xab, 20), 'consent-delta');

  assert.equal(unframeUniform(good.subarray(0, FRAME_BYTES - 1)), null, 'wrong length → null');
  assert.equal(unframeUniform(new Uint8Array(FRAME_BYTES)), null, 'all-zero (version 0, type 0) → null');

  const badVersion = good.slice(); badVersion[0] = FRAME_VERSION + 1;
  assert.equal(unframeUniform(badVersion), null, 'unknown version → null');

  const badType = good.slice(); badType[1] = 0xfe;
  assert.equal(unframeUniform(badType), null, 'unknown type code → null');

  const overrun = good.slice();
  new DataView(overrun.buffer).setUint32(2, FRAME_MAX_PAYLOAD + 1, false); // claim more payload than a cell holds
  assert.equal(unframeUniform(overrun), null, 'internal length overrunning the cell → null');

  // A valid cell still unframes after all the hostile probes (no shared-state corruption).
  assert.deepEqual(unframeUniform(good)!.payload, fill(0xab, 20), 'a valid cell still unframes');
});

test('robustness: frameUniform throws on an over-one-cell payload (no silent truncation)', () => {
  assert.throws(() => frameUniform(fill(0x01, FRAME_MAX_PAYLOAD + 1), 'message'), /exceeds one cell/);
  assert.throws(() => frameUniform(fill(0x01, 10), 'nope' as unknown as FrameType), /unknown frame type/);
});
