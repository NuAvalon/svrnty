// src/lib/crypto/distress-mark.test.ts
// ADVERSARIAL refutation gate for the #558 keystone K3 distress cry (Flint §8 silence invariant, KB#91383).
// Each test refutes a PROTECT-THE-PERSON property — "an adversary who PEELS the outer shell / holds the wire
// CANNOT [X]" — NEVER the mechanic "the cry is signed". The cry is sealed through the REAL K0 sealOnion
// (onion-envelope.ts) + K1 route_id (route-ratchet.ts) + K2 uniform-frame (uniform-frame.ts) — the wire a
// hosted guardian-satellite actually sees — never a stand-in.
// Timing-channel §8(b)/(c) properties are in distress-cadence.test.ts.
// Run: npx tsx --test src/lib/crypto/distress-mark.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from './mailbox-keys.js';
import { sealToMailbox, openMailboxEnvelope } from './mailbox-envelope.js';
import { sealOnion, peelOnion, openOnionInner } from './onion-envelope.js';
import { deriveSharedSecret } from './mutual-trust.js';
import { RouteRatchet, directionTag } from './route-ratchet.js';
import { frameUniform, unframeUniform, FRAME_BYTES, FRAME_MAX_PAYLOAD, type FrameType } from './uniform-frame.js';
import { buildConsentDelta } from './consent-delta.js';
import {
  buildDistressMark,
  buildDistressCell,
  verifyDistressMark,
  buildCoverPayload,
  buildCoverCell,
  DISTRESS_MARK_BYTES,
  DISTRESS_WIRE_VERSION,
} from './distress-mark.js';

// ── fixtures ─────────────────────────────────────────────────────────────
const fill = (byte: number, n: number) => new Uint8Array(n).fill(byte);
const ANCHOR = 480_000;
const W = ANCHOR + 7;

/** A distress channel C→guardian: C's signing seed, the guardian's stable identity binding, the guardian's
 *  DEVICE + SATELLITE mailbox keypairs, and the K1 route_id(C→guardian) for this window — everything needed
 *  to put a framed cry on the real wire exactly as the emit-path will. */
function makeChannel(senderSeedByte: number, guardianSeedByte: number) {
  const senderSeed = fill(senderSeedByte, 32);
  const guardianSeed = fill(guardianSeedByte, 32);
  const senderSignPub = ed25519.getPublicKey(senderSeed);
  const guardianSignPub = ed25519.getPublicKey(guardianSeed);
  const senderFp = bytesToHex(senderSignPub);
  const guardianFp = bytesToHex(guardianSignPub);
  const s_AB = deriveSharedSecret(senderSeed, guardianSignPub);
  const routeId = RouteRatchet.init(s_AB, directionTag(senderFp, guardianFp), ANCHOR, W).currentRouteId();
  return {
    senderSeed,
    senderSignPub,
    guardianBinding: guardianSignPub, // the guardian's stable identity fp bytes (signed, never on the wire)
    device: generateMailboxKeypair(),
    satellite: generateMailboxKeypair(),
    routeId,
  };
}

/** Put a framed cell on the real wire: frame → inner-seal to guardian DEVICE → onion-seal to guardian
 *  SATELLITE by the K1 route_id. (frameUniform is called by build*Cell; a raw cell can also be passed.) */
async function toWire(cell: Uint8Array, ch: ReturnType<typeof makeChannel>) {
  const inner = await sealToMailbox(cell, toPublicKeys(ch.device));
  return sealOnion(inner, toPublicKeys(ch.satellite), ch.routeId);
}

// ════════════════════════════════════════════════════════════════════════
// sanity — the cry rides the whole K0/K1/K2 stack and verifies at the guardian device.
// ════════════════════════════════════════════════════════════════════════
test('sanity: distress cry round-trips frame→seal→onion→peel→open→unframe→verify at the guardian device', async () => {
  const ch = makeChannel(0x11, 0x22);
  const cell = buildDistressCell({ epoch: 100 }, ch.senderSeed, ch.guardianBinding);
  assert.equal(cell.length, FRAME_BYTES, 'a distress cry is exactly one FRAME_BYTES cell');

  const outer = await toWire(cell, ch);
  const peeled = await peelOnion(outer, toSecretKeys(ch.satellite), mailboxFpOf(ch.satellite));
  assert.ok(peeled, 'guardian satellite peels the outer');
  assert.equal(peeled.route, ch.routeId, 'satellite routes by the blinded K1 route_id');

  const openedCell = await openOnionInner(peeled.inner, toSecretKeys(ch.device), mailboxFpOf(ch.device));
  assert.ok(openedCell, 'guardian DEVICE opens the inner cell');
  const un = unframeUniform(openedCell);
  assert.ok(un && un.type === 'distress', 'device unframes a distress cell');

  const mark = verifyDistressMark(un.payload, ch.senderSignPub, { guardianBinding: ch.guardianBinding, lastSeenEpoch: -1 });
  assert.ok(mark, 'device verifies the cry');
  assert.equal(mark.epoch, 100, 'epoch recovered');
});

// ════════════════════════════════════════════════════════════════════════
// (TYPE + SIZE, Finding-#1) — a peeling guardian-satellite CANNOT tell a distress cry from a consent-delta,
// a message, or a cover cell, by type OR by length. SIZE is the green-flatter, so it is proven with maximally
// size-divergent raw inputs + a POSITIVE CONTROL that the UNFRAMED path DOES leak the kind by length.
// ════════════════════════════════════════════════════════════════════════
test('(TYPE+SIZE) distress is byte-indistinguishable from consent-delta / message / cover to a peeling satellite', async () => {
  const ch = makeChannel(0x11, 0x22);

  const distress = buildDistressMark({ epoch: 7 }, ch.senderSeed, ch.guardianBinding);          // 73 B
  const consent = buildConsentDelta({ typ: 'consent/go-private', epoch: 1, scope: fill(0xc1, 4) }, ch.senderSeed, ch.guardianBinding);
  const message = fill(0x11, FRAME_MAX_PAYLOAD);                                                  // a full single cell
  const cover = buildCoverPayload(1);                                                             // a 1-byte cover

  const kinds: Array<{ payload: Uint8Array; type: FrameType }> = [
    { payload: distress, type: 'distress' },
    { payload: consent, type: 'consent-delta' },
    { payload: message, type: 'message' },
    { payload: cover, type: 'cover' },
  ];

  // Every kind frames to a constant-size cell.
  for (const k of kinds) assert.equal(frameUniform(k.payload, k.type).length, FRAME_BYTES, `${k.type} → one cell`);

  // On the real wire + after a satellite peel, every field length is IDENTICAL across all four kinds.
  const outers = await Promise.all(kinds.map((k) => toWire(frameUniform(k.payload, k.type), ch)));
  const [od] = outers;
  for (const o of outers) {
    for (const f of ['ct', 'epk', 'kem_ct', 'nonce'] as const) {
      assert.equal(o[f].length, od[f].length, `outer.${f} length identical across kinds`);
    }
  }
  const peels = await Promise.all(outers.map((o) => peelOnion(o, toSecretKeys(ch.satellite), mailboxFpOf(ch.satellite))));
  assert.ok(peels.every(Boolean), 'satellite peels all kinds');
  const innerCtLen = peels[0]!.inner.ct.length;
  for (const p of peels) assert.equal(p!.inner.ct.length, innerCtLen, 'peeled inner.ct length identical across kinds');

  // POSITIVE CONTROL (non-vacuous): WITHOUT the frame, distress(73B) / consent / cover(1B) / message seal to
  // DIFFERENT inner.ct lengths — raw size leaks the kind. The uniform frame is what removes the signal.
  const rawLens = await Promise.all(
    kinds.map(async (k) => (await sealToMailbox(k.payload, toPublicKeys(ch.device))).ct.length),
  );
  assert.notEqual(rawLens[0], rawLens[2], 'unframed distress and message DO leak different sizes (control)');
  assert.notEqual(rawLens[0], rawLens[3], 'unframed distress and cover DO leak different sizes (control)');
});

// ════════════════════════════════════════════════════════════════════════
// (a) DEVICE-SEALED AUTH — a guardian's SATELLITE, which peels the OUTER, CANNOT read or verify the sender
// proof: the cry's authentication is sealed to the guardian DEVICE, and the satellite holds no device key.
// ════════════════════════════════════════════════════════════════════════
test('(a) a peeling satellite cannot read or verify the sender proof — auth is inner-sealed to the device', async () => {
  const ch = makeChannel(0x11, 0x22);
  const cell = buildDistressCell({ epoch: 5 }, ch.senderSeed, ch.guardianBinding);
  const outer = await toWire(cell, ch);

  const peeled = await peelOnion(outer, toSecretKeys(ch.satellite), mailboxFpOf(ch.satellite));
  assert.ok(peeled, 'satellite peels the outer (it routes, that is its job)');

  // The satellite tries to open the peeled inner with its OWN secrets (the only keys it has) → it CANNOT:
  // the inner was sealed to the DEVICE, so re-inserting the satellite fp and opening with satellite secrets
  // fails the recipient check / AEAD tag. No plaintext, no signature, no epoch — the proof is unreadable.
  const asSatellite = await openMailboxEnvelope(
    { ...peeled.inner, mailbox_fp: mailboxFpOf(ch.satellite) } as any,
    toSecretKeys(ch.satellite),
    mailboxFpOf(ch.satellite),
  );
  assert.equal(asSatellite, null, 'satellite cannot open the device-sealed inner → cannot read/verify the cry');

  // POSITIVE CONTROL: the guardian DEVICE (the intended holder of the auth) opens and verifies.
  const openedCell = await openOnionInner(peeled.inner, toSecretKeys(ch.device), mailboxFpOf(ch.device));
  assert.ok(openedCell, 'device opens the inner');
  const un = unframeUniform(openedCell)!;
  assert.ok(verifyDistressMark(un.payload, ch.senderSignPub, { guardianBinding: ch.guardianBinding, lastSeenEpoch: -1 }), 'device verifies');
});

// ════════════════════════════════════════════════════════════════════════
// SINGLE-CELL CAP (life-safety gate-1, Archie #154636) — a cry is ALWAYS exactly one cell, enforced in code.
// ════════════════════════════════════════════════════════════════════════
test('single-cell cap: a cry is fixed-size and one cell by construction; the frame throws above one cell', () => {
  const ch = makeChannel(0x11, 0x22);
  const cry = buildDistressMark({ epoch: 42 }, ch.senderSeed, ch.guardianBinding);
  assert.equal(cry.length, DISTRESS_MARK_BYTES, 'a cry is exactly DISTRESS_MARK_BYTES (fixed shape, no variable field)');
  assert.ok(DISTRESS_MARK_BYTES <= FRAME_MAX_PAYLOAD, 'a cry fits one cell by construction');
  assert.equal(buildDistressCell({ epoch: 42 }, ch.senderSeed, ch.guardianBinding).length, FRAME_BYTES, 'framed cry is one cell');

  // POSITIVE CONTROL (the cap is real + non-vacuous): a payload above one cell THROWS at frame time — a cry
  // is never silently split (a split cry would leak a multi-cell VOLUME signal, the exact §8 harm).
  assert.throws(() => frameUniform(fill(0xd1, FRAME_MAX_PAYLOAD + 1), 'distress'), /exceeds one cell/);
});

// ════════════════════════════════════════════════════════════════════════
// UNFORGEABILITY + CROSS-GUARDIAN REPLAY — an adversary cannot forge a cry, nor re-point C's cry for one
// guardian at another guardian.
// ════════════════════════════════════════════════════════════════════════
test('unforgeability: a cry signed by the wrong key, or tampered, does not verify', () => {
  const ch = makeChannel(0x11, 0x22);
  const wrongSignerSeed = fill(0x99, 32);
  const forged = buildDistressMark({ epoch: 3 }, wrongSignerSeed, ch.guardianBinding);
  assert.equal(
    verifyDistressMark(forged, ch.senderSignPub, { guardianBinding: ch.guardianBinding, lastSeenEpoch: -1 }),
    null,
    'a cry signed by someone other than C fails under C\'s pubkey',
  );

  const genuine = buildDistressMark({ epoch: 3 }, ch.senderSeed, ch.guardianBinding);
  const tampered = genuine.slice();
  tampered[tampered.length - 1] ^= 0x01; // flip a signature bit
  assert.equal(
    verifyDistressMark(tampered, ch.senderSignPub, { guardianBinding: ch.guardianBinding, lastSeenEpoch: -1 }),
    null,
    'a tampered signature fails',
  );
});

test('cross-guardian replay: a cry built for guardian G1 does not verify at guardian G2', () => {
  const g1 = makeChannel(0x11, 0x22);
  const g2 = makeChannel(0x11, 0x33); // same sender C, a DIFFERENT guardian binding
  const cryForG1 = buildDistressMark({ epoch: 9 }, g1.senderSeed, g1.guardianBinding);
  assert.ok(verifyDistressMark(cryForG1, g1.senderSignPub, { guardianBinding: g1.guardianBinding, lastSeenEpoch: -1 }), 'verifies at G1');
  assert.equal(
    verifyDistressMark(cryForG1, g1.senderSignPub, { guardianBinding: g2.guardianBinding, lastSeenEpoch: -1 }),
    null,
    'the SAME bytes fail at G2 (the guardian binding is signed, so a mis-delivered cry is rejected)',
  );
});

// ════════════════════════════════════════════════════════════════════════
// MONOTONIC ANTI-REPLAY — a relay cannot replay an old sealed cry; a legitimate repeat cry uses a higher epoch.
// ════════════════════════════════════════════════════════════════════════
test('monotonic anti-replay: epoch <= lastSeen is rejected; a higher epoch is accepted', () => {
  const ch = makeChannel(0x11, 0x22);
  const cry = buildDistressMark({ epoch: 10 }, ch.senderSeed, ch.guardianBinding);
  assert.equal(verifyDistressMark(cry, ch.senderSignPub, { guardianBinding: ch.guardianBinding, lastSeenEpoch: 10 }), null, 'replay of epoch 10 when 10 seen → rejected');
  assert.equal(verifyDistressMark(cry, ch.senderSignPub, { guardianBinding: ch.guardianBinding, lastSeenEpoch: 11 }), null, 'an older epoch than seen → rejected');
  assert.ok(verifyDistressMark(cry, ch.senderSignPub, { guardianBinding: ch.guardianBinding, lastSeenEpoch: 9 }), 'a fresh higher epoch → accepted');
});

// ════════════════════════════════════════════════════════════════════════
// NULL-NOT-THROW — the relay controls these bytes; verify must never throw on hostile input.
// ════════════════════════════════════════════════════════════════════════
test('null-not-throw: verify returns null (never throws) on malformed / hostile input', () => {
  const ch = makeChannel(0x11, 0x22);
  const good = buildDistressMark({ epoch: 1 }, ch.senderSeed, ch.guardianBinding);
  const opts = { guardianBinding: ch.guardianBinding, lastSeenEpoch: -1 };
  assert.equal(verifyDistressMark(new Uint8Array(0), ch.senderSignPub, opts), null, 'empty');
  assert.equal(verifyDistressMark(good.slice(0, DISTRESS_MARK_BYTES - 1), ch.senderSignPub, opts), null, 'short by one');
  const badVer = good.slice(); badVer[0] = DISTRESS_WIRE_VERSION + 1;
  assert.equal(verifyDistressMark(badVer, ch.senderSignPub, opts), null, 'wrong version');
  assert.equal(verifyDistressMark(good, new Uint8Array(31), opts), null, 'bad pubkey length');
  assert.equal(verifyDistressMark(good, ch.senderSignPub, { guardianBinding: new Uint8Array(0), lastSeenEpoch: -1 }), null, 'empty binding');
});

// ════════════════════════════════════════════════════════════════════════
// COVER CELLS — a cover cell is byte-indistinguishable from a cry after framing, and the device discards it.
// ════════════════════════════════════════════════════════════════════════
test('cover: a cover cell frames to the same constant cell and unframes to type cover (device discards it)', () => {
  const cell = buildCoverCell(16);
  assert.equal(cell.length, FRAME_BYTES, 'a cover cell is one FRAME_BYTES cell, identical in size to a cry');
  const un = unframeUniform(cell);
  assert.ok(un && un.type === 'cover', 'the device reads type cover (inside the device seal) and discards');
});
