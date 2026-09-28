// src/lib/crypto/mailbox-owner-auth.test.ts
// Run: npx tsx --test src/lib/crypto/mailbox-owner-auth.test.ts
//
// S1 mailbox owner-auth: routine owner-op roundtrip, FLAG-1 fail-closed, ★ target-binding (Flint's catch),
// monotonic epoch, tamper, + the recovery pre-rotation commit/reveal + self-sign. The last test EMITS the
// co-verify vector for Athena's satellite verify_mailbox_owner (byte-exact before either side wires).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  OWNER_OP_TYPES,
  commitNextOwnerKey,
  ownerOpScope,
  signOwnerOp,
  verifyOwnerOp,
  verifyRecoveryReveal,
  type OwnerOpType,
} from './mailbox-owner-auth';

// ── deterministic fixtures ──
const ownerSk = new Uint8Array(32).fill(0x11);
const ownerPub = ed25519.getPublicKey(ownerSk);
const holderPub = ed25519.getPublicKey(new Uint8Array(32).fill(0x22)); // an op target (holder being allowed)
const holderHex = bytesToHex(holderPub);
const MAILBOX = 'a1b2c3d4e5f6';
const EPOCH = 5;

test('roundtrip: sign allow-add → verify OK', () => {
  const sig = signOwnerOp(ownerSk, MAILBOX, 'allow-add', EPOCH, holderHex);
  const r = verifyOwnerOp({ ownerPub, sig, mailboxFp: MAILBOX, op: 'allow-add', epoch: EPOCH, targetHex: holderHex });
  assert.equal(r.ok, true, r.reason);
});

test('FLAG-1 fail-closed: bad op, non-hex mailbox_fp, wrong-length target', () => {
  assert.throws(() => ownerOpScope(MAILBOX, 'delete-everything' as OwnerOpType, EPOCH, holderHex));
  assert.throws(() => ownerOpScope('NOT-HEX', 'allow-add', EPOCH, holderHex));
  assert.throws(() => ownerOpScope(MAILBOX, 'allow-add', EPOCH, 'abcd')); // too short
  assert.throws(() => ownerOpScope(MAILBOX, 'allow-add', -1, holderHex)); // negative epoch
});

test('★ TARGET-BINDING: a sig for target X does NOT verify for target Y (op-integrity)', () => {
  const otherHex = bytesToHex(ed25519.getPublicKey(new Uint8Array(32).fill(0x33)));
  const sig = signOwnerOp(ownerSk, MAILBOX, 'allow-add', EPOCH, holderHex); // owner authorizes allow-add holderPub
  // a hostile relay swaps the target to otherHex → must fail (the target is inside the signed bytes)
  const r = verifyOwnerOp({ ownerPub, sig, mailboxFp: MAILBOX, op: 'allow-add', epoch: EPOCH, targetHex: otherHex });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'owner-sig-invalid');
});

test('cross-op / cross-mailbox: sig does not transfer', () => {
  const sig = signOwnerOp(ownerSk, MAILBOX, 'allow-add', EPOCH, holderHex);
  assert.equal(verifyOwnerOp({ ownerPub, sig, mailboxFp: MAILBOX, op: 'revoke-holder', epoch: EPOCH, targetHex: holderHex }).ok, false);
  assert.equal(verifyOwnerOp({ ownerPub, sig, mailboxFp: 'ffffffffffff', op: 'allow-add', epoch: EPOCH, targetHex: holderHex }).ok, false);
});

test('monotonic epoch: epoch ≤ lastEpoch rejected', () => {
  const sig = signOwnerOp(ownerSk, MAILBOX, 'allow-add', EPOCH, holderHex);
  assert.equal(verifyOwnerOp({ ownerPub, sig, mailboxFp: MAILBOX, op: 'allow-add', epoch: EPOCH, targetHex: holderHex, lastEpoch: EPOCH - 1 }).ok, true);
  assert.equal(verifyOwnerOp({ ownerPub, sig, mailboxFp: MAILBOX, op: 'allow-add', epoch: EPOCH, targetHex: holderHex, lastEpoch: EPOCH }).ok, false); // replay
  assert.equal(verifyOwnerOp({ ownerPub, sig, mailboxFp: MAILBOX, op: 'allow-add', epoch: EPOCH, targetHex: holderHex, lastEpoch: EPOCH + 1 }).ok, false); // stale
});

test('tamper: flipped signature byte fails', () => {
  const sig = signOwnerOp(ownerSk, MAILBOX, 'allow-add', EPOCH, holderHex);
  const bad = sig.slice();
  bad[0] ^= 0xff;
  assert.equal(verifyOwnerOp({ ownerPub, sig: bad, mailboxFp: MAILBOX, op: 'allow-add', epoch: EPOCH, targetHex: holderHex }).ok, false);
});

test('recovery pre-rotation: reveal hashes to commitment + self-signs rotate-owner (lost device key NOT needed)', () => {
  // At reg, the owner pre-commits the NEXT (seed-derived) owner key by HASH only.
  const nextOwnerSk = new Uint8Array(32).fill(0x44);
  const nextOwnerPub = ed25519.getPublicKey(nextOwnerSk);
  const commitment = commitNextOwnerKey(nextOwnerPub);
  // Device lost. Recovery: reveal nextOwnerPub (must hash to commitment) + it SELF-SIGNS the rotate-owner op.
  assert.equal(verifyRecoveryReveal(nextOwnerPub, commitment), true);
  assert.equal(verifyRecoveryReveal(ed25519.getPublicKey(new Uint8Array(32).fill(0x55)), commitment), false); // wrong reveal
  const rotateSig = signOwnerOp(nextOwnerSk, MAILBOX, 'rotate-owner', EPOCH + 1, bytesToHex(nextOwnerPub));
  // satellite: reveal-hash OK → verify the rotate-owner op self-signed by the revealed key (ownerPub = revealed)
  const r = verifyOwnerOp({ ownerPub: nextOwnerPub, sig: rotateSig, mailboxFp: MAILBOX, op: 'rotate-owner', epoch: EPOCH + 1, targetHex: bytesToHex(nextOwnerPub), lastEpoch: EPOCH });
  assert.equal(r.ok, true, r.reason);
});

test('EMIT co-verify vector for Athena verify_mailbox_owner', () => {
  const op: OwnerOpType = 'allow-add';
  const sig = signOwnerOp(ownerSk, MAILBOX, op, EPOCH, holderHex);
  const vector = {
    _note: 'S1 owner-op co-verify vector (Apollo). Athena verify_mailbox_owner MUST accept this byte-for-byte.',
    preimage_utf8: ownerOpScope(MAILBOX, op, EPOCH, holderHex),
    mailbox_fp: MAILBOX,
    op,
    epoch: EPOCH,
    target_hex: holderHex,
    owner_pub_hex: bytesToHex(ownerPub),
    sig_hex: bytesToHex(sig),
    last_epoch: EPOCH - 1,
    expect: 'ok=true',
    note_signing: 'Ed25519 over utf8(preimage), flat delimited string, NO length-prefix/envelope',
  };
  console.log('\n===OWNEROP_VECTOR_BEGIN===');
  console.log(JSON.stringify(vector, null, 2));
  console.log('===OWNEROP_VECTOR_END===\n');
  assert.equal(verifyOwnerOp({ ownerPub, sig, mailboxFp: MAILBOX, op, epoch: EPOCH, targetHex: holderHex, lastEpoch: EPOCH - 1 }).ok, true);
});
