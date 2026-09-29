// src/lib/crypto/mailbox-owner-auth.test.ts
// Run: npx tsx --test src/lib/crypto/mailbox-owner-auth.test.ts
//
// S1 mailbox owner-auth. TWO surfaces:
//   (1) routine owner-op (byte-locked with Athena's owner_auth.py): sign/verify, FLAG-1 fail-closed,
//       ★ target-binding (Flint's catch), monotonic epoch, tamper.
//   (2) owner-KEY lifecycle (Flint #151507 / KB#91073+91096): distinct `svrnty-mailbox-ownerkey:` preimage,
//       genesis self-sign (TOFU), rotate/recovery pre-rotation reveal, per-mailbox DID-blind HKDF chain.
// The last tests EMIT the co-verify vectors (routine op + owner-key genesis + rotation) for Athena's satellite.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  OWNER_OP_TYPES,
  buildOwnerKeyGenesis,
  buildOwnerKeyRotation,
  commitNextOwnerKey,
  deriveOwnerKey,
  ownerKeyRegScope,
  ownerOpScope,
  signOwnerKeyReg,
  signOwnerOp,
  verifyOwnerKeyReg,
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
const coldSeed = new Uint8Array(32).fill(0xab); // the owner's cold seed (client-only; relay never sees it)

// ── (1) routine owner-op — byte-locked, unchanged ──
test('rotate-owner is NO LONGER a routine op (dropped from the enum — separation law)', () => {
  assert.deepEqual([...OWNER_OP_TYPES], ['allow-add', 'allow-remove', 'revoke-holder', 'register-admission']);
  assert.throws(() => ownerOpScope(MAILBOX, 'rotate-owner' as OwnerOpType, EPOCH, holderHex));
});

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
  const sig = signOwnerOp(ownerSk, MAILBOX, 'allow-add', EPOCH, holderHex);
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

// ── (2) owner-KEY lifecycle ──
test('owner-key chain: deterministic, per-mailbox DID-blind (different mailbox → different key)', () => {
  const a0 = deriveOwnerKey(coldSeed, MAILBOX, 0);
  assert.deepEqual(deriveOwnerKey(coldSeed, MAILBOX, 0).pub, a0.pub); // deterministic
  assert.notDeepEqual(deriveOwnerKey(coldSeed, MAILBOX, 1).pub, a0.pub); // index-distinct
  assert.notDeepEqual(deriveOwnerKey(coldSeed, 'ffffffffffff', 0).pub, a0.pub); // mailbox-distinct (unlinkable)
  assert.equal(a0.pub.length, 32);
});

test('GENESIS owner-key: self-sign verifies (TOFU), durable_id-blind, epoch 0', () => {
  const reg = buildOwnerKeyGenesis(coldSeed, MAILBOX);
  assert.equal(reg.epoch, 0);
  const k1 = deriveOwnerKey(coldSeed, MAILBOX, 1);
  assert.equal(reg.nextCommitmentHex, commitNextOwnerKey(k1.pub)); // commits H(owner_key_1)
  // genesis verify: no prior commitment (TOFU) → accept on self-sign
  const r = verifyOwnerKeyReg({
    ownerPub: ed25519.getPublicKey(deriveOwnerKey(coldSeed, MAILBOX, 0).seed),
    sig: reg.sig,
    mailboxFp: MAILBOX,
    epoch: 0,
    nextCommitmentHex: reg.nextCommitmentHex,
  });
  assert.equal(r.ok, true, r.reason);
  // genesis at epoch != 0 is rejected
  const k0 = deriveOwnerKey(coldSeed, MAILBOX, 0);
  const badEpoch = signOwnerKeyReg(k0.seed, MAILBOX, 1);
  assert.equal(verifyOwnerKeyReg({ ownerPub: k0.pub, sig: badEpoch.sig, mailboxFp: MAILBOX, epoch: 1, nextCommitmentHex: reg.nextCommitmentHex }).ok, false);
});

test('ROTATE/RECOVERY owner-key: reveal must hash to stored commitment + self-sign + monotonic', () => {
  const genesis = buildOwnerKeyGenesis(coldSeed, MAILBOX); // sets commitment_0 = H(owner_key_1)
  const rot1 = buildOwnerKeyRotation(coldSeed, MAILBOX, 1); // reveals owner_key_1 at epoch 1
  const k1 = deriveOwnerKey(coldSeed, MAILBOX, 1);
  // the revealed key hashes to the genesis commitment (pre-rotation)…
  assert.equal(verifyRecoveryReveal(k1.pub, genesis.nextCommitmentHex), true);
  // …and the full reg verifies against the stored prior commitment
  const r = verifyOwnerKeyReg({
    ownerPub: k1.pub,
    sig: rot1.sig,
    mailboxFp: MAILBOX,
    epoch: 1,
    nextCommitmentHex: rot1.nextCommitmentHex,
    priorCommitmentHex: genesis.nextCommitmentHex,
    lastEpoch: 0,
  });
  assert.equal(r.ok, true, r.reason);
  // WRONG prior commitment → reveal mismatch (a key not pre-committed cannot rotate in)
  assert.equal(verifyOwnerKeyReg({ ownerPub: k1.pub, sig: rot1.sig, mailboxFp: MAILBOX, epoch: 1, nextCommitmentHex: rot1.nextCommitmentHex, priorCommitmentHex: commitNextOwnerKey(ownerPub), lastEpoch: 0 }).ok, false);
  // NON-monotonic epoch rejected
  assert.equal(verifyOwnerKeyReg({ ownerPub: k1.pub, sig: rot1.sig, mailboxFp: MAILBOX, epoch: 1, nextCommitmentHex: rot1.nextCommitmentHex, priorCommitmentHex: genesis.nextCommitmentHex, lastEpoch: 1 }).ok, false);
});

test('owner-key reg fail-closed: bad next-commitment, tampered self-sign', () => {
  const genesis = buildOwnerKeyGenesis(coldSeed, MAILBOX);
  const k0 = deriveOwnerKey(coldSeed, MAILBOX, 0);
  assert.equal(verifyOwnerKeyReg({ ownerPub: k0.pub, sig: genesis.sig, mailboxFp: MAILBOX, epoch: 0, nextCommitmentHex: 'nothex' }).ok, false);
  const bad = genesis.sig.slice();
  bad[0] ^= 0xff;
  assert.equal(verifyOwnerKeyReg({ ownerPub: k0.pub, sig: bad, mailboxFp: MAILBOX, epoch: 0, nextCommitmentHex: genesis.nextCommitmentHex }).ok, false);
});

test('ownerKeyRegScope: domain-separated from ownerOpScope (a routine-op sig can never replay as a key install)', () => {
  const k0 = deriveOwnerKey(coldSeed, MAILBOX, 0);
  const keyScope = ownerKeyRegScope(MAILBOX, bytesToHex(k0.pub), 0);
  assert.ok(keyScope.startsWith('svrnty-mailbox-ownerkey:'));
  assert.ok(ownerOpScope(MAILBOX, 'allow-add', 0, bytesToHex(k0.pub)).startsWith('svrnty-mailbox-op:'));
  assert.notEqual(keyScope, ownerOpScope(MAILBOX, 'allow-add', 0, bytesToHex(k0.pub)));
});

test('EMIT co-verify vectors: routine owner-op + owner-key genesis + rotation', () => {
  const op: OwnerOpType = 'allow-add';
  const sig = signOwnerOp(ownerSk, MAILBOX, op, EPOCH, holderHex);
  const genesis = buildOwnerKeyGenesis(coldSeed, MAILBOX);
  const rot1 = buildOwnerKeyRotation(coldSeed, MAILBOX, 1);
  const k0 = deriveOwnerKey(coldSeed, MAILBOX, 0);
  const k1 = deriveOwnerKey(coldSeed, MAILBOX, 1);
  const vector = {
    _note: 'S1 co-verify vector (Apollo). Athena verify_mailbox_owner + owner-key store MUST accept byte-for-byte. Ed25519 over utf8(preimage), flat delimited, NO envelope.',
    routine_owner_op: {
      preimage_utf8: ownerOpScope(MAILBOX, op, EPOCH, holderHex),
      owner_pub_hex: bytesToHex(ownerPub),
      sig_hex: bytesToHex(sig),
      last_epoch: EPOCH - 1,
      expect: 'ok=true',
    },
    ownerkey_genesis: {
      preimage_utf8: ownerKeyRegScope(MAILBOX, genesis.ownerPubHex, 0),
      owner_pub_hex: genesis.ownerPubHex, // == owner_key_0
      sig_hex: bytesToHex(genesis.sig),
      next_commitment_hex: genesis.nextCommitmentHex, // == H(owner_key_1)
      prior_commitment: null, // TOFU
      expect: 'ok=true; relay stores durable_id-BLIND',
    },
    ownerkey_rotation_epoch1: {
      preimage_utf8: ownerKeyRegScope(MAILBOX, rot1.ownerPubHex, 1),
      owner_pub_hex: rot1.ownerPubHex, // == owner_key_1 (the REVEAL)
      sig_hex: bytesToHex(rot1.sig),
      next_commitment_hex: rot1.nextCommitmentHex, // == H(owner_key_2)
      prior_commitment_hex: genesis.nextCommitmentHex, // == H(owner_key_1); H(reveal) must equal this
      last_epoch: 0,
      expect: 'ok=true; H(owner_key_1)===prior_commitment',
    },
    chain_check: {
      hkdf_info_genesis: `svrnty-mailbox-ownerkey-chain:v1:${MAILBOX}:0`,
      owner_key_0_pub_hex: bytesToHex(k0.pub),
      owner_key_1_pub_hex: bytesToHex(k1.pub),
    },
  };
  console.log('\n===OWNERKEY_VECTOR_BEGIN===');
  console.log(JSON.stringify(vector, null, 2));
  console.log('===OWNERKEY_VECTOR_END===\n');

  assert.equal(verifyOwnerOp({ ownerPub, sig, mailboxFp: MAILBOX, op, epoch: EPOCH, targetHex: holderHex, lastEpoch: EPOCH - 1 }).ok, true);
  assert.equal(verifyOwnerKeyReg({ ownerPub: k0.pub, sig: genesis.sig, mailboxFp: MAILBOX, epoch: 0, nextCommitmentHex: genesis.nextCommitmentHex }).ok, true);
  assert.equal(verifyOwnerKeyReg({ ownerPub: k1.pub, sig: rot1.sig, mailboxFp: MAILBOX, epoch: 1, nextCommitmentHex: rot1.nextCommitmentHex, priorCommitmentHex: genesis.nextCommitmentHex, lastEpoch: 0 }).ok, true);
});
