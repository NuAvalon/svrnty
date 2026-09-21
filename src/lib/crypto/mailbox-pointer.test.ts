// src/lib/crypto/mailbox-pointer.test.ts
// KAT + behavioral pins for the mailbox lifecycle crypto (KB#90104 items 1-4, Flint grammar-pin).
// Fixed ramp inputs so Flint's independent encoder reproduces the vectors byte-for-byte.
//   node --import tsx --test src/lib/crypto/mailbox-pointer.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { lpBin, lpStr, u64be } from './lp-tlv.js';
import { deriveMailboxFp } from './mailbox-envelope.js';
import { mailboxRegPreimage } from '../identity/raw-sign.js';
import {
  MAILBOX_PTR_DOMAIN,
  encodeMailboxPointerPlaintext,
  buildSignedMailboxPointer,
  parseSignedMailboxPointer,
  verifyMailboxPointer,
  selectLatestValidPointer,
} from './mailbox-pointer.js';

// ── fixed KAT inputs (documented ramps — trivially reproducible) ──
const ramp = (n: number) => Uint8Array.from({ length: n }, (_, i) => i % 256);
const X25519_PUB = ramp(32); // 00 01 02 … 1f
const MLKEM_EK = ramp(1568); // 00 01 … ff 00 01 …
const EPOCH = 7;
const IDENTITY_SEED = new Uint8Array(32).fill(0x42);
const PUBLISHER_PUB = ed25519.getPublicKey(IDENTITY_SEED);
const OWNER_IDENTITY_FP = 'a'.repeat(64); // 64-lowercase-hex placeholder identity fp

test('lp-tlv byte vectors (Flint byte-pin #141596)', () => {
  assert.equal(bytesToHex(lpBin(new Uint8Array())), '00000000');
  assert.equal(bytesToHex(lpBin(Uint8Array.of(0xab))), '00000001ab');
  assert.equal(bytesToHex(lpBin(ramp(256))).slice(0, 8), '00000100');
  assert.equal(bytesToHex(u64be(7)), '0000000000000007');
  assert.equal(bytesToHex(u64be(0)), '0000000000000000');
  assert.equal(bytesToHex(lpStr('a')), '0000000161');
});

test('KAT (i) mailbox_fp of the fixed keypair', () => {
  const fp = deriveMailboxFp(X25519_PUB, MLKEM_EK);
  console.log('KAT_MAILBOX_FP=' + fp);
  assert.equal(fp.length, 64);
  assert.equal(fp, '7f798c11555d8eec04625ce513669d612c8cd0fba102dabb734d074a9d5e299b');
});

test('KAT (ii) ptr_plaintext hex for fixed {epoch, pubkeys}', () => {
  const pt = encodeMailboxPointerPlaintext(EPOCH, X25519_PUB, MLKEM_EK);
  const hex = bytesToHex(pt);
  console.log('KAT_PTR_PLAINTEXT_LEN=' + pt.length);
  console.log('KAT_PTR_PLAINTEXT_HEAD=' + hex.slice(0, 120));
  console.log('KAT_PTR_PLAINTEXT_SHA256=' + bytesToHex(sha256(pt)));
  // structural length: LP(domain 21) + LP(fp 32) + u64be(8) + LP(x 32) + LP(ek 1568)
  //                  = (4+21) + (4+32) + 8 + (4+32) + (4+1568) = 1677
  assert.equal(pt.length, 1677);
  assert.equal(bytesToHex(sha256(pt)), '789f284a4236cfe8b3de09db4030b51758331b04107b5fa4ce890aff02fbcd3b');
});

test('owner_sig preimage byte-grammar (== satellite.py:1092)', () => {
  const fp = deriveMailboxFp(X25519_PUB, MLKEM_EK);
  const pre = mailboxRegPreimage(OWNER_IDENTITY_FP, fp, EPOCH);
  const expected = `svrnty-mailbox-reg-v1:${OWNER_IDENTITY_FP}:${fp}:${EPOCH}`;
  assert.equal(new TextDecoder().decode(pre), expected);
});

test('signed pointer round-trips through verify', () => {
  const blob = buildSignedMailboxPointer(EPOCH, X25519_PUB, MLKEM_EK, IDENTITY_SEED);
  const p = verifyMailboxPointer(blob, PUBLISHER_PUB);
  assert.ok(p, 'valid pointer must verify');
  assert.equal(p!.epoch, EPOCH);
  assert.equal(p!.mailboxFp, deriveMailboxFp(X25519_PUB, MLKEM_EK));
  assert.equal(bytesToHex(p!.x25519Pub), bytesToHex(X25519_PUB));
  assert.equal(bytesToHex(p!.mlkem1024Ek), bytesToHex(MLKEM_EK));
});

test('anti-substitution: a flipped pubkey byte → reject (null)', () => {
  const blob = buildSignedMailboxPointer(EPOCH, X25519_PUB, MLKEM_EK, IDENTITY_SEED);
  const parsed = parseSignedMailboxPointer(blob);
  assert.ok(parsed);
  // flip the first byte of the inline x25519 pubkey (inside plaintext). This breaks BOTH the sig (bytes
  // changed) AND fp==SHA256(pubkeys); either alone must reject.
  const tampered = blob.slice();
  // locate x25519 pub: after LP(domain 25) + LP(fp 36) + u64be 8 → offset 69, +4 LP header → 73
  const xOff = 25 + 36 + 8 + 4;
  tampered[xOff] ^= 0xff;
  assert.equal(verifyMailboxPointer(tampered, PUBLISHER_PUB), null);
});

test('wrong publisher key → reject (null)', () => {
  const blob = buildSignedMailboxPointer(EPOCH, X25519_PUB, MLKEM_EK, IDENTITY_SEED);
  const otherPub = ed25519.getPublicKey(new Uint8Array(32).fill(0x43));
  assert.equal(verifyMailboxPointer(blob, otherPub), null);
});

test('malformed blobs never throw, always null', () => {
  assert.equal(verifyMailboxPointer(new Uint8Array(0), PUBLISHER_PUB), null);
  assert.equal(verifyMailboxPointer(ramp(10), PUBLISHER_PUB), null);
  const blob = buildSignedMailboxPointer(EPOCH, X25519_PUB, MLKEM_EK, IDENTITY_SEED);
  assert.equal(verifyMailboxPointer(blob.slice(0, blob.length - 1), PUBLISHER_PUB), null); // truncated sig
  const extended = new Uint8Array(blob.length + 1);
  extended.set(blob);
  assert.equal(verifyMailboxPointer(extended, PUBLISHER_PUB), null); // trailing byte
});

test('selectLatestValidPointer: highest-epoch valid wins; tampered dropped', () => {
  const e7 = buildSignedMailboxPointer(7, X25519_PUB, MLKEM_EK, IDENTITY_SEED);
  const e9 = buildSignedMailboxPointer(9, X25519_PUB, MLKEM_EK, IDENTITY_SEED);
  assert.equal(selectLatestValidPointer([e7, e9], PUBLISHER_PUB)!.epoch, 9);
  assert.equal(selectLatestValidPointer([e9, e7], PUBLISHER_PUB)!.epoch, 9);
  // a tampered high-epoch blob is dropped → the valid e7 is selected
  const forged = e9.slice();
  forged[25 + 36 + 8 + 4] ^= 0xff; // corrupt a pubkey byte
  assert.equal(selectLatestValidPointer([e7, forged], PUBLISHER_PUB)!.epoch, 7);
  assert.equal(selectLatestValidPointer([], PUBLISHER_PUB), null);
});
