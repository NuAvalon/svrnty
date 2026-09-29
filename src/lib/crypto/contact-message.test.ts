// src/lib/crypto/contact-message.test.ts
// Run: npx tsx --test src/lib/crypto/contact-message.test.ts
//
// AUTHENTICATED no-wire PQ-hybrid contact message (sign-then-seal). Confidentiality (seal) + authenticity
// (recipient-bound hybrid signature). Core is exercised with raw recipient keys; the authenticity path is
// proven END-TO-END with two real OpenPGP identities (Alice signs → Bob opens + verifies).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as openpgp from 'openpgp';
import { x25519, ed25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair, generateSigningKeypair, uint8ToBase64 } from './pq.js';
import { extractRawSign, extractRawEnc } from '../identity/raw-sign.js';
import { deriveCanonicalFingerprintHex } from '../identity/fingerprint.js';
import {
  sealSignedToRecipient,
  encryptToContact,
  decryptFromContact,
  signContactMessage,
  verifyContactMessage,
  type SenderKeys,
  type MyKeys,
  type ContactKeys,
} from './contact-message.js';

const MSG = 'the strong 64-hex — meet me at the barzakh 🌀';
const FP_A = 'a'.repeat(64);
const FP_B = 'b'.repeat(64);

// A minimal sender (raw signing keys) for the core tests.
function makeSender(fp = FP_A): SenderKeys & { signPub: Uint8Array; sigPub: Uint8Array } {
  const signSeed = new Uint8Array(32).fill(0x11);
  const signPub = ed25519.getPublicKey(signSeed);
  const sig = generateSigningKeypair();
  return { signSeed, sigSecret: sig.secretKey, senderFingerprint: fp, signPub, sigPub: sig.publicKey };
}
function makeRecipient(fp = FP_B): MyKeys {
  const x25519Sec = x25519.utils.randomSecretKey();
  const x25519Pub = x25519.getPublicKey(x25519Sec);
  const { publicKey: mlkem1024Pub, secretKey: mlkem1024Sec } = generateKEMKeypair();
  return { x25519Sec, mlkem1024Sec, x25519Pub, mlkem1024Pub, myFingerprint: fp };
}

test('core roundtrip: sign-then-seal → decrypt recovers message (senderVerified=false without a card)', async () => {
  const alice = makeSender();
  const bob = makeRecipient();
  const armored = await sealSignedToRecipient(MSG, { x25519Pub: bob.x25519Pub, mlkem1024Pub: bob.mlkem1024Pub, fingerprint: bob.myFingerprint }, alice);
  assert.ok(armored.includes('BEGIN SVRNTY ENCRYPTED MESSAGE'));
  const out = await decryptFromContact(armored, bob);
  assert.ok(out);
  assert.equal(out.message, MSG);
  assert.equal(out.senderVerified, false); // no senderCard supplied → unverified (UI must label it)
  assert.equal(out.senderFingerprint, FP_A);
});

test('signature is recipient-bound: verifies for the intended recipient, fails for another', () => {
  const alice = makeSender();
  const sig = signContactMessage(MSG, FP_B, alice.signSeed, alice.sigSecret);
  assert.equal(verifyContactMessage(MSG, FP_B, sig, alice.signPub, alice.sigPub), true);
  assert.equal(verifyContactMessage(MSG, FP_A, sig, alice.signPub, alice.sigPub), false); // different recipient
  assert.equal(verifyContactMessage(MSG + '.', FP_B, sig, alice.signPub, alice.sigPub), false); // tampered message
});

test('wrong recipient cannot decrypt (null); malformed input never throws (null)', async () => {
  const alice = makeSender();
  const bob = makeRecipient();
  const carol = makeRecipient(FP_A);
  const armored = await sealSignedToRecipient(MSG, { x25519Pub: bob.x25519Pub, mlkem1024Pub: bob.mlkem1024Pub, fingerprint: bob.myFingerprint }, alice);
  assert.equal(await decryptFromContact(armored, carol), null);
  assert.equal(await decryptFromContact('not a block', bob), null);
  assert.equal(await decryptFromContact('', bob), null);
});

test('tamper: flipping a ciphertext char → GCM tag fails → null', async () => {
  const alice = makeSender();
  const bob = makeRecipient();
  const armored = await sealSignedToRecipient(MSG, { x25519Pub: bob.x25519Pub, mlkem1024Pub: bob.mlkem1024Pub, fingerprint: bob.myFingerprint }, alice);
  const lines = armored.split('\n');
  const mid = Math.floor(lines.length / 2);
  lines[mid] = (lines[mid][0] === 'A' ? 'B' : 'A') + lines[mid].slice(1);
  assert.equal(await decryptFromContact(lines.join('\n'), bob), null);
});

test('length-as-suite: a non-1568B ML-KEM pub is rejected at seal (fail-closed)', async () => {
  const alice = makeSender();
  const bob = makeRecipient();
  await assert.rejects(
    () => sealSignedToRecipient('x', { x25519Pub: bob.x25519Pub, mlkem1024Pub: new Uint8Array(1184), fingerprint: bob.myFingerprint }, alice),
    /ML-KEM-1024|1568/,
  );
});

// ── END-TO-END with two REAL svrnty identities (Alice → Bob) ──
async function makeIdentity() {
  const { privateKey, publicKey } = (await openpgp.generateKey({ type: 'ecc', curve: 'ed25519', userIDs: [{ name: 'id' }], format: 'object' } as any)) as any;
  const kem = generateKEMKeypair();
  const sig = generateSigningKeypair();
  const { seed: signSeed, signPub } = extractRawSign(privateKey);
  const { encSec, encPub } = await extractRawEnc(privateKey);
  const fingerprint = deriveCanonicalFingerprintHex(signPub, encPub, kem.publicKey, sig.publicKey);
  const card: ContactKeys = {
    public_key: publicKey.armor(),
    pq_kem_public_key: uint8ToBase64(kem.publicKey),
    pq_sig_public_key: uint8ToBase64(sig.publicKey),
    fingerprint,
  };
  const asSender: SenderKeys = { signSeed, sigSecret: sig.secretKey, senderFingerprint: fingerprint };
  const asRecipient: MyKeys = { x25519Sec: encSec, mlkem1024Sec: kem.secretKey, x25519Pub: encPub, mlkem1024Pub: kem.publicKey, myFingerprint: fingerprint };
  return { card, asSender, asRecipient, fingerprint };
}

test('★ END-TO-END authenticated: Alice→Bob encrypt → Bob opens + VERIFIES Alice (senderVerified=true)', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const armored = await encryptToContact(MSG, bob.card, alice.asSender);

  const verified = await decryptFromContact(armored, bob.asRecipient, alice.card);
  assert.ok(verified);
  assert.equal(verified.message, MSG);
  assert.equal(verified.senderVerified, true);
  assert.equal(verified.senderFingerprint, alice.fingerprint);

  // no card → message opens but sender unverified
  const noCard = await decryptFromContact(armored, bob.asRecipient);
  assert.equal(noCard!.senderVerified, false);

  // WRONG sender card (Bob's own card, but payload claims Alice) → not verified
  const wrongCard = await decryptFromContact(armored, bob.asRecipient, bob.card);
  assert.equal(wrongCard!.senderVerified, false);
});

test('★ anti-forwarding: a message Alice sealed to Bob cannot be re-verified as sent to Carol', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const armored = await encryptToContact(MSG, bob.card, alice.asSender);
  // Bob opens legitimately (bound to Bob) → verified
  assert.equal((await decryptFromContact(armored, bob.asRecipient, alice.card))!.senderVerified, true);
  // If Bob's decrypt claimed a different recipient fp, the sig (bound to Bob) would not verify:
  const bobPretendingCarol: MyKeys = { ...bob.asRecipient, myFingerprint: 'c'.repeat(64) };
  const spoofed = await decryptFromContact(armored, bobPretendingCarol, alice.card);
  assert.equal(spoofed!.senderVerified, false); // recipient-binding holds
});

test('anti-poison: encryptToContact refuses a card whose keys do not match its claimed fingerprint', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const poisoned: ContactKeys = { ...bob.card, fingerprint: 'f'.repeat(64) };
  await assert.rejects(() => encryptToContact(MSG, poisoned, alice.asSender), /anti-poison|does not match/);
});
