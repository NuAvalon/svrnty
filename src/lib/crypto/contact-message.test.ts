// src/lib/crypto/contact-message.test.ts
// Run: npx tsx --test src/lib/crypto/contact-message.test.ts
//
// No-wire PQ-hybrid contact message: armor round-trip, encrypt→decrypt recovery, tamper/wrong-recipient
// rejection, length-as-suite fail-closed. Core is exercised with RAW recipient keys (the load-bearing
// crypto is the already-co-verified mailbox-envelope; this proves the adapter + armor around it).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import * as openpgp from 'openpgp';
import { generateKEMKeypair, generateSigningKeypair, uint8ToBase64 } from './pq.js';
import { extractRawEnc } from '../identity/raw-sign.js';
import {
  encryptToRecipientKeys,
  encryptToContact,
  decryptFromContact,
  type MyDecryptKeys,
} from './contact-message.js';

// ── a recipient's raw (x25519 enc, ML-KEM-1024) keypair — what an identity's enc keys reduce to ──
function makeRecipient(): MyDecryptKeys {
  const x25519Sec = x25519.utils.randomSecretKey();
  const x25519Pub = x25519.getPublicKey(x25519Sec);
  const { publicKey: mlkem1024Pub, secretKey: mlkem1024Sec } = generateKEMKeypair();
  return { x25519Sec, mlkem1024Sec, x25519Pub, mlkem1024Pub };
}

const MSG = 'the strong 64-hex: a1b2c3…  — meet me at the barzakh 🌀';

test('roundtrip: encrypt to recipient keys → decrypt recovers the exact plaintext', async () => {
  const bob = makeRecipient();
  const armored = await encryptToRecipientKeys(MSG, bob.x25519Pub, bob.mlkem1024Pub);
  assert.ok(armored.includes('BEGIN SVRNTY ENCRYPTED MESSAGE'));
  assert.ok(armored.includes('END SVRNTY ENCRYPTED MESSAGE'));
  const out = await decryptFromContact(armored, bob);
  assert.equal(out, MSG);
});

test('armor is copy-paste robust: extra whitespace/newlines around the block still decrypt', async () => {
  const bob = makeRecipient();
  const armored = await encryptToRecipientKeys('hi', bob.x25519Pub, bob.mlkem1024Pub);
  const mangled = `\n\n  chat noise before\n${armored}\n  chat noise after  \n`;
  assert.equal(await decryptFromContact(mangled, bob), 'hi');
});

test('wrong recipient: a different identity cannot decrypt (returns null, never throws)', async () => {
  const bob = makeRecipient();
  const carol = makeRecipient();
  const armored = await encryptToRecipientKeys(MSG, bob.x25519Pub, bob.mlkem1024Pub);
  assert.equal(await decryptFromContact(armored, carol), null);
});

test('tamper: flipping a ciphertext char makes the GCM tag fail → null', async () => {
  const bob = makeRecipient();
  const armored = await encryptToRecipientKeys(MSG, bob.x25519Pub, bob.mlkem1024Pub);
  // flip a char in the armor body (not the header) — pick a middle line char
  const lines = armored.split('\n');
  const mid = Math.floor(lines.length / 2);
  lines[mid] = (lines[mid][0] === 'A' ? 'B' : 'A') + lines[mid].slice(1);
  assert.equal(await decryptFromContact(lines.join('\n'), bob), null);
});

test('malformed input never throws: garbage / missing armor / empty → null', async () => {
  const bob = makeRecipient();
  assert.equal(await decryptFromContact('not an armored block', bob), null);
  assert.equal(await decryptFromContact('', bob), null);
  assert.equal(await decryptFromContact('-----BEGIN SVRNTY ENCRYPTED MESSAGE-----\n@@@notb64@@@\n-----END SVRNTY ENCRYPTED MESSAGE-----', bob), null);
});

test('length-as-suite: a non-1568B ML-KEM pub is rejected at encrypt (fail-closed, no hardcoded suite)', async () => {
  const bob = makeRecipient();
  const shortKem = new Uint8Array(1184); // ML-KEM-768 length — below svrnty's Cat-5 floor
  await assert.rejects(() => encryptToRecipientKeys('x', bob.x25519Pub, shortKem), /ML-KEM-1024|1568/);
});

test('PQ-hybrid by construction: the package advertises X25519+ML-KEM-1024 and needs the kem secret', async () => {
  const bob = makeRecipient();
  const armored = await encryptToRecipientKeys(MSG, bob.x25519Pub, bob.mlkem1024Pub);
  // reconstruct the recipient WITHOUT the ML-KEM secret (wrong pq secret) → decrypt must fail
  const noPq: MyDecryptKeys = { ...bob, mlkem1024Sec: generateKEMKeypair().secretKey };
  assert.equal(await decryptFromContact(armored, noPq), null);
  // and with only the classical half wrong (right pq, wrong x25519) → also fails (true hybrid)
  const noClassical: MyDecryptKeys = { ...bob, x25519Sec: x25519.utils.randomSecretKey() };
  assert.equal(await decryptFromContact(armored, { ...noClassical, x25519Pub: bob.x25519Pub }), null);
});

test('★ END-TO-END with a REAL svrnty identity: encryptToContact(card) → extractRawEnc → decrypt recovers', async () => {
  // A real recipient: OpenPGP ecc-ed25519 identity (carries the x25519 enc subkey) + ML-KEM + ML-DSA.
  const { privateKey, publicKey } = (await openpgp.generateKey({
    type: 'ecc', curve: 'ed25519', userIDs: [{ name: 'bob' }], format: 'object',
  } as any)) as any;
  const kem = generateKEMKeypair();
  const sig = generateSigningKeypair();

  // Their signed-card key material (what a contact record carries).
  const card = {
    public_key: publicKey.armor(),
    pq_kem_public_key: uint8ToBase64(kem.publicKey),
    pq_sig_public_key: uint8ToBase64(sig.publicKey),
  };

  const armored = await encryptToContact(MSG, card);

  // Recipient opens it: raw x25519 enc secret (reversed d, via extractRawEnc) + their ML-KEM secret.
  const { encSec, encPub } = await extractRawEnc(privateKey);
  const out = await decryptFromContact(armored, {
    x25519Sec: encSec,
    mlkem1024Sec: kem.secretKey,
    x25519Pub: encPub,
    mlkem1024Pub: kem.publicKey,
  });
  assert.equal(out, MSG);
});

test('anti-poison: encryptToContact refuses a card whose keys do not match its claimed fingerprint', async () => {
  const { publicKey } = (await openpgp.generateKey({ type: 'ecc', curve: 'ed25519', userIDs: [{ name: 'mallory' }], format: 'object' } as any)) as any;
  const kem = generateKEMKeypair();
  const sig = generateSigningKeypair();
  const card = {
    public_key: publicKey.armor(),
    pq_kem_public_key: uint8ToBase64(kem.publicKey),
    pq_sig_public_key: uint8ToBase64(sig.publicKey),
    fingerprint: 'f'.repeat(64), // deliberately wrong
  };
  await assert.rejects(() => encryptToContact(MSG, card), /anti-poison|does not match/);
});
