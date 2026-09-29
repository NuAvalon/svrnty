// src/lib/crypto/contact-message-group.test.ts
// Run: npx tsx --test src/lib/crypto/contact-message-group.test.ts
//
// GROUP fan-out over the co-verified single-recipient contact message (PR#155). Proves: N-recipient
// round-trip, each member opens ONLY their own block, non-members get null, senderVerified inherits,
// anti-forwarding preserved per block, de-dup by fingerprint, empty-group throws, missing-fingerprint
// throws, malformed/tampered container → null (never throws), and single-member group works.
// NO new crypto — the per-block soundness is inherited from the co-verified contact-message primitive.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as openpgp from 'openpgp';
import { generateKEMKeypair, generateSigningKeypair, uint8ToBase64, base64ToUint8 } from './pq.js';
import { extractRawSign, extractRawEnc } from '../identity/raw-sign.js';
import { deriveCanonicalFingerprintHex } from '../identity/fingerprint.js';
import { type ContactKeys, type SenderKeys, type MyKeys } from './contact-message.js';
import { encryptToGroup, decryptFromGroup } from './contact-message-group.js';

const MSG = 'the strong 64-hex — group meet at the barzakh 🌀';

// A full svrnty identity (same construction as contact-message.test.ts).
async function makeIdentity() {
  const { privateKey, publicKey } = (await openpgp.generateKey({
    type: 'ecc',
    curve: 'ed25519',
    userIDs: [{ name: 'id' }],
    format: 'object',
  } as any)) as any;
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
  const asRecipient: MyKeys = {
    x25519Sec: encSec,
    mlkem1024Sec: kem.secretKey,
    x25519Pub: encPub,
    mlkem1024Pub: kem.publicKey,
    myFingerprint: fingerprint,
  };
  return { card, asSender, asRecipient, fingerprint };
}

// White-box: decode the armored group container back to its JSON (to assert dedup + known-group membership).
function decodeContainer(armored: string): { v: number; recipients: { fp: string; armored: string }[] } {
  const B = '-----BEGIN SVRNTY ENCRYPTED GROUP MESSAGE-----';
  const E = '-----END SVRNTY ENCRYPTED GROUP MESSAGE-----';
  const body = armored.slice(armored.indexOf(B) + B.length, armored.indexOf(E)).replace(/\s+/g, '');
  return JSON.parse(new TextDecoder().decode(base64ToUint8(body)));
}

test('★ group round-trip: each of N members opens the message + verifies the sender', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const carol = await makeIdentity();
  const dave = await makeIdentity();
  const armored = await encryptToGroup(MSG, [bob.card, carol.card, dave.card], alice.asSender);
  assert.ok(armored.includes('BEGIN SVRNTY ENCRYPTED GROUP MESSAGE'));
  for (const m of [bob, carol, dave]) {
    const out = await decryptFromGroup(armored, m.asRecipient, alice.card);
    assert.ok(out, 'each member should open their own block');
    assert.equal(out.message, MSG);
    assert.equal(out.senderVerified, true);
    assert.equal(out.senderFingerprint, alice.fingerprint);
  }
});

test('non-member cannot open the group block (null)', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const carol = await makeIdentity();
  const mallory = await makeIdentity(); // NOT in the group
  const armored = await encryptToGroup(MSG, [bob.card, carol.card], alice.asSender);
  assert.equal(await decryptFromGroup(armored, mallory.asRecipient, alice.card), null);
});

test('senderVerified=false without the sender card; message still opens', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const carol = await makeIdentity();
  const armored = await encryptToGroup(MSG, [bob.card, carol.card], alice.asSender);
  const out = await decryptFromGroup(armored, bob.asRecipient); // no senderCard
  assert.ok(out);
  assert.equal(out.message, MSG);
  assert.equal(out.senderVerified, false);
});

test('★ anti-forwarding preserved per block: a member claiming another member’s fp fails sender-verify', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const carol = await makeIdentity();
  const armored = await encryptToGroup(MSG, [bob.card, carol.card], alice.asSender);
  // Bob opens legitimately → verified
  assert.equal((await decryptFromGroup(armored, bob.asRecipient, alice.card))!.senderVerified, true);
  // Bob keeps his own keys but claims Carol's identity fp → the recipient-bound sig (bound to Bob) no
  // longer matches → senderVerified must be false (or he simply can't produce a verified open).
  const bobClaimingCarol: MyKeys = { ...bob.asRecipient, myFingerprint: carol.fingerprint };
  const spoofed = await decryptFromGroup(armored, bobClaimingCarol, alice.card);
  assert.ok(spoofed === null || spoofed.senderVerified === false);
});

test('de-dup by fingerprint: the same contact twice seals ONE block (and membership is visible = known-group)', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const carol = await makeIdentity();
  const armored = await encryptToGroup(MSG, [bob.card, bob.card, carol.card], alice.asSender);
  const container = decodeContainer(armored);
  assert.equal(container.recipients.length, 2, 'duplicate bob de-duped to a single block');
  const fps = container.recipients.map((r) => r.fp).sort();
  assert.deepEqual(fps, [bob.fingerprint, carol.fingerprint].sort()); // fingerprints visible → honest known-group label
  // and it still round-trips for both
  assert.equal((await decryptFromGroup(armored, bob.asRecipient, alice.card))!.message, MSG);
  assert.equal((await decryptFromGroup(armored, carol.asRecipient, alice.card))!.message, MSG);
});

test('single-member group works (degenerate fan-out)', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const armored = await encryptToGroup(MSG, [bob.card], alice.asSender);
  const out = await decryptFromGroup(armored, bob.asRecipient, alice.card);
  assert.ok(out);
  assert.equal(out.message, MSG);
  assert.equal(out.senderVerified, true);
});

test('empty group throws; a contact missing its fingerprint throws (keyed-on-identity contract)', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  await assert.rejects(() => encryptToGroup(MSG, [], alice.asSender), /at least one contact/);
  const noFp: ContactKeys = { ...bob.card, fingerprint: undefined };
  await assert.rejects(() => encryptToGroup(MSG, [noFp], alice.asSender), /must carry its fingerprint/);
});

test('malformed / tampered container → null, never throws', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const armored = await encryptToGroup(MSG, [bob.card], alice.asSender);
  assert.equal(await decryptFromGroup('not a group block', bob.asRecipient, alice.card), null);
  assert.equal(await decryptFromGroup('', bob.asRecipient, alice.card), null);
  // corrupt a char in the body → base64/JSON/shape fails or the inner block fails to open → null
  const lines = armored.split('\n');
  const mid = Math.floor(lines.length / 2);
  lines[mid] = (lines[mid][0] === 'A' ? 'B' : 'A') + lines[mid].slice(1);
  assert.equal(await decryptFromGroup(lines.join('\n'), bob.asRecipient, alice.card), null);
});
