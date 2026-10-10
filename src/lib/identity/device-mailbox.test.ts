// src/lib/identity/device-mailbox.test.ts
// piece-2 device-mailbox — pure-logic pins for the public-block helpers (no IndexedDB, no PGP).
//   npx tsx --test src/lib/identity/device-mailbox.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex } from '@noble/hashes/utils.js';
import { generateMailboxKeypair, serializeMailboxKeypair, deserializeMailboxKeypair, toPublicKeys } from '../crypto/mailbox-keys.js';
import { deriveMailboxFp } from '../crypto/mailbox-envelope.js';
import {
  validateMailboxPublic,
  extractValidMailboxFromCard,
  peerDeviceMailbox,
  mailboxPublicOf,
  type DeviceMailboxPublic,
} from './device-mailbox.js';

function freshPublic(): DeviceMailboxPublic {
  return mailboxPublicOf(toPublicKeys(generateMailboxKeypair()));
}

test('serialize → deserialize round-trips the keypair bytes exactly', () => {
  const kp = generateMailboxKeypair();
  const back = deserializeMailboxKeypair(serializeMailboxKeypair(kp));
  assert.deepEqual(back.x25519Pub, kp.x25519Pub);
  assert.deepEqual(back.x25519Sec, kp.x25519Sec);
  assert.deepEqual(back.mlkem1024Pub, kp.mlkem1024Pub);
  assert.deepEqual(back.mlkem1024Sec, kp.mlkem1024Sec);
});

test('mailboxPublicOf: fp = SHA256(x25519_pub ‖ mlkem1024_pub) and lengths are the suite-exact hex', () => {
  const kp = generateMailboxKeypair();
  const pub = mailboxPublicOf(toPublicKeys(kp));
  assert.equal(pub.mailbox_fp, deriveMailboxFp(kp.x25519Pub, kp.mlkem1024Pub));
  assert.equal(pub.mailbox_x25519_pk.length, 64);     // 32B
  assert.equal(pub.mailbox_mlkem1024_pk.length, 3136); // 1568B
  assert.equal(pub.mailbox_fp.length, 64);             // 32B
});

test('validateMailboxPublic: accepts a well-formed, content-consistent block', () => {
  const pub = freshPublic();
  assert.deepEqual(validateMailboxPublic(pub), pub);
});

test('validateMailboxPublic: rejects null/undefined/non-object', () => {
  assert.equal(validateMailboxPublic(null), null);
  assert.equal(validateMailboxPublic(undefined), null);
  assert.equal(validateMailboxPublic('nope'), null);
  assert.equal(validateMailboxPublic(42), null);
});

test('validateMailboxPublic: rejects a missing field', () => {
  const pub = freshPublic();
  assert.equal(validateMailboxPublic({ mailbox_fp: pub.mailbox_fp, mailbox_x25519_pk: pub.mailbox_x25519_pk }), null);
});

test('validateMailboxPublic: rejects wrong hex length', () => {
  const pub = freshPublic();
  assert.equal(validateMailboxPublic({ ...pub, mailbox_x25519_pk: pub.mailbox_x25519_pk.slice(0, 62) }), null);
  assert.equal(validateMailboxPublic({ ...pub, mailbox_mlkem1024_pk: pub.mailbox_mlkem1024_pk + 'ab' }), null);
});

test('validateMailboxPublic: rejects non-hex characters', () => {
  const pub = freshPublic();
  // same length, but 'zz' is not hex
  assert.equal(validateMailboxPublic({ ...pub, mailbox_fp: 'zz' + pub.mailbox_fp.slice(2) }), null);
});

test('validateMailboxPublic: rejects a self-INCONSISTENT fp (fp ≠ H(keys)) — the content-address gate', () => {
  const pub = freshPublic();
  // valid length + hex, but not the content address of the carried keys
  assert.equal(validateMailboxPublic({ ...pub, mailbox_fp: '0'.repeat(64) }), null);
});

test('extractValidMailboxFromCard: pulls a valid block from card.identity', () => {
  const pub = freshPublic();
  const cardIdentity = { fingerprint: 'f', public_key: 'k', ...pub };
  assert.deepEqual(extractValidMailboxFromCard(cardIdentity), pub);
});

test('extractValidMailboxFromCard: absent fields → null (legacy card, quiet)', () => {
  assert.equal(extractValidMailboxFromCard({ fingerprint: 'f', public_key: 'k' }), null);
  assert.equal(extractValidMailboxFromCard(null), null);
});

test('extractValidMailboxFromCard: PARTIAL (only fp present) → null (fail-closed, not a usable target)', () => {
  const pub = freshPublic();
  assert.equal(extractValidMailboxFromCard({ mailbox_fp: pub.mailbox_fp }), null);
});

test('extractValidMailboxFromCard: present-but-tampered fp → null (content-address mismatch)', () => {
  const pub = freshPublic();
  assert.equal(extractValidMailboxFromCard({ ...pub, mailbox_fp: 'a'.repeat(64) }), null);
});

test('peerDeviceMailbox: a stored contact block → seal-target bytes + fp (round-trips the hex)', () => {
  const kp = generateMailboxKeypair();
  const pub = mailboxPublicOf(toPublicKeys(kp));
  const target = peerDeviceMailbox({ device_mailbox: pub });
  assert.ok(target);
  assert.equal(bytesToHex(target.publicKeys.x25519Pub), pub.mailbox_x25519_pk);
  assert.equal(bytesToHex(target.publicKeys.mlkem1024Pub), pub.mailbox_mlkem1024_pk);
  assert.equal(target.fp, pub.mailbox_fp);
  // the reconstructed pubkeys content-address back to the same fp
  assert.equal(deriveMailboxFp(target.publicKeys.x25519Pub, target.publicKeys.mlkem1024Pub), pub.mailbox_fp);
});

test('peerDeviceMailbox: no/absent/malformed mailbox → null (emit under-reveals, fail-closed)', () => {
  assert.equal(peerDeviceMailbox(null), null);
  assert.equal(peerDeviceMailbox(undefined), null);
  assert.equal(peerDeviceMailbox({}), null);
  const pub = freshPublic();
  assert.equal(peerDeviceMailbox({ device_mailbox: { ...pub, mailbox_fp: '0'.repeat(64) } }), null);
});
