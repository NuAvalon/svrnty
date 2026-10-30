// Run: npx tsx --test src/lib/crypto/delivery-receipt.test.ts
//
// Delivery-receipt crypto core: DOMAIN_RECEIPT-signed {note_id, nonce} (forge-proof, fail-safe) +
// the receipt-wire grammar the sender's consumeOne seam parses & verifies. Raw-key tests (no OpenPGP
// needed — like contact-message.test.ts's core).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { generateSigningKeypair } from './pq.js';
import {
  DOMAIN_RECEIPT,
  RECEIPT_WIRE_TYPE,
  signDeliveryReceipt,
  verifyDeliveryReceipt,
  buildReceiptWire,
  tryParseReceiptWire,
  verifyReceiptWire,
} from './delivery-receipt.js';

const NOTE_ID = 'note_abc123';
const NONCE = 'nonce_deadbeef';
const FP_R = 'a1'.repeat(32); // recipient (the deliverer) — valid 64-hex

function makeRecipientSigner() {
  const signSeed = new Uint8Array(32).fill(0x22);
  const signPub = ed25519.getPublicKey(signSeed);
  const sig = generateSigningKeypair();
  return { signSeed, sigSecret: sig.secretKey, signPub, sigPub: sig.publicKey };
}

test('round-trip: a receipt the recipient signs verifies for the exact (note_id, nonce)', () => {
  const r = makeRecipientSigner();
  const sigHex = signDeliveryReceipt(NOTE_ID, NONCE, r.signSeed, r.sigSecret);
  assert.equal(verifyDeliveryReceipt(NOTE_ID, NONCE, sigHex, r.signPub, r.sigPub), true);
});

test('anti cross-note / freshness: wrong note_id or wrong nonce fails', () => {
  const r = makeRecipientSigner();
  const sigHex = signDeliveryReceipt(NOTE_ID, NONCE, r.signSeed, r.sigSecret);
  assert.equal(verifyDeliveryReceipt('note_OTHER', NONCE, sigHex, r.signPub, r.sigPub), false);
  assert.equal(verifyDeliveryReceipt(NOTE_ID, 'nonce_OTHER', sigHex, r.signPub, r.sigPub), false);
});

test('forge-proof + fail-safe: tampered sig / different signer / garbage all fail, never throw', () => {
  const r = makeRecipientSigner();
  const other = makeRecipientSigner();
  const sigHex = signDeliveryReceipt(NOTE_ID, NONCE, r.signSeed, r.sigSecret);
  const tampered = (sigHex[0] === 'a' ? 'b' : 'a') + sigHex.slice(1);
  assert.equal(verifyDeliveryReceipt(NOTE_ID, NONCE, tampered, r.signPub, r.sigPub), false);
  assert.equal(verifyDeliveryReceipt(NOTE_ID, NONCE, sigHex, other.signPub, other.sigPub), false);
  assert.equal(verifyDeliveryReceipt(NOTE_ID, NONCE, 'not-hex', r.signPub, r.sigPub), false);
  assert.equal(verifyDeliveryReceipt(NOTE_ID, NONCE, '', r.signPub, r.sigPub), false);
});

test('wire grammar: build → parse → verifyReceiptWire (valid), + rejects every mismatch', () => {
  const r = makeRecipientSigner();
  const wire = buildReceiptWire(NOTE_ID, NONCE, FP_R, r.signSeed, r.sigSecret);
  assert.equal(wire.type, RECEIPT_WIRE_TYPE);
  const parsed = tryParseReceiptWire(JSON.parse(JSON.stringify(wire)));
  assert.ok(parsed);
  assert.equal(
    verifyReceiptWire(parsed, { noteId: NOTE_ID, nonce: NONCE, recipientFingerprint: FP_R }, r.signPub, r.sigPub),
    true,
  );
  // a receipt claiming a different deliverer than the thread's peer → reject
  assert.equal(
    verifyReceiptWire(parsed, { noteId: NOTE_ID, nonce: NONCE, recipientFingerprint: 'b2'.repeat(32) }, r.signPub, r.sigPub),
    false,
  );
  // expected note_id / nonce mismatch → reject
  assert.equal(
    verifyReceiptWire(parsed, { noteId: 'note_X', nonce: NONCE, recipientFingerprint: FP_R }, r.signPub, r.sigPub),
    false,
  );
  assert.equal(
    verifyReceiptWire(parsed, { noteId: NOTE_ID, nonce: 'n_X', recipientFingerprint: FP_R }, r.signPub, r.sigPub),
    false,
  );
});

test('tryParseReceiptWire rejects non-receipts + malformed', () => {
  assert.equal(tryParseReceiptWire(null), null);
  assert.equal(tryParseReceiptWire({ type: 'svrnty-note-v0', note_id: 'x' }), null);
  assert.equal(tryParseReceiptWire({ type: RECEIPT_WIRE_TYPE }), null);
  assert.equal(tryParseReceiptWire({ type: RECEIPT_WIRE_TYPE, note_id: 'x', nonce: 'y', from_fingerprint: 'z' }), null);
});

test('DOMAIN_RECEIPT is the distinct receipt domain tag', () => {
  assert.equal(DOMAIN_RECEIPT, 'svrnty:receipt:v1');
});
