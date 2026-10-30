// src/lib/crypto/delivery-receipt.ts
//
// TRUST-BLIND DELIVERY RECEIPT — crypto core (Athena — Nov-5 delivered-receipt; Archie route #172169,
// Peter's explicit want; Flint design-OK #172192 + fold=(b) #172196). Graduates a note's send-status
// "Sent · unconfirmed" → "Delivered" — but ONLY on a cryptographically VERIFIED receipt
// (notes-status.ts FORBIDDEN_LIVE_STATUS stays a hard floor for every unverified path; a receipt-backed
// Delivered is honest, an unverified one is forbidden).
//
// SHAPE (rides the EXISTING note path — Flint fold=(b) + conditions #1/#3): a receipt is a
// RECEIPT_WIRE_TYPE object the RECIPIENT builds on consuming a note and seals with the SAME sealNoteTo
// (OpenPGP) to the ORIGINAL SENDER, depositing it to the sender's OWN mailbox (deriveMailboxId(sender_fp)).
// At the relay it is byte-INDISTINGUISHABLE from a note-deposit — opaque {mailbox_id, blob}, no
// relay-visible "receipt" field; the note↔receipt tie lives only inside the sealed blob. The sender's
// existing main-mailbox poll picks it up and the (new) consumeOne seam discriminates it CLIENT-SIDE,
// post-decrypt, by this module's `type` + a DOMAIN_RECEIPT-signed body — never a relay-readable flag.
//
// AUTH (Flint Q2): the recipient signs {note_id, nonce} under a DISTINCT DOMAIN_RECEIPT via the LP
// preimage (buildSignedBytes — the #249/contact-message pattern), so a receipt signature can NEVER
// verify as a note / contact-msg / vouch / card signature ([[pipe-canon]] domain separation). The
// sender verifies with the recipient's key it ALREADY holds (their contact card) — no new trust
// assumption. FAIL-SAFE: a dropped / garbled / forged receipt fails verification → status stays the
// honest "unconfirmed" floor, never a false "Delivered". Binding = note_id (anti cross-note replay) +
// nonce (freshness, the sender's per-note value carried in the sealed note); the recipient identity is
// implicit in the verifying key.
//
// NO new crypto / NO seal here — the seal is sealNoteTo in the transport wiring (so it matches a note
// byte-for-byte). This module is the pure, seal-independent sign/verify core + the receipt-wire grammar.

import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { canonicalize } from '../format/canonical';
import { buildSignedBytes, SUITE_HYBRID } from './sign-envelope';
import { AUTH_ED25519_SIG_BYTES, normalizeFingerprintHex } from '../identity/fingerprint';
import { sign as pqSign, verify as pqVerify } from './pq';

/**
 * DISTINCT domain tag (Flint requirement): a receipt signature is bound to this domain via the LP
 * preimage, so it can never collide with / be replayed as a note, contact-msg, vouch, or card sig.
 */
export const DOMAIN_RECEIPT = 'svrnty:receipt:v1';

/**
 * Inner discriminator (travels INSIDE the sealed blob, exactly like NOTE_WIRE_TYPE — never a
 * relay-visible field). The sender's consumeOne seam routes on this AFTER decrypt.
 */
export const RECEIPT_WIRE_TYPE = 'svrnty-receipt-v0';

/** The sealed-payload grammar for a delivery receipt (sealed with sealNoteTo, like a note). */
export interface ReceiptWireV0 {
  type: typeof RECEIPT_WIRE_TYPE;
  note_id: string; // the note being confirmed delivered
  nonce: string; // the sender's per-note freshness value (carried in the original sealed note)
  from_fingerprint: string; // the delivering recipient's identity id (verify via their card)
  sig: string; // hybrid hex(ed25519-sig 64B ‖ ML-DSA-87-sig) over the DOMAIN_RECEIPT preimage
}

// ── DOMAIN_RECEIPT preimage + sig (binds note_id + nonce; recipient-identity implicit in the key) ───
function receiptPreimage(noteId: string, nonce: string): Uint8Array {
  const canonical = canonicalize({ note_id: noteId, nonce });
  return utf8ToBytes(buildSignedBytes(DOMAIN_RECEIPT, SUITE_HYBRID, canonical));
}

/** Recipient signs "I delivered note_id (nonce)" — hybrid ed25519 ‖ ML-DSA-87 over the LP preimage. */
export function signDeliveryReceipt(noteId: string, nonce: string, signSeed: Uint8Array, sigSecret: Uint8Array): string {
  const p = receiptPreimage(noteId, nonce);
  return bytesToHex(concatBytes(ed25519.sign(p, signSeed), pqSign(p, sigSecret)));
}

/** Verify a receipt sig with the recipient's known keys. FAIL-SAFE: any error ⇒ false. */
export function verifyDeliveryReceipt(
  noteId: string,
  nonce: string,
  sigHex: string,
  recipientSignPub: Uint8Array,
  recipientSigPub: Uint8Array,
): boolean {
  try {
    const sig = hexToBytes(sigHex);
    if (sig.length <= AUTH_ED25519_SIG_BYTES) return false;
    const p = receiptPreimage(noteId, nonce);
    if (!ed25519.verify(sig.subarray(0, AUTH_ED25519_SIG_BYTES), p, recipientSignPub)) return false;
    return pqVerify(p, sig.subarray(AUTH_ED25519_SIG_BYTES), recipientSigPub);
  } catch {
    return false;
  }
}

// ── receipt-wire grammar (built by the recipient on consume; parsed+verified by the sender on poll) ─
/** Build a signed receipt-wire for {note_id, nonce} as the delivering recipient (to be sealNoteTo'd). */
export function buildReceiptWire(
  noteId: string,
  nonce: string,
  recipientFingerprint: string,
  signSeed: Uint8Array,
  sigSecret: Uint8Array,
): ReceiptWireV0 {
  return {
    type: RECEIPT_WIRE_TYPE,
    note_id: noteId,
    nonce,
    from_fingerprint: normalizeFingerprintHex(recipientFingerprint),
    sig: signDeliveryReceipt(noteId, nonce, signSeed, sigSecret),
  };
}

/**
 * Discriminator for the sender's consumeOne seam: is a decrypted mailbox payload a receipt-wire?
 * Mirrors tryParseNoteWire — returns null for anything that isn't one (caller continues other pipelines).
 */
export function tryParseReceiptWire(obj: unknown): ReceiptWireV0 | null {
  if (!obj || typeof obj !== 'object') return null;
  const o = obj as Record<string, unknown>;
  if (o.type !== RECEIPT_WIRE_TYPE) return null;
  if (typeof o.note_id !== 'string' || typeof o.nonce !== 'string' || typeof o.from_fingerprint !== 'string' || typeof o.sig !== 'string')
    return null;
  return o as unknown as ReceiptWireV0;
}

/**
 * Full receipt check for the sender: the wire's claimed (note_id, nonce) must match what the sender
 * recorded for the note AND the recipient's keys must sign exactly those. recipientFingerprint is the
 * fp the sender expects for this thread's peer — the wire's `from_fingerprint` must match it (the
 * verifying key already binds identity; this rejects a receipt claiming a different deliverer).
 */
export function verifyReceiptWire(
  wire: ReceiptWireV0,
  expected: { noteId: string; nonce: string; recipientFingerprint: string },
  recipientSignPub: Uint8Array,
  recipientSigPub: Uint8Array,
): boolean {
  if (wire.note_id !== expected.noteId) return false;
  if (wire.nonce !== expected.nonce) return false;
  const wireFp = normalizeFingerprintHex(wire.from_fingerprint);
  const expectedFp = normalizeFingerprintHex(expected.recipientFingerprint);
  if (!wireFp || wireFp !== expectedFp) return false; // reject empty/malformed or a mismatched deliverer
  return verifyDeliveryReceipt(wire.note_id, wire.nonce, wire.sig, recipientSignPub, recipientSigPub);
}
