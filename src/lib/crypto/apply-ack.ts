// src/lib/crypto/apply-ack.ts
//
// APPLY-ACK — destination-signed "your contact.update APPLIED" receipt for the living address book
// (svrnty-addressbook-ack-001; mneme audit finding, trust/consume-layer tr). The wire previously had
// ONLY relay-level acks (deposit-accepted + owner ackDelete hygiene) — nothing at the endpoint. This
// is the endpoint half: the RECIPIENT signs "your update ack_of applied into my book" back to the
// AUTHOR, so the author's edge can graduate method_delivery 'awaiting-ack' → 'acked' (and stay the
// honest 'undelivered' when none arrives). Twin of loom's dest-ack-contract-001 intake_ack —
// UDP-at-relay vs TCP-at-endpoint, the same honesty shape on the svrnty contact wire.
//
// ANTI-PANOPTICON (the reason this may ship where the note receipt did not): an apply-ack asserts
// APPLIED, never READ. It fires uniformly + automatically on every successful apply — machine
// attestation of protocol completion, not a human-behavior signal. It carries nothing the author did
// not already cause (they sent the update; its apply is the protocol's own terminus).
//
// SHAPE (rides the EXISTING mailbox path — the receipt pattern): an APPLY_ACK_WIRE_TYPE object the
// RECIPIENT builds on a successful apply and seals with the same OpenPGP envelope to the AUTHOR,
// depositing it to the author's OWN mailbox (deriveMailboxId(author_fp)). At the relay it is
// byte-INDISTINGUISHABLE from any other deposit — opaque {mailbox_id, blob}, no relay-visible "ack"
// field; the update↔ack tie lives only inside the sealed blob. The author's consumeOne seam
// discriminates it CLIENT-SIDE, post-decrypt, by `type` + a DOMAIN_APPLY_ACK signature — never a
// relay-readable flag.
//
// AUTH: the recipient signs {ack_of, to_fp} under a DISTINCT DOMAIN_APPLY_ACK via signWithEnvelope —
// the SAME envelope primitive the contact-update itself rides (domain separation: an ack signature
// can NEVER verify as a note / contact-msg / vouch / card / contact-update / receipt sig). The author
// verifies with the recipient's keys it ALREADY holds (their contact card) — no new trust assumption.
// FAIL-SAFE: a dropped / garbled / forged ack fails verification → method_delivery stays
// 'awaiting-ack' → decays to 'undelivered', never a false 'acked'.
//
// BINDING = ack_of — the update's EnvelopeSignature.classical hex (unique per signed envelope, the
// same string the author produced at send) + to_fp (the author — an ack addressed elsewhere can never
// graduate this edge). The applier's identity is implicit in the verifying key, and re-asserted by
// from_fingerprint matching the edge's peer at the seam.
//
// ACK-OF-ACK IS STRUCTURALLY IMPOSSIBLE: the wire has no apply surface — consumeOne routes it by its
// own seam to a bookkeeping write, and nothing in that path can emit an ack. Duplicate deliveries are
// idempotent: 'acked' is a monotonic write; a second copy re-sets the same value (at-least-once).
//
// NO new crypto / NO seal here — sign/verify delegate to the 0.1 envelope primitive (sign-envelope.ts,
// the SAME one verifyIncomingContactUpdate delegates to) and the seal is sealApplyAckTo in the
// transport wiring (messaging/seal.ts). This module is the pure, seal-independent wire grammar.

import { canonicalize } from '../format/canonical';
import {
  signWithEnvelope,
  verifyWithEnvelope,
  type EnvelopeSignature,
} from './sign-envelope';
import type { UnlockCycle } from './unlock-cycle';
import { normalizeFingerprintHex } from '../identity/fingerprint';

/**
 * DISTINCT domain tag: an apply-ack signature is bound to this domain via buildSignedBytes inside the
 * envelope primitive, so it can never collide with / be replayed as any other signed object type.
 */
export const DOMAIN_APPLY_ACK = 'svrnty:apply-ack:v1';

/**
 * Inner discriminator (travels INSIDE the sealed blob — never a relay-visible field). The author's
 * consumeOne seam routes on this AFTER decrypt.
 */
export const APPLY_ACK_WIRE_TYPE = 'svrnty-apply-ack-v0';

/** The sealed-payload grammar for an apply-ack (sealed with sealApplyAckTo, like a receipt). */
export interface ApplyAckWireV0 {
  type: typeof APPLY_ACK_WIRE_TYPE;
  /** The applied update's EnvelopeSignature.classical hex — WHICH update applied. */
  ack_of: string;
  /** The author's fingerprint — WHO the ack is for (the consume seam requires it == owner). */
  to_fp: string;
  /** The applying recipient's fingerprint (verified via their card at the seam). */
  from_fingerprint: string;
  /** EnvelopeSignature over DOMAIN_APPLY_ACK (classical armored ‖ pq_signature when the signer is hybrid). */
  signature: EnvelopeSignature;
}

/** The canonical signing input for an apply-ack — the object the signature binds, verbatim. */
export function applyAckSigningInput(ackOf: string, toFp: string): string {
  return canonicalize({ ack_of: ackOf, to_fp: toFp });
}

/**
 * Recipient signs "I applied your update ack_of" — signWithEnvelope binds the domain + suite, so a
 * stripped-PQ downgrade and a cross-domain replay both fail at verify. Classical signers produce a
 * classical sig (honest — an apply-ack is a NEW artifact with no hybrid to strip); a caller that must
 * REQUIRE hybrid enforces pq_signature presence at the seam (same rule as the update verify).
 */
export async function signApplyAck(
  ackOf: string,
  toFp: string,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
  pqSigningSecretKey?: Uint8Array,
  cycle?: UnlockCycle,
): Promise<EnvelopeSignature> {
  return signWithEnvelope(
    DOMAIN_APPLY_ACK,
    applyAckSigningInput(ackOf, toFp),
    classicalPrivateKeyArmored,
    classicalPassphrase,
    pqSigningSecretKey,
    cycle,
  );
}

/** Verify an ack signature with the applier's known keys. FAIL-SAFE: any error ⇒ false. */
export async function verifyApplyAck(
  ackOf: string,
  toFp: string,
  signature: EnvelopeSignature,
  applierPublicKeyArmored: string,
  applierPqSigningPublicKey?: Uint8Array,
): Promise<boolean> {
  try {
    return await verifyWithEnvelope(
      DOMAIN_APPLY_ACK,
      applyAckSigningInput(ackOf, toFp),
      signature,
      applierPublicKeyArmored,
      applierPqSigningPublicKey,
    );
  } catch {
    return false;
  }
}

// ── ack-wire grammar (built by the recipient on apply; parsed+verified by the author on poll) ──────
/** Build a signed ack-wire for {ack_of, to_fp} as the applying recipient (to be sealApplyAckTo'd). */
export async function buildApplyAckWire(
  ackOf: string,
  toFp: string,
  recipientFingerprint: string,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
  pqSigningSecretKey?: Uint8Array,
  cycle?: UnlockCycle,
): Promise<ApplyAckWireV0> {
  return {
    type: APPLY_ACK_WIRE_TYPE,
    ack_of: ackOf,
    to_fp: normalizeFingerprintHex(toFp),
    from_fingerprint: normalizeFingerprintHex(recipientFingerprint),
    signature: await signApplyAck(ackOf, toFp, classicalPrivateKeyArmored, classicalPassphrase, pqSigningSecretKey, cycle),
  };
}

/**
 * Discriminator for the author's consumeOne seam: is a decrypted mailbox payload an apply-ack wire?
 * Returns null for anything that isn't one (caller continues other pipelines — same shape as
 * tryParseReceiptWire). `signature.classical` must be a string (mirrors assertWellFormed's gate);
 * pq_signature passes through as-is so the verify-side guard refuses malformed values (#717 shape).
 */
export function tryParseApplyAckWire(obj: unknown): ApplyAckWireV0 | null {
  if (!obj || typeof obj !== 'object') return null;
  const o = obj as Record<string, unknown>;
  if (o.type !== APPLY_ACK_WIRE_TYPE) return null;
  if (
    typeof o.ack_of !== 'string' ||
    typeof o.to_fp !== 'string' ||
    typeof o.from_fingerprint !== 'string' ||
    !o.signature ||
    typeof (o.signature as Record<string, unknown>).classical !== 'string'
  )
    return null;
  return o as unknown as ApplyAckWireV0;
}

/**
 * Full ack check for the author: the wire's claimed (ack_of, to_fp) must match what the author
 * recorded for that peer's pending update AND the applier's keys must sign exactly those.
 * expected.fromFingerprint is the edge's peer — the wire's from_fingerprint must match it (the
 * verifying key already binds identity; this rejects an ack claiming a different applier).
 */
export async function verifyApplyAckWire(
  wire: ApplyAckWireV0,
  expected: { ackOf: string; toFp: string; fromFingerprint: string },
  applierPublicKeyArmored: string,
  applierPqSigningPublicKey?: Uint8Array,
): Promise<boolean> {
  if (wire.ack_of !== expected.ackOf) return false;
  const wireTo = normalizeFingerprintHex(wire.to_fp);
  const expectedTo = normalizeFingerprintHex(expected.toFp);
  if (!wireTo || wireTo !== expectedTo) return false; // not addressed to this owner
  const wireFrom = normalizeFingerprintHex(wire.from_fingerprint);
  const expectedFrom = normalizeFingerprintHex(expected.fromFingerprint);
  if (!wireFrom || wireFrom !== expectedFrom) return false; // empty/malformed or a different applier
  return verifyApplyAck(wire.ack_of, wire.to_fp, wire.signature, applierPublicKeyArmored, applierPqSigningPublicKey);
}
