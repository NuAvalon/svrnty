// src/lib/messaging/seal.ts
// Seal for notes v0 (Phase 3 rung 1). Patterned on sync/contact-update-envelope.ts.
// CONFIDENTIALITY SWAP (HNDL): when the recipient's ML-KEM-1024 pubkey is supplied, the note's ALREADY-
// SIGNED wire is sealed with the EXISTING hybrid mailbox envelope (living-book-sleeve) — post-quantum on
// the wire. Without it sealNoteTo THROWS (no classical fallback); SEND SITES fail-closed-SKIP a recipient
// with no pq_kem (see transport.sendNoteToPeer) so production NEVER downgrades. A classical blob for tests
// comes from seal-classical-fixture.ts only.
// NOT a Double Ratchet. No signature is added here — authenticity is signNoteWire, re-checked on consume.

import { createMessage, encrypt, readKey, readPrivateKey, decryptKey, readMessage, decrypt } from 'openpgp';
import { NOTE_WIRE_TYPE } from './domains';
import type { NoteWireV0 } from './types';
import type { UnlockCycle } from '@/lib/crypto/unlock-cycle';
import { sealLivingBookHybrid } from '@/lib/crypto/living-book-sleeve';
import { RECEIPT_WIRE_TYPE, tryParseReceiptWire, type ReceiptWireV0 } from '@/lib/crypto/delivery-receipt';
import { APPLY_ACK_WIRE_TYPE, tryParseApplyAckWire, type ApplyAckWireV0 } from '@/lib/crypto/apply-ack';

export async function sealNoteTo(
  note: NoteWireV0,
  recipientPublicKeyArmored: string,
  recipientPqKemB64?: string,
): Promise<string> {
  if (note.type !== NOTE_WIRE_TYPE) {
    throw new Error('sealNoteTo: refusing non-note wire type');
  }
  // HYBRID (HNDL) only: wrap the signed wire bytes with the recipient's ML-KEM pubkey. Reject-classical by construction
  // (living-book-sleeve → mailbox-env). There is NO classical fallback here: a note without a recipient KEM key is refused, never
  // downgraded. The send sites already skip when there is no verified pq_kem, so reaching this throw is a bug in a caller, and it
  // must be loud. Tests that need a CLASSICAL blob (the open path's back-compat) use seal-classical-fixture.ts, which no app code
  // may import (pinned by seal-no-downgrade.test.ts). The runner does not set NODE_ENV, so "outside tests" is enforced by
  // structure, not by sniffing the environment.
  if (!recipientPqKemB64) {
    throw new Error('sealNoteTo: refusing to seal without a recipient ML-KEM key (no classical downgrade)');
  }
  return sealLivingBookHybrid(new TextEncoder().encode(JSON.stringify(note)), recipientPublicKeyArmored, recipientPqKemB64);
}

/**
 * The note inner-wire type-gate, exported as a `WireParser` for the SINGLE dual-read chokepoint
 * (src/lib/sync/hybrid-dual-read.ts: makeHybridOpener(openEnv, parseNoteWire)) so the hybrid opener
 * reuses the EXACT same discriminator the classical opener uses → no-cross-swallow is byte-identical.
 * Returns null on non-JSON or any non-note wire (a hybrid/classical pkg of another inner type fails the
 * NOTE_WIRE_TYPE gate → null → the consume 4-way demux falls through).
 */
export function parseNoteWire(innerUtf8: string): NoteWireV0 | null {
  try {
    const p = JSON.parse(innerUtf8) as NoteWireV0;
    if (p?.type !== NOTE_WIRE_TYPE) return null;
    if (typeof p.body !== 'string' || typeof p.from_fingerprint !== 'string') return null;
    return p;
  } catch {
    return null;
  }
}

/**
 * Decrypt a CLASSICAL OpenPGP note blob → NoteWireV0, or null on any failure (I-1 silent drop) / non-note
 * wire. Classical-ONLY: the PQ-hybrid dual-read now lives in the SINGLE chokepoint (hybrid-dual-read.ts
 * dualReadOpener(makeHybridOpener(openEnv, parseNoteWire), noteOpenpgpDecryptor)) composed by the consume
 * deps builders — this opener is its classical fallback. The type-gate is the exported {@link parseNoteWire},
 * which the hybrid opener reuses so no-cross-swallow is byte-identical across both legs.
 */
export function noteOpenpgpDecryptor(
  recipientPrivateKeyArmored: string,
  passphrase: string,
  cycle?: UnlockCycle,
): (blob: string) => Promise<NoteWireV0 | null> {
  return async (blob: string): Promise<NoteWireV0 | null> => {
    try {
      const decryptionKeys = cycle ? await cycle.key() : await decryptKey({ privateKey: await readPrivateKey({ armoredKey: recipientPrivateKeyArmored }), passphrase });
      const message = await readMessage({ armoredMessage: blob });
      const { data } = await decrypt({ message, decryptionKeys });
      const text = typeof data === 'string' ? data : await streamToText(data);
      return parseNoteWire(text);
    } catch {
      return null;
    }
  };
}

// ── Delivery-receipt seal pair (Athena — Nov-5 delivered-receipt) ──────────────────────────────────
// A receipt is sealed EXACTLY like a note (OpenPGP to the recipient's pubkey → opaque blob) so at the
// relay it is byte-indistinguishable from a note deposit ({mailbox_id, blob}). The ONLY difference is
// the inner `type` discriminator (RECEIPT_WIRE_TYPE), checked CLIENT-SIDE post-decrypt. We keep a
// SEPARATE pair (not a loosened sealNoteTo) so the note type-guard stays intact and a receipt decryptor
// returns null for a note / contact-update / affirm (and vice-versa) — the 5-way no-cross-swallow in
// consumeOne depends on each decryptor refusing every other type.

/** Seal a receipt-wire to the original sender's OpenPGP pubkey → opaque blob (like sealNoteTo). */
export async function sealReceiptTo(
  receipt: ReceiptWireV0,
  recipientPublicKeyArmored: string,
): Promise<string> {
  if (receipt.type !== RECEIPT_WIRE_TYPE) {
    throw new Error('sealReceiptTo: refusing non-receipt wire type');
  }
  const encryptionKeys = await readKey({ armoredKey: recipientPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(receipt) });
  return (await encrypt({ message, encryptionKeys })) as string;
}

/**
 * The receipt inner-wire type-gate, string in → ReceiptWireV0 | null. Exported as a `WireParser` for the single
 * dual-read chokepoint (hybrid-dual-read.ts: makeHybridOpener(openEnv, parseReceiptWire)) so the hybrid leg and
 * the classical leg run the EXACT same discriminator → no-cross-swallow is byte-identical on both (same shape as
 * {@link parseNoteWire}). Null on non-JSON or any non-receipt shape.
 */
export function parseReceiptWire(innerUtf8: string): ReceiptWireV0 | null {
  try {
    return tryParseReceiptWire(JSON.parse(innerUtf8));
  } catch {
    return null;
  }
}

/**
 * Decrypt opaque blob → ReceiptWireV0, or null on any failure / non-receipt (I-1 silent drop). Classical
 * fallback leg of the dual-read; like {@link noteOpenpgpDecryptor} it runs OFF the poll's N10 unlock cycle when one
 * is given (a lock / identity switch mid-tick must stop THIS decryptor too: a receipt must not be opened, and so
 * not accepted, after the cycle ended).
 */
export function receiptOpenpgpDecryptor(
  recipientPrivateKeyArmored: string,
  passphrase: string,
  cycle?: UnlockCycle,
): (blob: string) => Promise<ReceiptWireV0 | null> {
  return async (blob: string): Promise<ReceiptWireV0 | null> => {
    try {
      const decryptionKeys = cycle ? await cycle.key() : await decryptKey({ privateKey: await readPrivateKey({ armoredKey: recipientPrivateKeyArmored }), passphrase });
      const message = await readMessage({ armoredMessage: blob });
      const { data } = await decrypt({ message, decryptionKeys });
      const text = typeof data === 'string' ? data : await streamToText(data);
      return parseReceiptWire(text); // null for any non-receipt shape → caller falls through
    } catch {
      return null;
    }
  };
}

// ── Apply-ack seal pair (svrnty-addressbook-ack-001) ────────────────────────────────────────────────
// An apply-ack is sealed EXACTLY like a receipt (OpenPGP to the author's pubkey → opaque blob) so at
// the relay it is byte-indistinguishable from any other deposit ({mailbox_id, blob}). The ONLY
// difference is the inner `type` discriminator (APPLY_ACK_WIRE_TYPE), checked CLIENT-SIDE post-decrypt.
// Separate pair (not a loosened sealNoteTo / sealReceiptTo) so each decryptor refuses every other
// type — the no-cross-swallow in consumeOne depends on it. HYBRID UPGRADE rides the receipt pair's
// own path when that lands (crypto/apply-ack.ts header) — for now the ack is a classical-envelope
// artifact like the receipt it twins.

/** Seal an apply-ack wire to the update author's OpenPGP pubkey → opaque blob (like sealReceiptTo). */
export async function sealApplyAckTo(
  ack: ApplyAckWireV0,
  authorPublicKeyArmored: string,
): Promise<string> {
  if (ack.type !== APPLY_ACK_WIRE_TYPE) {
    throw new Error('sealApplyAckTo: refusing non-apply-ack wire type');
  }
  const encryptionKeys = await readKey({ armoredKey: authorPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(ack) });
  return (await encrypt({ message, encryptionKeys })) as string;
}

/**
 * The apply-ack inner-wire type-gate, string in → ApplyAckWireV0 | null. Exported as a `WireParser` for
 * the single dual-read chokepoint (hybrid-dual-read.ts: makeHybridOpener(openEnv, parseApplyAckWire)) so
 * the hybrid leg and the classical leg run the EXACT same discriminator — no-cross-swallow byte-identical.
 */
export function parseApplyAckWire(innerUtf8: string): ApplyAckWireV0 | null {
  try {
    return tryParseApplyAckWire(JSON.parse(innerUtf8));
  } catch {
    return null;
  }
}

/**
 * Decrypt opaque blob → ApplyAckWireV0, or null on any failure / non-ack (I-1 silent drop). Classical
 * fallback leg of the dual-read; runs OFF the poll's N10 unlock cycle like the other decryptors.
 */
export function applyAckOpenpgpDecryptor(
  recipientPrivateKeyArmored: string,
  passphrase: string,
  cycle?: UnlockCycle,
): (blob: string) => Promise<ApplyAckWireV0 | null> {
  return async (blob: string): Promise<ApplyAckWireV0 | null> => {
    try {
      const decryptionKeys = cycle ? await cycle.key() : await decryptKey({ privateKey: await readPrivateKey({ armoredKey: recipientPrivateKeyArmored }), passphrase });
      const message = await readMessage({ armoredMessage: blob });
      const { data } = await decrypt({ message, decryptionKeys });
      const text = typeof data === 'string' ? data : await streamToText(data);
      return parseApplyAckWire(text); // null for any non-ack shape → caller falls through
    } catch {
      return null;
    }
  };
}

async function streamToText(data: unknown): Promise<string> {
  const maybe = data as { getReader?: () => ReadableStreamDefaultReader };
  if (typeof maybe?.getReader !== 'function') return String(data);
  const reader = maybe.getReader();
  const dec = new TextDecoder();
  let out = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    out += typeof value === 'string' ? value : dec.decode(value as BufferSource, { stream: true });
  }
  return out;
}
