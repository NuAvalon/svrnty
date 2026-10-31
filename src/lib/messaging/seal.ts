// src/lib/messaging/seal.ts
// Seal for notes v0 (Phase 3 rung 1). Patterned on sync/contact-update-envelope.ts.
// CONFIDENTIALITY SWAP (HNDL): when the recipient's ML-KEM-1024 pubkey is supplied, the note's ALREADY-
// SIGNED wire is sealed with the EXISTING hybrid mailbox envelope (living-book-sleeve) — post-quantum on
// the wire. Without it sealNoteTo THROWS (no classical fallback); SEND SITES fail-closed-SKIP a recipient
// with no pq_kem (see transport.sendNoteToPeer) so production NEVER downgrades. A classical blob for tests
// comes from seal-classical-fixture.ts only.
// NOT a Double Ratchet. No signature is added here — authenticity is signNoteWire, re-checked on consume.

import { readPrivateKey, decryptKey, readMessage, decrypt } from 'openpgp';
import { NOTE_WIRE_TYPE } from './domains';
import type { NoteWireV0 } from './types';
import type { UnlockCycle } from '@/lib/crypto/unlock-cycle';
import { sealLivingBookHybrid } from '@/lib/crypto/living-book-sleeve';
import { RECEIPT_V1_WIRE_TYPE, type ReceiptWireV1 } from './receipt-wire-v1';

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

// ── Delivery receipt seal (S62) ──────────────────────────────────────────────────────────────────
// The MAC receipt is sealed hybrid like a note, so at the relay it is the same KIND of object ({mailbox_id, blob}). It is NOT
// indistinguishable from a note: it is about 2.6 KB against 12.5 KB and up (measured, S62 slice 3), and Archie ruled (v8) that this
// residual is stated rather than padded away. The inner `type` discriminator is checked CLIENT-SIDE after opening.

/**
 * Seal the MAC receipt (ReceiptWireV1) to the note SENDER, post-quantum hybrid exactly like a note, so on the relay it is an ordinary
 * sealed envelope. THROWS without the recipient's ML-KEM key: no classical fallback, never a downgrade (the emitter skips instead).
 */
export async function sealReceiptV1To(receipt: ReceiptWireV1, recipientPublicKeyArmored: string, recipientPqKemB64?: string): Promise<string> {
  if (receipt.type !== RECEIPT_V1_WIRE_TYPE) throw new Error('sealReceiptV1To: refusing non-receipt wire type');
  if (!recipientPqKemB64) throw new Error('sealReceiptV1To: refusing to seal without a recipient ML-KEM key (no classical downgrade)');
  return sealLivingBookHybrid(new TextEncoder().encode(JSON.stringify(receipt)), recipientPublicKeyArmored, recipientPqKemB64);
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
