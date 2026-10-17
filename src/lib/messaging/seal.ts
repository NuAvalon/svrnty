// src/lib/messaging/seal.ts
// Classical seal for notes v0 (Phase 3 rung 1).
// Patterned on sync/contact-update-envelope.ts — OpenPGP to admitted peer pubkey.
// NOT a Double Ratchet. Hybrid-PQ wrapper is the named upgrade (#116410), not this file's job.

import { createMessage, encrypt, readKey, readPrivateKey, decryptKey, readMessage, decrypt } from 'openpgp';
import { NOTE_WIRE_TYPE } from './domains';
import type { NoteWireV0 } from './types';
import { RECEIPT_WIRE_TYPE, tryParseReceiptWire, type ReceiptWireV0 } from '@/lib/crypto/delivery-receipt';

export async function sealNoteTo(
  note: NoteWireV0,
  recipientPublicKeyArmored: string,
): Promise<string> {
  if (note.type !== NOTE_WIRE_TYPE) {
    throw new Error('sealNoteTo: refusing non-note wire type');
  }
  const encryptionKeys = await readKey({ armoredKey: recipientPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(note) });
  return (await encrypt({ message, encryptionKeys })) as string;
}

/** Decrypt opaque blob → NoteWireV0, or null on any failure (I-1 silent drop). */
export function noteOpenpgpDecryptor(
  recipientPrivateKeyArmored: string,
  passphrase: string,
): (blob: string) => Promise<NoteWireV0 | null> {
  return async (blob: string): Promise<NoteWireV0 | null> => {
    try {
      const locked = await readPrivateKey({ armoredKey: recipientPrivateKeyArmored });
      const decryptionKeys = await decryptKey({ privateKey: locked, passphrase });
      const message = await readMessage({ armoredMessage: blob });
      const { data } = await decrypt({ message, decryptionKeys });
      const text = typeof data === 'string' ? data : await streamToText(data);
      const parsed = JSON.parse(text) as NoteWireV0;
      if (parsed?.type !== NOTE_WIRE_TYPE) return null;
      if (typeof parsed.body !== 'string' || typeof parsed.from_fingerprint !== 'string') return null;
      return parsed;
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

/** Decrypt opaque blob → ReceiptWireV0, or null on any failure / non-receipt (I-1 silent drop). */
export function receiptOpenpgpDecryptor(
  recipientPrivateKeyArmored: string,
  passphrase: string,
): (blob: string) => Promise<ReceiptWireV0 | null> {
  return async (blob: string): Promise<ReceiptWireV0 | null> => {
    try {
      const locked = await readPrivateKey({ armoredKey: recipientPrivateKeyArmored });
      const decryptionKeys = await decryptKey({ privateKey: locked, passphrase });
      const message = await readMessage({ armoredMessage: blob });
      const { data } = await decrypt({ message, decryptionKeys });
      const text = typeof data === 'string' ? data : await streamToText(data);
      return tryParseReceiptWire(JSON.parse(text)); // null for any non-receipt shape → caller falls through
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
