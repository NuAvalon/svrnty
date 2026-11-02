// src/lib/messaging/receipt-wire-v1.ts
// S62 A5-d (contract v6): the designated-verifier MAC receipt, as it travels. {type, note_id, code, tag} and NOTHING else:
// no from_fingerprint, no signature, no key. The tag is HMAC under a key only the note's sender holds (receipt-mac.ts), so the
// receipt proves nothing to a third party and cannot be forged by the relay. Pure: no I/O.

import { bytesToHex } from '@noble/hashes/utils.js';
import { RECEIPT_CODES, receiptKeyFromHex, receiptTag, type ReceiptCode } from '@/lib/crypto/receipt-mac';

export const RECEIPT_V1_WIRE_TYPE = 'svrnty-receipt-v1' as const;

export interface ReceiptWireV1 {
  type: typeof RECEIPT_V1_WIRE_TYPE;
  note_id: string;
  code: ReceiptCode;
  tag: string; // 64 lowercase hex
}

const TAG_HEX = /^[0-9a-f]{64}$/;
const KEYS = ['code', 'note_id', 'tag', 'type'];
const MAX_NOTE_ID = 200;

/**
 * Build the wire from the note's per-note receipt key (64 hex, as carried inside the signed note). Null when the key is absent or malformed or the
 * note id is unusable: the caller then emits NOTHING (an old or hostile note that carries no usable key gets no receipt).
 */
export function buildReceiptWireV1(receiptKeyHex: unknown, noteId: unknown, code: ReceiptCode): ReceiptWireV1 | null {
  const rk = receiptKeyFromHex(receiptKeyHex);
  if (!rk || typeof noteId !== 'string' || noteId.length === 0 || noteId.length > MAX_NOTE_ID) return null;
  return { type: RECEIPT_V1_WIRE_TYPE, note_id: noteId, code, tag: bytesToHex(receiptTag(rk, noteId, code)) };
}

/** The inner-wire type gate: exactly this shape or null (never throws). Extra keys are refused, so a v0 identity-signed receipt can never parse as v1. */
export function parseReceiptWireV1(innerUtf8: string): ReceiptWireV1 | null {
  try {
    const o = JSON.parse(innerUtf8) as Record<string, unknown>;
    if (!o || typeof o !== 'object' || Array.isArray(o)) return null;
    if (Object.keys(o).sort().join(',') !== KEYS.join(',')) return null;
    if (o.type !== RECEIPT_V1_WIRE_TYPE) return null;
    if (typeof o.note_id !== 'string' || o.note_id.length === 0 || o.note_id.length > MAX_NOTE_ID) return null;
    if (!(RECEIPT_CODES as readonly unknown[]).includes(o.code)) return null;
    if (typeof o.tag !== 'string' || !TAG_HEX.test(o.tag)) return null;
    return { type: RECEIPT_V1_WIRE_TYPE, note_id: o.note_id, code: o.code as ReceiptCode, tag: o.tag };
  } catch {
    return null;
  }
}
