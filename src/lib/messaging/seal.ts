// src/lib/messaging/seal.ts
// Seal for notes v0 (Phase 3 rung 1). Patterned on sync/contact-update-envelope.ts.
// CONFIDENTIALITY SWAP (HNDL): when the recipient's ML-KEM-1024 pubkey is supplied, the note's ALREADY-
// SIGNED wire is sealed with the EXISTING hybrid mailbox envelope (living-book-sleeve) — post-quantum on
// the wire. Without it, the classical OpenPGP path is kept for back-compat/tests; SEND SITES fail-closed-
// SKIP a recipient with no pq_kem (see transport.sendNoteToPeer) so production NEVER downgrades silently.
// NOT a Double Ratchet. No signature is added here — authenticity is signNoteWire, re-checked on consume.

import { createMessage, encrypt, readKey, readPrivateKey, decryptKey, readMessage, decrypt } from 'openpgp';
import { NOTE_WIRE_TYPE } from './domains';
import type { NoteWireV0 } from './types';
import {
  sealLivingBookHybrid,
  openLivingBookHybrid,
  type LivingBookHybridSecrets,
} from '@/lib/crypto/living-book-sleeve';

export async function sealNoteTo(
  note: NoteWireV0,
  recipientPublicKeyArmored: string,
  recipientPqKemB64?: string,
): Promise<string> {
  if (note.type !== NOTE_WIRE_TYPE) {
    throw new Error('sealNoteTo: refusing non-note wire type');
  }
  // HYBRID (HNDL) when the recipient's ML-KEM pubkey is present — wrap the signed wire bytes, the exact
  // spot the classical encrypt() was. Reject-classical by construction (living-book-sleeve → mailbox-env).
  if (recipientPqKemB64) {
    return sealLivingBookHybrid(new TextEncoder().encode(JSON.stringify(note)), recipientPublicKeyArmored, recipientPqKemB64);
  }
  // Classical fallback (back-compat/tests). Send sites fail-closed-skip when no pq_kem — never reach here.
  const encryptionKeys = await readKey({ armoredKey: recipientPublicKeyArmored });
  const message = await createMessage({ text: JSON.stringify(note) });
  return (await encrypt({ message, encryptionKeys })) as string;
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
 * Decrypt opaque blob → NoteWireV0, or null on any failure (I-1 silent drop). DUAL-READ: when `hybrid`
 * (my mailbox secrets + fp) is supplied, try the PQ-hybrid envelope FIRST; a classical/armored blob is not
 * a hybrid package (openLivingBookHybrid → null) and falls through to the OpenPGP path. A hybrid package of
 * a DIFFERENT inner type fails the NOTE_WIRE_TYPE gate → null (preserves the consume 4-way no-cross-swallow).
 * The type-gate is the exported {@link parseNoteWire}, which the single dual-read chokepoint reuses.
 */
export function noteOpenpgpDecryptor(
  recipientPrivateKeyArmored: string,
  passphrase: string,
  hybrid?: LivingBookHybridSecrets,
): (blob: string) => Promise<NoteWireV0 | null> {
  return async (blob: string): Promise<NoteWireV0 | null> => {
    if (hybrid) {
      try {
        const pt = await openLivingBookHybrid(blob, hybrid.secrets, hybrid.myFp);
        if (pt) {
          const parsed = JSON.parse(new TextDecoder().decode(pt)) as NoteWireV0;
          if (parsed?.type !== NOTE_WIRE_TYPE) return null; // hybrid pkg, not a note → no cross-swallow
          if (typeof parsed.body !== 'string' || typeof parsed.from_fingerprint !== 'string') return null;
          return parsed;
        }
        // pt null → not a hybrid package → fall through to the classical OpenPGP path below.
      } catch {
        return null; // malformed hybrid package → drop (never throw on hostile input)
      }
    }
    try {
      const locked = await readPrivateKey({ armoredKey: recipientPrivateKeyArmored });
      const decryptionKeys = await decryptKey({ privateKey: locked, passphrase });
      const message = await readMessage({ armoredMessage: blob });
      const { data } = await decrypt({ message, decryptionKeys });
      const text = typeof data === 'string' ? data : await streamToText(data);
      return parseNoteWire(text);
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
