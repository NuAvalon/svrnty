// src/lib/crypto/receipt-mac.ts
// S62 (#714) A5-d: the DELIVERY-RECEIPT authenticator (Flint's ruling 36b079e8, contract v6 8311a285). PURE: no I/O, no key material but the
// per-note receipt_key passed in.
//
// A designated-verifier MAC, NOT a signature. The sender puts a fresh 32-byte `receipt_key` (rk) inside the sealed, signed note; the recipient,
// after the durable store write, returns {note_id, code, tag}. Only the sender (who holds rk) can check it, and the sender could have made any tag,
// so a receipt proves nothing to a third party (deniable), while the relay, which never sees rk, cannot forge one. There is NO identity key and
// NO signature anywhere in this module (pinned by a static test): that is the whole point of A5-d.
//
//   K   = HKDF-SHA256(ikm = rk, salt = utf8("svrnty:receipt:v2"), info = utf8(note_id), L = 32)
//   tag = HMAC-SHA256(K, LP("svrnty:receipt:v2") || LP(note_id) || LP(code))        LP(x) = u32be(len(utf8(x))) || utf8(x)
//   code in { "delivered", "couldnt_verify", "read" }
//
// Binding: the key is per note (no cross-note replay) and the code is inside the MAC (no delivered->read upgrade, no couldnt_verify->delivered).
// Fail-safe: every verify error is `false`, never a throw, so the caller's state stays "Sent".

import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

export const RECEIPT_MAC_DOMAIN = 'svrnty:receipt:v2';
export const RECEIPT_KEY_BYTES = 32;
export const RECEIPT_TAG_BYTES = 32;
export const RECEIPT_CODES = ['delivered', 'couldnt_verify', 'read'] as const;
export type ReceiptCode = (typeof RECEIPT_CODES)[number];

const enc = new TextEncoder();
const HEX64 = /^[0-9a-fA-F]{64}$/;

function isCode(c: unknown): c is ReceiptCode {
  return typeof c === 'string' && (RECEIPT_CODES as readonly string[]).includes(c);
}

/** u32be(len) || bytes. */
function lp(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** Fresh per-note key from the platform CSPRNG. Never reused. */
export function newReceiptKey(): Uint8Array {
  const k = new Uint8Array(RECEIPT_KEY_BYTES);
  crypto.getRandomValues(k);
  return k;
}

export function receiptKeyToHex(rk: Uint8Array): string {
  if (!(rk instanceof Uint8Array) || rk.length !== RECEIPT_KEY_BYTES) throw new Error('receipt key must be 32 bytes');
  return Array.from(rk, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Strict: exactly 64 hex characters, else null. */
export function receiptKeyFromHex(hex: unknown): Uint8Array | null {
  if (typeof hex !== 'string' || !HEX64.test(hex)) return null;
  const out = new Uint8Array(RECEIPT_KEY_BYTES);
  for (let i = 0; i < RECEIPT_KEY_BYTES; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The 32-byte tag for (rk, note_id, code). THROWS on malformed input (a programming error on the emit side). */
export function receiptTag(rk: Uint8Array, noteId: string, code: ReceiptCode): Uint8Array {
  if (!(rk instanceof Uint8Array) || rk.length !== RECEIPT_KEY_BYTES) throw new Error('receipt key must be 32 bytes');
  if (typeof noteId !== 'string' || noteId.length === 0) throw new Error('note_id must be a non-empty string');
  if (!isCode(code)) throw new Error('unknown receipt code');
  const id = enc.encode(noteId);
  const domain = enc.encode(RECEIPT_MAC_DOMAIN);
  const k = hkdf(sha256, rk, domain, id, 32);
  return hmac(sha256, k, concat(lp(domain), lp(id), lp(enc.encode(code))));
}

/** Constant-time over equal-length inputs; a length mismatch is rejected up front (lengths are public). */
function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Check a received tag. The ONLY secret input is `rk`: there is deliberately no public key, signature or identity parameter, so a verifier
 * without rk cannot check a receipt (third-party non-transferability). Any error (bad key, unknown code, malformed tag) is `false`.
 */
export function verifyReceiptTag(rk: Uint8Array, noteId: string, code: unknown, tag: Uint8Array | string): boolean {
  try {
    if (!isCode(code)) return false;
    const got = typeof tag === 'string' ? receiptKeyFromHex(tag) : tag; // a 64-hex tag parses the same way as a 32-byte key
    if (!(got instanceof Uint8Array) || got.length !== RECEIPT_TAG_BYTES) return false;
    return ctEqual(receiptTag(rk, noteId, code), got);
  } catch {
    return false;
  }
}
