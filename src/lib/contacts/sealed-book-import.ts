// src/lib/contacts/sealed-book-import.ts
// Opening a password-sealed contacts export (what "Export Contacts" writes) for the contact book's import. This module only OPENS the file and says what went
// wrong; what is imported is decided by book-import.ts, unchanged: every contact lands 'unverified', whatever the file says.
//
//   - The sealed text is capped before anything is parsed, and the DECRYPTED text is capped again before it is handed on (a small envelope can hold a big body).
//   - A wrong password and a file this app cannot read are two different outcomes: only the envelope's own wrong-password code says "wrong password". A malformed
//     envelope, a method it will not run, text that is not a contacts export: all of them are "can't read this file", never "wrong password".
//   - Every sentence is a constant. Nothing from the file is ever rendered as text, including the owner it names.
// Run: npx tsx --test src/lib/contacts/sealed-book-import.test.ts
import { openWithPassword } from '@/lib/crypto/password-envelope';
import { RESTORE_MESSAGES } from '@/lib/identity/restore-errors';
import { MAX_FILE_CHARS } from './book-import';

export const SEALED_BOOK_MESSAGES = Object.freeze({
  passwordLabel: 'Password for this file',
  passwordHelper: 'This file is sealed. Enter the password you chose when you exported these contacts.',
  alwaysUnverified: 'Imported contacts start as unverified until you verify each one.',
  malformed: "This app can't read this file as a contacts export.",
  tooLarge: 'This file is too large to import. Nothing was added.',
  differentOwner: 'These contacts were exported by a different identity.',
  /** Contacts the file carries without their keys: they cannot be added. n is a count, never a value from the file. */
  missingKeys: (n: number): string => (n === 1
    ? "1 contact was exported without its keys, so it can't be added. Ask them to share their contact again."
    : `${n} contacts were exported without their keys, so they can't be added. Ask each person to share their contact again.`),
});

export type SealedBookFailure = 'wrong-password' | 'malformed' | 'too-large';

/** Why a sealed contacts file did not open. The screen maps `code` to a sentence; the error's own text is never shown. */
export class SealedBookRefused extends Error {
  readonly code: SealedBookFailure;
  constructor(code: SealedBookFailure) { super(`sealed contacts file refused: ${code}`); this.name = 'SealedBookRefused'; this.code = code; }
}

const HEAD_CHARS = 8192;

/**
 * Is this pasted text a sealed envelope? A cheap look at the head first (a sealed file is small JSON that names `encrypted`, `salt` and `iv` before its long
 * `data`), so ordinary pastes are never parsed twice; then the shape. Text over the cap is not sealed here: the plain path refuses it before any parse.
 */
export function looksSealed(text: string): boolean {
  if (text.length > MAX_FILE_CHARS) return false;
  const head = text.slice(0, HEAD_CHARS);
  if (!head.trimStart().startsWith('{') || !head.includes('"encrypted"') || !head.includes('"salt"')) return false;
  try {
    const o = JSON.parse(text) as { encrypted?: unknown; salt?: unknown; iv?: unknown; data?: unknown } | null;
    return !!o && typeof o === 'object' && o.encrypted === true && typeof o.salt === 'string' && typeof o.iv === 'string' && typeof o.data === 'string';
  } catch {
    return false;
  }
}

/**
 * Open a sealed contacts file with its password and return the plaintext, for the same parser a plain paste goes to. `maxChars` is the cap on both the sealed
 * text and the plaintext (the default is the importer's own cap; a test passes a small one). `open` is the envelope opener (a test passes a fake).
 */
export async function openSealedBook(
  text: string,
  password: string,
  maxChars: number = MAX_FILE_CHARS,
  open: typeof openWithPassword = openWithPassword,
): Promise<string> {
  // Before anything is decrypted. A body cannot be larger than its envelope (AES-GCM does not compress), so this already bounds the plaintext; the check
  // after the decrypt is the second, independent bound (the opener is a parameter so a test can hand back an oversize body).
  if (text.length > maxChars) throw new SealedBookRefused('too-large');
  let envelope: unknown;
  try { envelope = JSON.parse(text); } catch { throw new SealedBookRefused('malformed'); }
  let plain: Uint8Array;
  try {
    plain = (await open(envelope, password)).plaintext;
  } catch (e) {
    // By the envelope's own code, never by its text: only a failed password check is a wrong password.
    if ((e as { code?: unknown } | null)?.code === 'wrong-password') throw new SealedBookRefused('wrong-password');
    throw new SealedBookRefused('malformed');
  }
  if (plain.length > maxChars * 4) throw new SealedBookRefused('too-large'); // UTF-8 is at most 4 bytes a character: over this, the text cannot be under the cap
  const plaintext = new TextDecoder().decode(plain);
  if (plaintext.length > maxChars) throw new SealedBookRefused('too-large');
  return plaintext;
}

/** Does the owner the file names differ from this identity? Compared as 64-hex fingerprints, case-insensitively. A file naming no owner is not different. */
export function namesDifferentOwner(fileOwner: string | null, myFingerprint: string): boolean {
  if (fileOwner === null) return false;
  return fileOwner.trim().toLowerCase() !== myFingerprint.trim().toLowerCase();
}

/**
 * The contacts a file carries WITHOUT their keys. importContactBook reports a row with no fingerprint and key by that one reason; those are counted here and
 * the screen shows one constant sentence for them, not a name per row. Returns the count and the failures that are something else.
 */
export function splitMissingKeys<F extends { reason: string }>(failed: F[]): { missingKeys: number; other: F[] } {
  const other = failed.filter((f) => f.reason !== 'it has no fingerprint and key');
  return { missingKeys: failed.length - other.length, other };
}

/** The sentence for a failed open: by the refusal's code, never by any error's text. Anything unexpected is "can't read this file", never "wrong password". */
export function sealedFailureMessage(err: unknown): string {
  const code = err instanceof SealedBookRefused ? err.code : null;
  if (code === 'wrong-password') return RESTORE_MESSAGES.wrongPassword;
  if (code === 'too-large') return SEALED_BOOK_MESSAGES.tooLarge;
  return SEALED_BOOK_MESSAGES.malformed;
}

const CANONICAL_FP = /^[0-9a-f]{64}$/;

/**
 * A contact with a canonical fingerprint (64 lowercase hex) is bound to its Ed25519 key AND both post-quantum public keys, so a row that carries none of the
 * post-quantum keys can never pass the store's binding check. An export made before the post-quantum keys were written is full of them. They are counted here,
 * with the keyless rows, and not tried: the screen then says they were exported without their keys instead of "its key does not match its fingerprint".
 */
export function splitUnbindable(entries: unknown[]): { attempt: unknown[]; unbindable: number } {
  const attempt: unknown[] = [];
  let unbindable = 0;
  for (const entry of entries) {
    const c = (entry && typeof entry === 'object' ? entry : {}) as Record<string, unknown>;
    const fp = typeof c.fingerprint === 'string' ? c.fingerprint : '';
    const hasPq = (typeof c.pq_kem_public_key === 'string' && c.pq_kem_public_key !== '') || (typeof c.pq_sig_public_key === 'string' && c.pq_sig_public_key !== '');
    if (CANONICAL_FP.test(fp) && !hasPq) unbindable++;
    else attempt.push(entry);
  }
  return { attempt, unbindable };
}
