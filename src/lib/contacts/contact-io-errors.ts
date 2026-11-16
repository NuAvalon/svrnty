// src/lib/contacts/contact-io-errors.ts
// What the contacts import/export screens say when something fails. The rule (copy ledger, code-only): a screen sentence is chosen by a CODE, and an error's
// own text is never shown. Every sentence below is a constant (copy owner's wording, ledger row 210); an unknown error gets one generic sentence and is logged by
// its name and code only (a SyntaxError from JSON.parse can quote a slice of the pasted contacts, so its message is never logged either).
//   - The password-required decision for the import dialog comes from the typed code, BEFORE any display text; it is never a string match on a message.
//   - Nothing from a file or an error (message, name, code) is ever rendered.
// Run: npx tsx --test src/lib/contacts/contact-io-errors.test.ts
import { EnvelopeRefused, EnvelopeWrongPassword, MIN_EXPORT_PASSWORD_LENGTH } from '@/lib/crypto/password-envelope';
import { RESTORE_MESSAGES } from '@/lib/identity/restore-errors';
import { ContactBookTooLarge } from './book-import';
import { SEALED_BOOK_MESSAGES } from './sealed-book-import';
import { errorTag } from '@/lib/error-tag';

export type ContactIoFailure = 'export-password-short' | 'private-key-missing' | 'import-password-required';

/** A refusal the dialogs raise themselves. The screen maps `code` to a sentence; `message` is for the log only and says nothing about the file. */
export class ContactIoRefused extends Error {
  readonly code: ContactIoFailure;
  constructor(code: ContactIoFailure) { super(`contacts screen refused: ${code}`); this.name = 'ContactIoRefused'; this.code = code; }
}

export const CONTACT_IO_MESSAGES = Object.freeze({
  /** An import that stopped for a reason we do not name; rows before it may already be in the book. */
  importUnknown: 'The import stopped; some contacts may have been added. Check your contacts before you try again.',
  exportUnknown: "The export didn't finish. Try again.",
  keyExportUnknown: "The key export didn't finish. Try again.",
  privateKeyMissing: "This device doesn't have your private key, so there's nothing to export.",
  /** Unchanged wording: a pasted text that is not JSON. */
  invalidJson: 'Invalid JSON format',
  /** The number is the check's own constant, never a written-out digit. Byte-identical to the sentence the export dialog threw before. */
  exportPasswordShort: (min: number): string => `Enter a password of at least ${min} characters to export your contacts.`,
});

// errorTag lives in a leaf module (no imports), so a screen that only needs the log tag does not pull the password-envelope and book-import code into its bundle.
export { errorTag };

/** The export dialog's catch: the typed short-password refusal, else the generic sentence. */
export function exportFailureMessage(err: unknown): string {
  if (err instanceof ContactIoRefused && err.code === 'export-password-short') return CONTACT_IO_MESSAGES.exportPasswordShort(MIN_EXPORT_PASSWORD_LENGTH);
  return CONTACT_IO_MESSAGES.exportUnknown;
}

/** The private-key export dialog's catch. */
export function keyExportFailureMessage(err: unknown): string {
  if (err instanceof ContactIoRefused && err.code === 'private-key-missing') return CONTACT_IO_MESSAGES.privateKeyMissing;
  return CONTACT_IO_MESSAGES.keyExportUnknown;
}

export interface ImportFailureView { message: string; needsPassword: boolean }

/** The import dialog's catch: the sentence AND whether to ask for the password, both from the error's type/code, in that order. */
export function importFailureView(err: unknown): ImportFailureView {
  if (err instanceof ContactIoRefused && err.code === 'import-password-required') return { message: SEALED_BOOK_MESSAGES.passwordHelper, needsPassword: true };
  if (err instanceof EnvelopeWrongPassword) return { message: RESTORE_MESSAGES.wrongPassword, needsPassword: true };
  if (err instanceof EnvelopeRefused || err instanceof SyntaxError) return { message: SEALED_BOOK_MESSAGES.malformed, needsPassword: false };
  return { message: CONTACT_IO_MESSAGES.importUnknown, needsPassword: false };
}

/** The contact book's plain-paste import catch. */
export function plainPasteFailureMessage(err: unknown): string {
  if (err instanceof ContactBookTooLarge) return SEALED_BOOK_MESSAGES.tooLarge;
  if (err instanceof SyntaxError) return CONTACT_IO_MESSAGES.invalidJson;
  return CONTACT_IO_MESSAGES.importUnknown;
}
