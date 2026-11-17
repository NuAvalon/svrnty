// src/lib/crypto/contact-keys-mismatch.ts
// The refusal raised when a contact's keys do not match the fingerprint it claims (the anti-poison check before encrypting to a contact), as a coded error.
// The encrypt screen used to tell this refusal apart by testing the error's TEXT with a regular expression; rewording that one message would have turned the
// poisoned sentence into the generic failure without a single test noticing. So the refusal is CODED, and the screen asks
// by code, never by text (like the contact refusals and the blocked-upgrade stop).
//   - A leaf on purpose (no imports): the screen can ask without loading the crypto.
//   - The error's own message is unchanged, so a log or a test that reads it sees the same words as before.
// Run: npx tsx --test src/lib/crypto/contact-keys-mismatch.test.ts
export const CONTACT_KEYS_MISMATCH_CODE = 'contact-keys-mismatch';

export class ContactKeysMismatch extends Error {
  readonly code = CONTACT_KEYS_MISMATCH_CODE;
  constructor() {
    super('encryptToContact: contact keys do not match its claimed fingerprint — refusing to encrypt (anti-poison)');
    this.name = 'ContactKeysMismatch';
  }
}

/** Recognised by CODE, never by text: a plain Error with look-alike words is not this refusal. */
export function isContactKeysMismatch(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { code?: unknown }).code === CONTACT_KEYS_MISMATCH_CODE;
}
