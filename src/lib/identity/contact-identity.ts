// src/lib/identity/contact-identity.ts
// #724: a contact row's fingerprint is its identity, so an update may never REPLACE it. Trust, open visibility and every
// grant hang off the row, so a fingerprint swapped onto a trusted row would hand that trust (and what it lets the peer see)
// to a different key. Linking a key-less contact (no fingerprint yet) to its first SVRNTY identity is allowed: that is
// "Link to SVRNTY" (ContactManagement, offered only when the contact is not linked, and it resets trust to unverified).
// A real key change is a new contact, or a verified rotation through its own path (none exists yet, #723).
// Pure, so the rule is testable without IndexedDB; client-store.updateContact calls it before writing.

/**
 * updateContact REFUSED this change on purpose, before writing anything. Typed, with a reason, so a screen can tell a refusal from a write that FAILED and say
 * why. It is not ContactRefused: client-store's restore loop skips and counts a ContactRefused from addContact, and an update refusal must still stop it.
 */
export type ContactUpdateRefusalReason = 'binding' | 'verify-before-trust' | 'identity-immutable';
export class ContactUpdateRefused extends Error {
  readonly code = 'contact-update-refused' as const;
  constructor(public readonly reason: ContactUpdateRefusalReason, message: string) { super(message); this.name = 'ContactUpdateRefused'; }
}

export function assertFingerprintUnchanged(existingFingerprint: unknown, nextFingerprint: unknown): void {
  const before = typeof existingFingerprint === 'string' ? existingFingerprint.trim().toLowerCase() : '';
  if (!before) return; // key-less row: linking it to a first identity is allowed
  const after = typeof nextFingerprint === 'string' ? nextFingerprint.trim().toLowerCase() : '';
  if (after !== before) {
    throw new ContactUpdateRefused('identity-immutable', "contact identity is immutable: refusing to change this contact's fingerprint (a new key is a new contact)");
  }
}
