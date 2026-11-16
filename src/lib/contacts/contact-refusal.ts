// src/lib/contacts/contact-refusal.ts
// A REFUSAL is not a failure: the store declined on purpose, before writing, and the reason is the message. A screen that turns it into "didn't finish" says
// something false and, for a fingerprint that does not match its key, hides a warning. So every catch that replaces an error's text maps these first, BY CODE
// and REASON (never by message), and only what is left gets the site's fixed sentence. The sentences are the copy owner's words (ledger row 233) and constants.
// Recognised by code, not instanceof, like isRestoreDurableRefusal: a leaf with no imports, so a public page can use it without loading the store.
// Run: npx tsx --test src/lib/contacts/contact-refusal.test.ts

/** Where the catch sits: a pasted/scanned card, a contact typed by hand, or anywhere else a contact is written. */
export type ContactRefusalContext = 'import' | 'add' | 'other';

export const CONTACT_REFUSAL_MESSAGES = Object.freeze({
  /** R1: a card whose fingerprint does not match its key. The same sentence the paste import already showed when it checks the card itself. */
  importBinding: 'This card could not be verified — its fingerprint does not match its key, so it was not imported. Ask them to send a fresh one.',
  /** R2: a contact typed or pasted by hand. */
  addBinding: "This contact wasn't added: its fingerprint doesn't match its public key. Check both and try again.",
  /** R3: a change to a stored contact. */
  updateBinding: "Nothing was saved: this contact's fingerprint doesn't match its public key.",
  /** R4: trusted without a verification, on a new row or a promotion. */
  verifyBeforeTrust: 'Verify this person in person or another way before you trust them. Nothing was changed.',
  /** R5: the existing TrustRefusedError sentence, from a constant. */
  blocked: 'This contact is blocked. Unblock them before trusting them.',
  /** R6: a change of fingerprint on a contact that already has one. */
  identityImmutable: "Nothing was saved: a contact's fingerprint can't be changed. If they have a new key, add them as a new contact.",
});

const codeOf = (e: unknown): unknown => (typeof e === 'object' && e !== null ? (e as { code?: unknown }).code : undefined);
const reasonOf = (e: unknown): unknown => (typeof e === 'object' && e !== null ? (e as { reason?: unknown }).reason : undefined);

/** The refusal's own sentence, or null when the error is not a contact refusal (the caller then uses its site's fixed sentence). */
export function contactRefusalMessage(err: unknown, ctx: ContactRefusalContext = 'other'): string | null {
  const code = codeOf(err);
  const reason = reasonOf(err);
  if (code === 'contact-refused') {
    if (reason === 'binding') return ctx === 'import' ? CONTACT_REFUSAL_MESSAGES.importBinding : ctx === 'add' ? CONTACT_REFUSAL_MESSAGES.addBinding : CONTACT_REFUSAL_MESSAGES.updateBinding;
    if (reason === 'verify-before-trust') return CONTACT_REFUSAL_MESSAGES.verifyBeforeTrust;
    return null;
  }
  if (code === 'contact-update-refused') {
    if (reason === 'binding') return CONTACT_REFUSAL_MESSAGES.updateBinding;
    if (reason === 'verify-before-trust') return CONTACT_REFUSAL_MESSAGES.verifyBeforeTrust;
    if (reason === 'identity-immutable') return CONTACT_REFUSAL_MESSAGES.identityImmutable;
    return null;
  }
  if (code === 'trust-refused' && reason === 'blocked') return CONTACT_REFUSAL_MESSAGES.blocked;
  return null;
}
