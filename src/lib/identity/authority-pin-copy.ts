// src/lib/identity/authority-pin-copy.ts
// The security-warning sentences for a card that doesn't check out. RULE: a card-supplied string never appears in a security warning.
// Where a name appears it is the person's OWN BOOK name (the contact they already hold), made frame-safe by warningName(): control
// characters and bidi controls removed, quotes and newlines kept out of the sentence's frame, clamped, and bidi-isolated (FSI ... PDI)
// because these sentences render as plain text. Where no book entry exists (the Gate, a first-contact add) the sentence has NO name,
// and its function takes NO parameter, so passing the card's name is a type error, not just a failing test. Words by the copy review.

/** Longest book name a warning will show, in code points (the Gate's arrival-name clamp is the same 80). */
export const WARNING_NAME_MAX = 80;

const FSI = '⁨';
const PDI = '⁩';
// Bidi embedding/override/isolate controls and the directional marks: removed, then the whole name is isolated once.
const BIDI_CONTROLS = /[؜‎‏‪-‮⁦-⁩]/gu;

/** The book's name, safe to place inside a quoted security sentence. Not for card-supplied text: that never goes in a warning. */
export function warningName(raw: unknown): string {
  if (typeof raw !== 'string') return FSI + PDI;
  const cleaned = raw
    .replace(/\p{Cc}/gu, ' ') // C0 + C1 controls, newlines included: nothing can break the sentence onto its own line
    .replace(BIDI_CONTROLS, '')
    .replace(/["“”]/gu, "'") // a quote in the name can't close the sentence's own quotes
    .replace(/\s+/gu, ' ')
    .trim();
  return FSI + Array.from(cleaned).slice(0, WARNING_NAME_MAX).join('') + PDI;
}

/** A valid card for a contact already in your book carries a DIFFERENT authority pin. First write wins, so it isn't applied. */
export function authorityPinConflictMessage(bookName: string): string {
  return `A card for "${warningName(bookName)}" doesn't match the one you already have, so it wasn't applied. Your existing contact is unchanged. Someone else may have access to their identity. Check with them another way before acting on this card.`;
}

/** The same conflict for someone waiting at your Gate. Every Gate name came from a card, so there is no trusted name to show. */
export function gateAuthorityPinConflictMessage(): string {
  return `This card doesn't match the one already waiting at your Gate for the same person, so it wasn't applied. Nothing at your Gate has changed. Someone else may have access to their identity. Check with the person who sent you this link another way before letting them in.`;
}

/** A card for a contact already in your book has a present-but-invalid signature. */
export function unverifiedCardMessage(bookName: string): string {
  return `A card for "${warningName(bookName)}" could not be verified — possible tampering. Your existing contact is unchanged; ask them to re-share over a secure link.`;
}

/** A first-contact add whose card has a present-but-invalid signature. The contact is created FROM this card, so no trusted name exists. */
export function addedUnverifiedContactMessage(): string {
  return `Added a new contact (classical only). Their key material couldn't be verified, so this card may have been tampered with. Ask the person who sent it to share it again over a secure link.`;
}
