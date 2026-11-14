// src/lib/identity/authority-pin-copy.ts
// The one sentence shown when a valid card for a contact we already hold carries a DIFFERENT authority pin. First write wins, so the card is not
// applied and re-sharing it cannot change that: the advice is to check another way, not to re-share. Words by the copy review; both import paths use this.
export function authorityPinConflictMessage(name: string): string {
  return `A card for "${name}" doesn't match the one you already have, so it wasn't applied. Your existing contact is unchanged. Someone else may have access to their identity. Check with them another way before acting on this card.`;
}
