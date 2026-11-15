// src/lib/identity/beacon-key-copy.ts
// The one sentence shown when a valid card for a contact we already hold carries a DIFFERENT beacon key at the same generation. The whole card is refused:
// nothing from it is applied. ${name} is the EXISTING contact's name from the person's own book, never the card's. No key, fingerprint or generation is
// shown, and the sentence does not use the words beacon, generation or rotation. Words by the copy review.
export function beaconKeyConflictMessage(name: string): string {
  return `A card for "${name}" doesn't match a key you already have for them, so it wasn't applied. Your existing contact is unchanged. Their identity may be in use somewhere else. Check with them another way before relying on this card.`;
}
