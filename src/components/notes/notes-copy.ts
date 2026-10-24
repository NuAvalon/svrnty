// Fixed copy for the over-wire Notes inbox (CURSOR_QUEUE SEND/INBOX).
// Status floor is "Sent · unconfirmed." — never Delivered / Read / Expired.
// Beta unlock/redeem chrome is the NEXT queue item (gate-ON only) — not this surface.

export const NOTES_COPY = {
  tabLabel: 'Notes',
  heading: 'Encrypted messages, with the people you trust',
  whatItIs:
    'Send and receive end-to-end encrypted messages with your contacts. Every message is sealed on your device — the relay only ever moves sealed blobs, so it can’t read your messages.',
  sending:
    'When you send, you’ll see Sent — your message left your device sealed and reached the relay. (A Delivered confirmation is coming.)',
  sendingWait:
    'If they have not joined yet, your message waits for them. The moment they join and unlock their book, it delivers. A message to someone who never joins will eventually expire.',
  receiving:
    'You receive messages from your contacts. A message arrives sealed and is saved to this device — if it doesn’t appear in your inbox live yet, it’s there when you open your messages.',
  sentUnconfirmed: 'Sent · unconfirmed.',
  notSent: 'Not sent. Saved on this device.',
  sendAction: 'Send',
  sendingAction: 'Sending…',
  composeLabel: 'Note',
  composePlaceholder: 'Write a note…',
  pickerLabel: 'To',
  pickerPlaceholder: 'Choose a contact',
  inboxLabel: 'Inbox',
  threadEmpty: 'No notes in this thread yet.',
  inboxEmpty: 'No notes yet. Pick a contact to write one.',
  noSendableContacts:
    'No contacts to write to. Import a signed svrnty card first. Keyless contacts cannot receive a sealed note.',
  noContactSelected: 'Pick a contact first.',
  emptyBody: 'Write a note first.',
  identityLocked: 'Unlock your identity first.',
  identityKeysMissing: 'This identity is missing the keys a note needs.',
  needCanonical:
    'Notes over the wire need a current svrnty identity. This book cannot send yet.',
  sendFailed: 'The note could not be sent.',
  // S14: the recipient has no verified PQ KEM key; sends are skipped, never downgraded. Claim-safe wording (no 'quantum-safe').
  notSentNeedsUpgrade:
    'Not sent. Saved on this device. {name} needs to share an updated contact card (security upgrade). Ask them to re-share, then re-add.',
  contactNotSendable: 'This contact cannot receive a sealed note.',
} as const;

/** The status line for a note that was NOT deposited: a recipient with no verified PQ KEM key was skipped (S14), which is
 *  not a network failure and must not read like one. */
export function notSentMessage(contact: { name: string; pqKemPublicKey?: string }): string {
  return contact.pqKemPublicKey
    ? NOTES_COPY.notSent
    : NOTES_COPY.notSentNeedsUpgrade.replace('{name}', contact.name);
}

export const NOTES_BOUNDS = {
  name: 80,
  body: 32_000,
  fingerprintDisplay: 64,
} as const;
