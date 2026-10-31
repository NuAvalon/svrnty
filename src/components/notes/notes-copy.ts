// Fixed copy for the Chat surface (over-wire SEND / INBOX).
// The Chat tab is the window — no essay masthead. Status floor is
// "Sent · unconfirmed." — never Delivered / Read / Expired.
// Essay claims ("encrypted messages…", "How notes travel") stay off this glass.
// "Delivered" renders ONLY on a cryptographically VERIFIED delivery receipt (the S62 MAC receipt, live-book-poll.buildReceiptSeam);
// the floor stays "Sent · unconfirmed." for every unverified path (notes-status.ts statusIsHonest).

export const NOTES_COPY = {
  tabLabel: 'Chat',
  heading: 'Chat',
  sentUnconfirmed: 'Sent · unconfirmed.',
  notSent: 'Not sent. Saved on this device.',
  // Rendered ONLY for a verified-receipt 'delivered' status (recipient DEVICE received+decrypted the
  // note — not relay-only, not "Read"). Plain "Delivered" per Hypatia #172212 (honest-by-construction
  // via statusIsHonest; no qualifier).
  delivered: 'Delivered',
  // Light secondary line under "Sent · unconfirmed." (NOT bare) — reads as in-progress, not failed:
  // the delivery-receipt flow (S62) is live and will resolve to "Delivered". Hypatia #172212 floor hint.
  awaitingDelivery: 'Awaiting delivery confirmation',
  sendAction: 'Send',
  sendingAction: 'Sending…',
  composeLabel: 'Message',
  composePlaceholder: 'Write a message…',
  pickerLabel: 'To',
  pickerPlaceholder: 'Choose a contact',
  inboxLabel: 'Inbox',
  threadEmpty: 'No messages yet.',
  inboxEmpty: 'No conversations yet. Pick a contact to write one.',
  noSendableContacts:
    'No contacts to write to. Import a signed svrnty card first. Keyless contacts cannot receive a sealed message.',
  noContactSelected: 'Pick a contact first.',
  emptyBody: 'Write a message first.',
  identityLocked: 'Unlock your identity first.',
  identityKeysMissing: 'This identity is missing the keys a message needs.',
  needCanonical:
    'Chat over the wire needs a current svrnty identity. This book cannot send yet.',
  // Send outcomes (Hypatia #837, Flint #823 T1), keyed by WHERE the send failed. None may say delivered/received. There is deliberately NO
  // "Retrying won't send a second copy" line and NO Retry button: the relay ignores a client envelope id today (route.ts), so a resend CAN duplicate.
  sendFailed: 'Not sent. Nothing left this device. Your message is still in the box.',
  sendRefused: 'Not sent. The relay turned it down. Your message is still in the box.',
  sentNotSaved: "Sent to the relay, but this device couldn't save a copy. Don't send it again. Your text is below so you can copy it.",
  sendUnconfirmed: "Couldn't confirm it was sent. The relay may already have it.",
  unsavedTextLabel: 'Your message',
  dismiss: 'Dismiss',
  // #731: opens the contact's conversation from a "couldn't be opened" line, so the user can ask for a resend. PLACEHOLDER pending Hypatia.
  cantOpenAsk: 'Open conversation',
  // S14: the recipient has no verified PQ KEM key; sends are skipped, never downgraded. Claim-safe wording (no 'quantum-safe').
  notSentNeedsUpgrade:
    'Not sent. Saved on this device. {name} needs to share an updated contact card (security upgrade). Ask them to re-share, then re-add.',
  contactNotSendable: 'This contact cannot receive a sealed message.',
  // D2 (Hypatia #776, KB#93726). Shown ONLY for a sendable contact with ratchet keys whose session has NOT received a frame from them (see
  // showRatchetOffLine). It never says the ratchet is on / enabled / forward secrecy: after commit 4a nothing in this app STARTS a ratchet.
  ratchetOff: "Triple ratchet is off for {name}: this app doesn't start one yet. Messages are still end-to-end encrypted.",
  fieldPeople: 'Conversations',
  fieldBack: 'Chats',
  fieldPick: 'Pick someone to open a conversation.',
  fieldPreviewEmpty: 'No messages yet',
  composeHint: 'Enter to send · Shift+Enter for a new line',
  searchLabel: 'Search',
  searchPlaceholder: 'Search conversations…',
  searchEmpty: 'No conversations match.',
} as const;

/** The status line for a note that was NOT deposited: a recipient with no verified PQ KEM key was skipped (S14), which is
 *  not a network failure and must not read like one. */
export function notSentMessage(contact: { name: string; pqKemPublicKey?: string }): string {
  return contact.pqKemPublicKey
    ? NOTES_COPY.notSent
    : NOTES_COPY.notSentNeedsUpgrade.replace('{name}', contact.name);
}

export function ratchetOffMessage(name: string): string {
  return NOTES_COPY.ratchetOff.replace('{name}', name);
}

export const NOTES_BOUNDS = {
  name: 80,
  body: 32_000,
  fingerprintDisplay: 64,
} as const;
