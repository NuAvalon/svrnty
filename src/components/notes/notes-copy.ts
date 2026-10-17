// Fixed copy for the Chat surface (over-wire SEND / INBOX).
// The Chat tab is the window — no essay masthead. Status floor is
// "Sent · unconfirmed." — never Delivered / Read / Expired.
// Essay claims ("encrypted messages…", "How notes travel") stay off this glass.
// "Delivered" renders ONLY on a cryptographically VERIFIED delivery receipt (delivery-receipt.ts);
// the floor stays "Sent · unconfirmed." for every unverified path (notes-status.ts statusIsHonest).

export const NOTES_COPY = {
  tabLabel: 'Chat',
  heading: 'Chat',
  sentUnconfirmed: 'Sent · unconfirmed.',
  notSent: 'Not sent. Saved on this device.',
  // Rendered ONLY for a verified-receipt 'delivered' status. Hypatia owns the exact copy-graduation
  // wording (#172182 Delivered-when-receipt-proves) — confirm/adjust this string with her.
  delivered: 'Delivered',
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
    'No contacts to write to. Import a signed svrnty card first. Keyless contacts cannot receive a sealed note.',
  noContactSelected: 'Pick a contact first.',
  emptyBody: 'Write a message first.',
  identityLocked: 'Unlock your identity first.',
  identityKeysMissing: 'This identity is missing the keys a note needs.',
  needCanonical:
    'Chat over the wire needs a current svrnty identity. This book cannot send yet.',
  sendFailed: 'The message could not be sent.',
  contactNotSendable: 'This contact cannot receive a sealed note.',
  fieldPeople: 'Conversations',
  fieldBack: 'Chats',
  fieldPick: 'Pick someone to open a conversation.',
  fieldPreviewEmpty: 'No messages yet',
  composeHint: 'Enter to send · Shift+Enter for a new line',
  searchLabel: 'Search',
  searchPlaceholder: 'Search conversations…',
  searchEmpty: 'No conversations match.',
} as const;

export const NOTES_BOUNDS = {
  name: 80,
  body: 32_000,
  fingerprintDisplay: 64,
} as const;
