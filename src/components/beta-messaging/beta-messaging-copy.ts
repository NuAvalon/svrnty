// Verbatim beta-surface copy (CURSOR_QUEUE item 1 — BETA surface only).
// README stays messaging-free. Quiet edges are test-anchored in
// beta-messaging-copy.test.ts. Status floor is Sent — never Delivered / Read / Expired.

export const BETA_COPY = {
  tabLabel: 'Notes',
  unlockHeading: 'Turn on beta messaging',
  unlockBody:
    'Messaging is in beta. Redeem your access key to turn it on for this address book — one key per book.',
  redeemAction: 'Redeem key',
  redeemingAction: 'Redeeming…',
  unlockMicrocopy:
    "Your key unlocks messaging for you. It doesn't change what anyone else can do.",
  accessKeyLabel: 'Access key',
  accessKeyPlaceholder: 'Paste your access key',
  whatItIsHeading: 'Encrypted messages, with the people you trust',
  whatItIs:
    'Send and receive end-to-end encrypted messages with your contacts. Every message is sealed on your device — the relay only ever moves sealed blobs, and never learns who you talk to.',
  sending:
    "When you send, you'll see Sent — your message left your device sealed and reached the relay. (A Delivered confirmation is coming.)",
  sendingWait:
    "If they haven't joined beta, your message waits for them. The moment they join and unlock their book, it delivers. A message to someone who never joins will eventually expire.",
  receiving:
    "You receive messages from your contacts. A message arrives sealed and is saved to this device — if it doesn't appear in your inbox live yet, it's there when you open your messages. (Live inbox updates are coming.)",
  sentStatus: 'Sent',
  redeemFailed: 'This key could not be turned on for this book.',
  redeemEmpty: 'Paste your access key first.',
  identityLocked: 'Unlock your identity first.',
  identityKeysMissing: 'This identity is missing the keys a redeem needs.',
} as const;

/** Outbound status the send UI may show. Floor is Sent. Never Delivered / Read / Expired. */
export const BETA_SEND_STATUS = {
  sent: 'Sent',
} as const;

export const BETA_BOUNDS = {
  accessKey: 24_000,
  name: 80,
} as const;
