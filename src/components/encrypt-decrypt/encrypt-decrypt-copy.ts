// Fixed, non-leaky copy for the Encrypt / Decrypt tab.
// Claim-honesty: this surface does not send. "Verified from" only when
// decryptFromContact returns senderVerified === true.

export const ENCDEC_COPY = {
  tabLabel: 'Encrypt / Decrypt',
  intro:
    'Pick a contact, encrypt a message, then copy the ciphertext. Paste it yourself over any channel. This tab does not send anything.',
  modeEncrypt: 'Encrypt',
  modeDecrypt: 'Decrypt',
  pickerLabelEncrypt: 'Encrypt for',
  pickerPlaceholder: 'Choose a contact',
  plaintextLabel: 'Message',
  ciphertextLabel: 'Ciphertext',
  encryptAction: 'Encrypt',
  decryptAction: 'Decrypt',
  copyCiphertext: 'Copy ciphertext',
  copied: 'Copied',
  copyHint: 'Select the ciphertext and copy it. This tab does not send.',
  notSent: (contactName: string) => `Encrypted for ${contactName} · not sent`,
  verifiedFrom: (contactName: string, fingerprint: string) =>
    `Verified from ${contactName} · ${fingerprint}`,
  senderNotVerified: 'sender NOT cryptographically verified',
  noEncryptableContacts:
    'No encryptable contacts. Import a signed svrnty card first. Classical (keyless) contacts cannot be encrypted to.',
  contactNotEncryptable: 'This contact cannot be encrypted to.',
  identityLocked: 'Unlock your identity first.',
  identityKeysMissing: 'This identity is missing encryption keys.',
  encryptPoisoned: 'This contact’s keys do not match its fingerprint. Encryption was refused.',
  encryptFailed: 'The message could not be encrypted.',
  decryptFailed:
    'This message could not be opened. It may be garbled, meant for someone else, or not a svrnty ciphertext.',
  decryptGarbled: 'This ciphertext could not be read. Check that you pasted the full block.',
  decryptWrongRecipient: 'This message is not sealed to this identity.',
  emptyPlaintext: 'Write a message first.',
  emptyCiphertext: 'Paste a ciphertext block first.',
  noContactSelected: 'Pick a contact first.',
} as const;

export const ENCDEC_BOUNDS = {
  name: 80,
  fingerprintDisplay: 64,
  plaintext: 32_000,
  ciphertext: 200_000,
} as const;
