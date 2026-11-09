// Test-only: sendNoteFromHeadless refuses anyone not in the sender's book, and most send tests are about what happens after that check.
// This puts the peer in the book first, the same way a real agent admits a contact before writing to them. Refusals are tested against the real function.
import type { HeadlessContact } from './headless-store';
import { sendNoteFromHeadless as send } from './headless-client';

export const sendNoteFromHeadless: typeof send = (args) => {
  if (!args.store.getContactByFingerprint(args.peerFingerprint)) {
    args.store.upsertContact({ id: args.peerFingerprint, fingerprint: args.peerFingerprint, public_key: args.peerPublicKeyArmored } as HeadlessContact);
  }
  return send(args);
};
