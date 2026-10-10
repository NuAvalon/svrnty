// Thin call to fleet sendNoteToPeer. Never reimplements seal / sign / deposit.

import { sendNoteToPeer } from '@/lib/messaging/transport';
import { NOTES_COPY } from './notes-copy';
import type { OwnerNoteSender } from './notes-keys';

export type SendNoteResult =
  | { ok: true; note_id: string; thread_id: string; deposited: boolean }
  | { ok: false; error: string };

export async function sendNoteFromInbox(args: {
  sender: OwnerNoteSender;
  peerFingerprint: string;
  peerPublicKeyArmored: string;
  /** Recipient's ML-KEM-1024 pubkey (base64). Present ⇒ PQ-hybrid seal (HNDL); absent ⇒ fail-closed skip. */
  peerPqKemPublicKey?: string;
  body: string;
  threadId?: string;
}): Promise<SendNoteResult> {
  try {
    const result = await sendNoteToPeer({
      sender: { fingerprint: args.sender.fingerprint, participant_kind: 'human' },
      senderPublicKeyArmored: args.sender.publicKeyArmored,
      senderPrivateKeyArmored: args.sender.privateKeyArmored,
      passphrase: args.sender.passphrase,
      senderPqKemPublicKey: args.sender.pqKemPublicKey,
      senderPqSigPublicKey: args.sender.pqSigPublicKey,
      peerFingerprint: args.peerFingerprint,
      peerPublicKeyArmored: args.peerPublicKeyArmored,
      peerPqKemPublicKey: args.peerPqKemPublicKey,
      body: args.body,
      threadId: args.threadId,
    });
    return {
      ok: true,
      note_id: result.note_id,
      thread_id: result.thread_id,
      deposited: result.deposited,
    };
  } catch {
    return { ok: false, error: NOTES_COPY.sendFailed };
  }
}
