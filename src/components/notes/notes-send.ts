// Thin call to fleet sendNoteToPeer. Never reimplements seal / sign / deposit.

import { sendNoteToPeer } from '@/lib/messaging/transport';
import { loadOwnerRatchetIdentity, peerRatchetFromCard } from '@/lib/messaging/ratchet-keys';
import { NOTES_COPY } from './notes-copy';
import type { OwnerNoteSender } from './notes-keys';

export type SendNoteResult =
  | { ok: true; note_id: string; thread_id: string; deposited: boolean }
  | { ok: false; error: string };

export async function sendNoteFromInbox(args: {
  sender: OwnerNoteSender;
  ownerIdentity?: unknown;
  peerFingerprint: string;
  peerPublicKeyArmored: string;
  /** Recipient's ML-KEM-1024 pubkey (base64). Present ⇒ PQ-hybrid seal (HNDL); absent ⇒ fail-closed skip. */
  peerPqKemPublicKey?: string;
  /** Recipient's ML-DSA-87 pubkey (base64): with the KEM key it binds the canonical fingerprint (isCanonicalNoteSender). */
  peerPqSigPublicKey?: string;
  body: string;
  threadId?: string;
}): Promise<SendNoteResult> {
  try {
    const [ownerRatchet, peerRatchet] = await Promise.all([
      args.ownerIdentity
        ? loadOwnerRatchetIdentity(args.sender.fingerprint, args.ownerIdentity)
        : Promise.resolve(null),
      peerRatchetFromCard({
        publicKeyArmored: args.peerPublicKeyArmored,
        pqKemPublicKey: args.peerPqKemPublicKey,
        pqSigPublicKey: args.peerPqSigPublicKey,
      }),
    ]);
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
      ownerRatchet: ownerRatchet ?? undefined,
      peerRatchet: peerRatchet ?? undefined,
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
