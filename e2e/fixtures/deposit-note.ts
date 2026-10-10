// e2e/fixtures/deposit-note.ts
// Classical note SEND simulation for the notes-roundtrip e2e. The MIRROR of deposit-contact-update.ts,
// one layer up: it constructs a GENUINE signed + sealed NoteWireV0 (Seal-v0 CLASSICAL openpgp — the
// path the friends-launch ships; sealLivingBookHybrid / @afdccbd is NOT on main) and deposits the
// opaque blob to the recipient's mailbox. That drives the recipient's app-shell live-book poll through
// the SAME over-wire NOTE seam it runs in production — noteOpenpgpDecryptor (decrypt + type-check) →
// acceptInboundNote (verifyNoteSender AUTHN: public_key↔from_fingerprint + sig; THEN isAdmitted;
// THEN putNote/putThread). So the e2e honestly exercises the real RECEIVE path, and only that.
//
// RELAY COHERENCE (identical reasoning to deposit-contact-update): the send + consume must share ONE
// relay. The shell poll reads /api/relay/queue (the Next.js in-memory mailbox — a single server-side
// store shared by the deposit + the poll), so the deposit MUST hit /api/relay/envelope. The satellite
// /send is a SEPARATE store a note deposited there never reaches. The deposit is identity-blind BY
// DESIGN (the relay cannot read the sealed blob); the security that matters is the inner signed wire,
// which is why this helper builds a real one.
//
// Re-exports the PROVEN primitives from deposit-contact-update.ts (makeE2EIdentity / seedAliceWithBob /
// depositRawBlob — exercised green by demo-arc.spec.ts) so there is ONE canonical identity-mint + book-
// seed path, never a drifting copy.

import type { APIRequestContext } from '@playwright/test';
import { sealNoteTo } from '../../src/lib/messaging/seal';
import { signNoteWire } from '../../src/lib/messaging/note-auth';
import { NOTE_WIRE_TYPE } from '../../src/lib/messaging/domains';
import type { NoteWireV0, ParticipantKind } from '../../src/lib/messaging/types';
import { deriveMailboxId } from '../../src/lib/relay/mailbox-auth';
import type { E2EIdentity } from './deposit-contact-update';

export { makeE2EIdentity, seedAliceWithBob, depositRawBlob } from './deposit-contact-update';
export type { E2EIdentity } from './deposit-contact-update';

/** Opaque wire id — the consume path treats note_id/thread_id as strings (no crypto meaning). */
function randId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
}

export interface NoteDepositFields {
  body: string;
  threadId?: string;
  noteId?: string;
  participantKind?: ParticipantKind;
  /**
   * Forged-sender NEGATIVE control. Put a DIFFERENT fingerprint on the wire than the one that actually
   * signs (`sender`). verifyNoteSender recomputes the canonical fp from the CARRIED (signer's) key and
   * finds it ≠ claimedFrom → the note is dropped at the AUTHN gate (#55 forgeable-sender), never
   * admitted, never rendered. Omit for an honest note (from_fingerprint = sender.fingerprint).
   */
  claimedFrom?: string;
}

/**
 * Build the exact opaque blob that rides sender → recipient: sign the note wire with the sender's
 * identity key (so the recipient can AUTHENTICATE `from_fingerprint`, not just decrypt), then seal it
 * to the recipient's public key. A CANONICAL (64-hex) sender threads its PQ pubkeys so verifyNoteSender
 * recomputes SHA256(sign‖enc‖kem‖sig) and binds — exactly what transport.sendNoteToPeer does in prod.
 * Returns the blob plus the ids the UI will key on (notes-thread-${thread_id} / notes-bubble-${note_id}).
 */
export async function buildSealedNote(
  sender: E2EIdentity,
  recipientPublicKeyArmored: string,
  fields: NoteDepositFields,
): Promise<{ blob: string; note_id: string; thread_id: string }> {
  const note_id = fields.noteId ?? randId('note');
  const thread_id = fields.threadId ?? randId('thr');
  const unsigned: NoteWireV0 = {
    type: NOTE_WIRE_TYPE,
    note_id,
    thread_id,
    from_fingerprint: fields.claimedFrom ?? sender.fingerprint,
    sent_at: new Date().toISOString(),
    body: fields.body,
    participant_kind: fields.participantKind ?? 'human',
  };
  const signed = await signNoteWire(
    unsigned,
    sender.publicKey,
    sender.privateKey,
    sender.passphrase,
    sender.kemPublicKeyB64, // §5 canonical-fp binding (both present ⇒ canonical path)
    sender.sigPublicKeyB64,
  );
  const blob = await sealNoteTo(signed, recipientPublicKeyArmored);
  return { blob, note_id, thread_id };
}

/**
 * Simulate the sender's SEND: build a real signed + sealed note and deposit it to the recipient's
 * mailbox. The recipient's always-on shell poll then genuinely routes → authenticates → admits →
 * persists it (or drops it, for a forgery / unopenable blob). Returns the deposit HTTP status (200 =
 * the blind relay queued the opaque blob) plus the wire ids for the UI assertions.
 */
export async function depositNote(
  request: APIRequestContext,
  args: {
    baseURL?: string;
    sender: E2EIdentity;
    recipientFingerprint: string;
    recipientPublicKeyArmored: string;
    fields: NoteDepositFields;
  },
): Promise<{ status: number; note_id: string; thread_id: string }> {
  const { blob, note_id, thread_id } = await buildSealedNote(
    args.sender,
    args.recipientPublicKeyArmored,
    args.fields,
  );
  const res = await request.post(`${args.baseURL ?? ''}/api/relay/envelope`, {
    data: { mailbox_id: deriveMailboxId(args.recipientFingerprint), blob },
  });
  return { status: res.status(), note_id, thread_id };
}
