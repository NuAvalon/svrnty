// src/lib/messaging/transport.ts
// Deposit / consume notes via the EXISTING dumb mailbox — no new relay smarts.
// Discriminator is inside the sealed payload (svrnty-note-v0), not an HTTP path.

import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { sealNoteTo, noteOpenpgpDecryptor } from './seal';
import { signNoteWire, verifyNoteSender } from './note-auth';
import { NOTE_WIRE_TYPE } from './domains';
import type { NoteWireV0, ParticipantKind } from './types';
import { newNoteId, putNote, putThread, listThreads, newThreadId, newReceiptNonce } from './store';
import type { NoteRecord } from './types';
import { isTripleRatchetBody, chooseWireBody, ownerBoundRatchetIO, type RatchetIO, type StagedOpen } from './direct-session';
import type { RatchetIdentity, RatchetPeer } from '@/lib/crypto/message-ratchet';

export interface NoteSenderIdentity {
  fingerprint: string;
  participant_kind: ParticipantKind;
}

/** Seal + deposit one note to a peer's mailbox (opaque blob). */
export async function sendNoteToPeer(args: {
  sender: NoteSenderIdentity;
  /** Sender's own openpgp identity key material — signs the note so the recipient can authenticate
   *  `from_fingerprint` (fingerprintMatchesKey binds senderPublicKeyArmored ↔ sender.fingerprint). */
  senderPublicKeyArmored: string;
  senderPrivateKeyArmored: string;
  passphrase: string;
  /** §5 canonical-fp binding: the sender's PQ pubkeys (base64). Thread BOTH so a CANONICAL (64-hex)
   *  sender authenticates — verifyNoteSender recomputes SHA256(sign‖enc‖kem‖sig). A classical (40-hex)
   *  sender omits them → the OpenPGP-fp path. Sourced from the identity's post_quantum. */
  senderPqKemPublicKey?: string;
  senderPqSigPublicKey?: string;
  peerFingerprint: string;
  peerPublicKeyArmored: string;
  /** The RECIPIENT's verified ML-KEM-1024 pubkey (base64). Present ⇒ the note is sealed PQ-hybrid (HNDL).
   *  ABSENT ⇒ fail-closed: the note is NOT deposited (never downgraded to classical). */
  peerPqKemPublicKey?: string;
  body: string;
  threadId?: string;
  relayBase?: string;
  fetchImpl?: typeof fetch;
  /** When both sides have X25519 + ML-KEM AND the peer has been observed to send ratchet frames (D1), the inner body is a
   *  triple-ratchet packet; otherwise it is the plain body, which still travels inside the hybrid outer seal. */
  ownerRatchet?: RatchetIdentity;
  peerRatchet?: RatchetPeer;
  /** Test seam: the stores this flow writes through. Defaults are the real encrypted IndexedDB stores. */
  io?: { ratchet?: RatchetIO; putNote?: typeof putNote; putThread?: typeof putThread; listThreads?: typeof listThreads };
}): Promise<{ note_id: string; thread_id: string; deposited: boolean }> {
  const fetchImpl = args.fetchImpl ?? fetch;
  const relayBase = args.relayBase ?? '/api/relay';
  const thread_id = args.threadId ?? newThreadId();
  const note_id = newNoteId();
  const sent_at = new Date().toISOString();
  // Delivery-receipt (Athena — Nov-5): a per-note freshness nonce, carried SEALED+SIGNED inside the wire
  // (it is part of noteSigningInput → sender-signed under DOMAIN_NOTE) and kept on the local record as the
  // sender's source-of-truth. The recipient echoes it in a recipient-signed receipt; the sender verifies
  // the echo against this stored value. Always generated — harmless if the peer never returns a receipt
  // (the note simply stays the honest 'Sent · unconfirmed.' floor).
  const receipt_nonce = newReceiptNonce();

  // ONE predicate decides "can this note be deposited" for BOTH the ratchet policy and the deposit gate below. Two copies of it would
  // let R1 regress silently if one changed (Flint #769).
  const canDeposit = !!args.peerPqKemPublicKey;
  // R1 + D1: the wire-body policy is one function, in the only safe order (gate -> ratchet -> sign -> seal -> POST). A note that
  // cannot be deposited (no verified ML-KEM key) touches NO ratchet state, and a peer not yet observed to send ratchet frames
  // gets the plain body. See chooseWireBody (direct-session.ts).
  const { wireBody } = await chooseWireBody(
    {
      body: args.body,
      peerFingerprint: args.peerFingerprint,
      canDeposit,
      ownerRatchet: args.ownerRatchet,
      peerRatchet: args.peerRatchet,
    },
    args.io?.ratchet ?? ownerBoundRatchetIO(args.sender.fingerprint),   // R2: every session read/write is checked against the acting owner
  );

  const unsignedWire: NoteWireV0 = {
    type: NOTE_WIRE_TYPE,
    note_id,
    thread_id,
    from_fingerprint: args.sender.fingerprint,
    sent_at,
    body: wireBody,
    participant_kind: args.sender.participant_kind,
    receipt_nonce,
  };

  // Sign BEFORE sealing so the recipient can authenticate the sender (not just decrypt). The
  // signature travels inside the sealed blob — confidentiality is unchanged; authenticity is added.
  const wire = await signNoteWire(
    unsignedWire,
    args.senderPublicKeyArmored,
    args.senderPrivateKeyArmored,
    args.passphrase,
    args.senderPqKemPublicKey, // §5: canonical-fp binding (both must be present to bind; else classical path)
    args.senderPqSigPublicKey,
  );
  // fail-closed: no pq_kem → skip, never downgrade (HNDL). A recipient without a verified ML-KEM-1024
  // pubkey is NOT deposited to in a classical/downgraded form; the local copy is kept as "not sent".
  let deposited = false;
  if (canDeposit) {
    const blob = await sealNoteTo(wire, args.peerPublicKeyArmored, args.peerPqKemPublicKey!);
    const mailbox_id = deriveMailboxId(args.peerFingerprint);
    const res = await fetchImpl(`${relayBase}/envelope`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mailbox_id, blob }),
    });
    deposited = res.ok;
  } else {
    console.warn('[notes] fail-closed: recipient has no pq_kem — note NOT deposited (never downgrade, HNDL)');
  }

  // Local outbound copy (encrypted at rest in notes store — caller must have unlocked it)
  const local: NoteRecord = {
    note_id,
    thread_id,
    direction: 'outbound',
    from_fingerprint: args.sender.fingerprint,
    to_fingerprints: [args.peerFingerprint],
    sent_at,
    body: args.body,
    participant_kind: args.sender.participant_kind,
    retention: { expires_at: null },
    wire_type: NOTE_WIRE_TYPE,
    receipt_nonce, // source-of-truth for verifying the recipient's delivery receipt (delivered stays unset until then)
  };
  await (args.io?.putNote ?? putNote)(local);

  const threads = await (args.io?.listThreads ?? listThreads)();
  let thread = threads.find((t) => t.thread_id === thread_id);
  if (!thread) {
    thread = {
      thread_id,
      kind: 'direct',
      participants: [
        {
          fingerprint: args.peerFingerprint,
          kind: 'human', // display kind; peer's self-claim arrives on inbound
          display_name: args.peerFingerprint.slice(0, 8),
        },
      ],
      created_at: sent_at,
      last_activity_at: sent_at,
      retention: { expires_at: null },
    };
  } else {
    thread = { ...thread, last_activity_at: sent_at };
  }
  await (args.io?.putThread ?? putThread)(thread);

  return { note_id, thread_id, deposited };
}

/**
 * Try to interpret a decrypted mailbox plaintext JSON as a note.
 * Returns null if it isn't a note (e.g. contact.update) — caller continues other pipelines.
 */
export function tryParseNoteWire(obj: unknown): NoteWireV0 | null {
  if (!obj || typeof obj !== 'object') return null;
  const o = obj as Record<string, unknown>;
  if (o.type !== NOTE_WIRE_TYPE) return null;
  if (typeof o.body !== 'string' || typeof o.from_fingerprint !== 'string') return null;
  return o as unknown as NoteWireV0;
}

/** Build the OpenPGP note decryptor for the unlocked owner. */
export { noteOpenpgpDecryptor };

/**
 * Admit-check: only persist inbound notes from fingerprints already in the book.
 * `isAdmitted` is injected so this module never imports the contacts store directly.
 */
export async function acceptInboundNote(args: {
  wire: NoteWireV0;
  isAdmitted: (fingerprint: string) => Promise<boolean>;
  peerDisplayName?: string;
  peerKind?: ParticipantKind;
  /** Open a triple-ratchet inner body. Required when the body is a ratchet packet. May return the plaintext (already committed, legacy)
   *  or a {@link StagedOpen}, whose session advance is committed HERE only after the note and thread are stored (R4). */
  openRatchet?: (fromFingerprint: string, body: string) => Promise<string | StagedOpen | null>;
  /** Test seam: the stores this flow writes through. Defaults are the real encrypted IndexedDB stores. */
  io?: { putNote?: typeof putNote; putThread?: typeof putThread; listThreads?: typeof listThreads };
}): Promise<NoteRecord | null> {
  // AUTHENTICATE before admit (Flint #55 merge-gate): a note's from_fingerprint is attacker-controlled
  // until the signature is verified and bound to the carried public_key. Unsigned or forged ⇒ drop
  // HERE, before isAdmitted — admission is not authentication.
  if (!(await verifyNoteSender(args.wire))) {
    return null; // unsigned / forged sender — structural drop
  }
  if (!(await args.isAdmitted(args.wire.from_fingerprint))) {
    return null; // spam / stranger — structural drop
  }
  let body = args.wire.body;
  let commitRatchet: (() => Promise<void>) | undefined;
  if (isTripleRatchetBody(body)) {
    if (!args.openRatchet) return null;
    const opened = await args.openRatchet(args.wire.from_fingerprint, body);
    if (opened === null) return null;
    if (typeof opened === 'string') {
      body = opened;
    } else {
      body = opened.plaintext;
      commitRatchet = opened.commit;
    }
  }
  const sent_at = args.wire.sent_at || new Date().toISOString();
  const record: NoteRecord = {
    note_id: args.wire.note_id,
    thread_id: args.wire.thread_id,
    direction: 'inbound',
    from_fingerprint: args.wire.from_fingerprint,
    to_fingerprints: [], // self
    sent_at,
    body,
    participant_kind: args.wire.participant_kind || args.peerKind || 'human',
    retention: { expires_at: null },
    wire_type: NOTE_WIRE_TYPE,
  };
  await (args.io?.putNote ?? putNote)(record);

  const threads = await (args.io?.listThreads ?? listThreads)();
  let thread = threads.find((t) => t.thread_id === record.thread_id);
  if (!thread) {
    thread = {
      thread_id: record.thread_id,
      kind: args.wire.ring_channel_id ? 'ring' : 'direct',
      participants: [
        {
          fingerprint: args.wire.from_fingerprint,
          kind: record.participant_kind,
          display_name: args.peerDisplayName || args.wire.from_fingerprint.slice(0, 8),
        },
      ],
      ring_channel_id: args.wire.ring_channel_id,
      created_at: sent_at,
      last_activity_at: sent_at,
      retention: { expires_at: null },
    };
  } else {
    thread = { ...thread, last_activity_at: sent_at };
  }
  await (args.io?.putThread ?? putThread)(thread);
  // R4: ONLY NOW is the ratchet advance persisted: the note and its thread are durably stored. A failure anywhere above leaves the
  // session untouched, so the retried envelope opens again. If this commit itself fails the note is already stored (putNote is idempotent
  // on note_id), the session is still un-advanced, and the retry re-opens, re-stores harmlessly and commits.
  if (commitRatchet) await commitRatchet();
  return record;
}
