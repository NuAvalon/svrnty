// src/lib/messaging/transport.ts
// Deposit / consume notes via the EXISTING dumb mailbox — no new relay smarts.
// Discriminator is inside the sealed payload (svrnty-note-v0), not an HTTP path.

import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { sealNoteTo, noteOpenpgpDecryptor } from './seal';
import { NOTE_WIRE_TYPE } from './domains';
import type { NoteWireV0, ParticipantKind } from './types';
import { newNoteId, putNote, putThread, listThreads, newThreadId } from './store';
import type { NoteRecord, NoteThread } from './types';

export interface NoteSenderIdentity {
  fingerprint: string;
  participant_kind: ParticipantKind;
}

/** Seal + deposit one note to a peer's mailbox (opaque blob). */
export async function sendNoteToPeer(args: {
  sender: NoteSenderIdentity;
  peerFingerprint: string;
  peerPublicKeyArmored: string;
  body: string;
  threadId?: string;
  relayBase?: string;
  fetchImpl?: typeof fetch;
}): Promise<{ note_id: string; thread_id: string; deposited: boolean }> {
  const fetchImpl = args.fetchImpl ?? fetch;
  const relayBase = args.relayBase ?? '/api/relay';
  const thread_id = args.threadId ?? newThreadId();
  const note_id = newNoteId();
  const sent_at = new Date().toISOString();

  const wire: NoteWireV0 = {
    type: NOTE_WIRE_TYPE,
    note_id,
    thread_id,
    from_fingerprint: args.sender.fingerprint,
    sent_at,
    body: args.body,
    participant_kind: args.sender.participant_kind,
  };

  const blob = await sealNoteTo(wire, args.peerPublicKeyArmored);
  const mailbox_id = deriveMailboxId(args.peerFingerprint);
  const res = await fetchImpl(`${relayBase}/envelope`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mailbox_id, blob }),
  });
  const deposited = res.ok;

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
  };
  await putNote(local);

  const threads = await listThreads();
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
  await putThread(thread);

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
}): Promise<NoteRecord | null> {
  if (!(await args.isAdmitted(args.wire.from_fingerprint))) {
    return null; // spam / stranger — structural drop
  }
  const sent_at = args.wire.sent_at || new Date().toISOString();
  const record: NoteRecord = {
    note_id: args.wire.note_id,
    thread_id: args.wire.thread_id,
    direction: 'inbound',
    from_fingerprint: args.wire.from_fingerprint,
    to_fingerprints: [], // self
    sent_at,
    body: args.wire.body,
    participant_kind: args.wire.participant_kind || args.peerKind || 'human',
    retention: { expires_at: null },
    wire_type: NOTE_WIRE_TYPE,
  };
  await putNote(record);

  const threads = await listThreads();
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
  await putThread(thread);
  return record;
}
