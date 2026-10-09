// src/lib/messaging/index.ts
// Phase 3 notes substrate — see docs/MESSAGING_PRIOR_ART.md + docs/MESSAGING_STORE.md.
// Public claim: "notes between contacts" until ratchet (3.3) is green.

export { DOMAIN_NOTE, DOMAIN_RING_KEY_WRAP, NOTE_WIRE_TYPE } from './domains';
export { noteSigningInput } from './canonical';
export { sealNoteTo, noteOpenpgpDecryptor } from './seal';
export {
  createRingChannel,
  rotateRingMembership,
  ringDepositTargets,
  addRingMember,
  removeRingMember,
  notesToShare,
  RING_HISTORY_LIMIT,
} from './ring';
export { RingSession, MAX_RING_MEMBERS } from './ring-session';
export type { RingPeer, RingHistoryItem } from './ring-session';
export { mainTimeline, sideThread, replyCount, replyLink, isNoteId } from './threads';
export { loadRatchetIdentity, ringPeerFromContact } from './ring-keys';
export {
  initNotesStore,
  isNotesStoreUnlocked,
  lockNotesStore,
  putThread,
  listThreads,
  putNote,
  listNotesForThread,
  listAllNotes,
  deleteThread,
  putRingChannel,
  listRingChannels,
  newNoteId,
  newThreadId,
} from './store';
export {
  sendNoteToPeer,
  sendRingNote,
  sendRingHistory,
  acceptInboundNote,
  tryParseNoteWire,
} from './transport';
export { buildNotesBackup, parseNotesBackup, exportNotesBackup, importNotesBackup, NOTES_BACKUP_VERSION } from './notes-backup';
export type { NotesBackup } from './notes-backup';
export type {
  ParticipantKind,
  ThreadKind,
  NoteThread,
  NoteRecord,
  NoteWireV0,
  RingChannel,
  RingHistoryAccess,
  RetentionPolicy,
} from './types';
