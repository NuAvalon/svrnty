// src/lib/messaging/index.ts
// Phase 3 notes substrate — see docs/MESSAGING_PRIOR_ART.md + docs/MESSAGING_STORE.md.
// Public claim: "notes between contacts" until ratchet (3.3) is green.

export { DOMAIN_NOTE, DOMAIN_RING_KEY_WRAP, NOTE_WIRE_TYPE } from './domains';
export { noteSigningInput } from './canonical';
export { sealNoteTo, noteOpenpgpDecryptor } from './seal';
export { createRingChannel, rotateRingMembership, ringDepositTargets } from './ring';
export {
  initNotesStore,
  isNotesStoreUnlocked,
  lockNotesStore,
  putThread,
  listThreads,
  putNote,
  listNotesForThread,
  deleteThread,
  putRingChannel,
  listRingChannels,
  newNoteId,
  newThreadId,
} from './store';
export {
  sendNoteToPeer,
  acceptInboundNote,
  tryParseNoteWire,
} from './transport';
export type {
  ParticipantKind,
  ThreadKind,
  NoteThread,
  NoteRecord,
  NoteWireV0,
  RingChannel,
  RetentionPolicy,
} from './types';
