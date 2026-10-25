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
// Only the POLICY surface. The raw session primitives (sealDirectNote / openDirectNote / put/getRatchetSession) are deliberately NOT
// exported: they skip the deposit gate, the observed-capability rule, the owner binding and commit-after-store (R1/D1/R2/R4).
export { isTripleRatchetBody, chooseWireBody, openDirectNoteStaged, peerRatchetStatus, TRIPLE_RATCHET_BODY } from './direct-session';
export type { PeerRatchetStatus } from './direct-session';
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
