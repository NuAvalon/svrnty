// src/lib/messaging/domains.ts
// Domain-separation tags for notes (Phase 3).
//
// These live HERE — not yet in src/lib/format/envelope.ts — because /src/lib/format/** is
// format-frozen (MERGE_GATE → Peter-ack). When Archie freezes note fields, promote these
// strings byte-exact into envelope.ts and delete this file's duplicates.

export const DOMAIN_NOTE = 'svrnty:note:v0';
export const DOMAIN_RING_KEY_WRAP = 'svrnty:ring-key-wrap:v0';

/** Wire discriminator inside a decrypted mailbox blob (not an HTTP route). */
export const NOTE_WIRE_TYPE = 'svrnty-note-v0';
