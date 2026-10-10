// src/lib/messaging/types.ts
// Notes / future-messaging types (Phase 3.2). Ephemeral conversation objects —
// never mixed into the living-book TrustEdge schema.

import { NOTE_WIRE_TYPE } from './domains';
import type { EnvelopeSignature } from '@/lib/crypto/sign-envelope';

/** Who is speaking — humans and human-trusted agents share the admit-to-speak rule. */
export type ParticipantKind = 'human' | 'agent';

export type ThreadKind = 'direct' | 'ring';

/** Retention: book is permanent; notes are user-ruled / optionally TTL'd. */
export interface RetentionPolicy {
  /** ISO timestamp after which the client should drop the note; null = keep until user deletes */
  expires_at: string | null;
}

export interface ThreadParticipant {
  fingerprint: string;
  kind: ParticipantKind;
  /** Local display name YOU gave them (from the book); never trusted from wire alone */
  display_name: string;
}

export interface NoteThread {
  thread_id: string;
  kind: ThreadKind;
  /** direct: one peer; ring: local membership list (never a server roster) */
  participants: ThreadParticipant[];
  /** Ring channel id when kind === 'ring' */
  ring_channel_id?: string;
  created_at: string;
  last_activity_at: string;
  retention: RetentionPolicy;
}

export type NoteDirection = 'outbound' | 'inbound';

export interface NoteRecord {
  note_id: string;
  thread_id: string;
  direction: NoteDirection;
  from_fingerprint: string;
  to_fingerprints: string[]; // direct: [peer]; ring: fan-out list (local)
  sent_at: string;
  body: string;
  participant_kind: ParticipantKind;
  retention: RetentionPolicy;
  /** Wire protocol version that produced this note */
  wire_type: typeof NOTE_WIRE_TYPE;
}

/**
 * Plaintext payload sealed to recipient(s). Pre-ratchet (v0): classical confidentiality
 * only — NOT forward-secret. See docs/MESSAGING_PRIOR_ART.md claim ladder.
 */
export interface NoteWireV0 {
  type: typeof NOTE_WIRE_TYPE;
  note_id: string;
  thread_id: string;
  from_fingerprint: string;
  sent_at: string;
  body: string;
  participant_kind: ParticipantKind;
  /** Optional; omitted on direct threads */
  ring_channel_id?: string;
  // ── Sender authentication (Apollo — Flint #55 forgeable-sender merge-gate) ──────────────────
  // Without these a note is only ENCRYPTED, not SIGNED: from_fingerprint would be attacker-set and
  // any admitted contact's fingerprint could be forged. `public_key` is the sender's openpgp key;
  // `signature` is signWithEnvelope(DOMAIN_NOTE, noteSigningInput(wire)). acceptInboundNote binds
  // public_key↔from_fingerprint (fingerprintMatchesKey) then verifies BEFORE admit. Optional on the
  // TYPE (a local outbound copy / older record may lack them), but acceptInboundNote REJECTS an
  // inbound wire that is missing or fails them. Both are EXCLUDED from noteSigningInput.
  public_key?: string;
  signature?: EnvelopeSignature;
  // §5 canonical-fp binding: the sender's PQ PUBLIC keys, so verifyNoteSender can recompute the 64-hex
  // canonical fingerprint = SHA256(sign‖enc‖kem‖sig) and confirm from_fingerprint↔key for a CANONICAL
  // identity. Absent for a classical (40-hex OpenPGP) sender → fingerprintMatchesKey falls back to the
  // getFingerprint() path. Public keys only; possession is proved by the signature. Both are EXCLUDED
  // from noteSigningInput (the pinned DOMAIN_NOTE preimage is unchanged — they bind via the fp-match).
  pq_kem_public_key?: string; // base64(ML-KEM-1024 pubkey, 1568B)
  pq_sig_public_key?: string; // base64(ML-DSA-87 pubkey, 2592B)
}

/** Local ring-channel state — NEVER uploaded as a roster table. */
export interface RingChannel {
  channel_id: string;
  /** Local label only; never sent to relay as group name */
  local_label: string;
  member_fingerprints: string[];
  /** Epoch bumps on membership change → content key rotation (3.4) */
  key_epoch: number;
  /** AES-256 content key, base64 — wrapped per-member for distribution; plaintext only in unlocked client */
  content_key_b64: string;
  created_at: string;
  rotated_at: string;
}
