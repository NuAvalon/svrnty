// src/lib/format/envelope.ts
// Signed-envelope FIELD DEFINITIONS + canonical signing-input for svrnty Tier-0 (Queue B 0.1/0.2 — Archie).
// FORMAT half: what fields exist + their canonical bytes. CRYPTO half (domain-sep prefix, suite_id,
// sign/verify) = Flint's 0.1 signing layer. Signing structure (Flint #115344):
//   sign( LP(domain_tag) ‖ LP(suite_id) ‖ signingInput(...) )        LP = length-prefixed
// The DOMAIN_* tags live here as the SINGLE SOURCE OF TRUTH so the tag strings never drift between
// the format layer (me) and the signing layer (Flint imports these).
// Spec: shared/outbox/archie/svrnty_queueB_0.13_dedup_and_0.1_0.2_format_v1.md §A2/A3

import { canonicalize } from './canonical';

// --- Domain-separation tags (shared vocab; Flint length-prefixes these before signing) ---
export const DOMAIN_TRUST_SIGNAL = 'svrnty:trust-signal:v1';
export const DOMAIN_CONTACT_UPDATE = 'svrnty:contact-update:v1';
export const DOMAIN_SLUG_CLAIM = 'svrnty:slug-claim:v1';
// Key-lineage sub-domains for Flint's rotation/recovery signing (#115350). Crypto is his; the tag
// STRINGS live here so the domain-separation vocabulary stays single-source (a signer/verifier tag
// drift is a domain-confusion bug — centralizing eliminates that class).
export const DOMAIN_KEY_ROTATION = 'svrnty:key-rotation:v1';
export const DOMAIN_KEY_RECOVERY = 'svrnty:key-recovery:v1';

// --- A2: Durable identity + epoch/lineage (formats-cheap: fields only, no rotation UX) ---

/** Successor authorization. Format defines the SHAPE; the signatures/quorum crypto are Flint's. */
export type SuccessorAuth =
  | { kind: 'rotation'; sig_by_prior_epoch: string }                 // normal: prior key signs successor
  | { kind: 'recovery'; quorum_sigs: string[]; threshold: number };  // recovery: prior key LOST → quorum signs

/**
 * Durable identity: `fingerprint` is genesis-derived and NEVER changes across rotation;
 * `epoch` + `successor` carry the lineage so the living address book survives key rotation
 * (epoch-catch-up: accept a newer validly-successored epoch after verifying lineage).
 */
export interface DurableIdentity {
  fingerprint: string;      // immutable across rotations (= TrustEdge.peer_fingerprint)
  epoch: number;            // monotonic; +1 per rotation/recovery
  successor?: {
    new_fingerprint: string;
    new_public_key: string;
    epoch: number;          // = this.epoch + 1
    auth: SuccessorAuth;    // Flint's crypto
  };
}

// --- A3: Envelopes (the field sets Flint signs) ---

/**
 * contact.update delta envelope. Ordering key = `version` (monotonic), NOT `updated_at`
 * (timestamps lie under clock skew). Receiver rejects version <= last-seen before any sig work.
 */
export interface ContactUpdateEnvelope {
  fingerprint: string;             // card owner (durable identity)
  epoch: number;                   // owner's current epoch — receiver verifies lineage
  version: number;                 // monotonic card version
  updated_at: string;              // ISO-8601 UTC — audit/display only, NOT the ordering key
  changed_fields: string[];        // allowlist subset; unknown field → reject the whole update
  delta: Record<string, unknown>;  // only the changed fields
}

/**
 * F6 slug-claim (closes the unsigned-slug-claim gap). Server verifies the signature against
 * `public_key` AND that `fingerprint === H(public_key)` — proving private-key possession over
 * THIS claim, not merely presenting a public key. (Reuses the canonical envelope, own sub-domain.)
 */
export interface SlugClaim {
  slug: string;
  fingerprint: string;      // MUST equal H(public_key), server-verified
  public_key: string;
  timestamp: string;        // ISO-8601 UTC — replay-bounded by the freshness window
}

// --- Canonical signing inputs (Flint prefixes LP(domain)‖LP(suite_id) then signs) ---

/** Canonical bytes for a contact.update signature (excludes any attached `signature`). */
export function contactUpdateSigningInput(env: ContactUpdateEnvelope): string {
  return canonicalize(env, { exclude: ['signature'] });
}

/** Canonical bytes for an F6 slug-claim signature. */
export function slugClaimSigningInput(claim: SlugClaim): string {
  return canonicalize(claim, { exclude: ['signature'] });
}
