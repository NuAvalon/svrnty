// src/lib/format/envelope.ts
// Signed-envelope FIELD DEFINITIONS + canonical signing-input for svrnty Tier-0 (Queue B 0.1/0.2).
// FORMAT half: what fields exist + their canonical bytes. CRYPTO half (domain-sep prefix, suite_id,
// sign/verify) = the 0.1 signing layer. Signing structure:
//   sign( LP(domain_tag) ‖ LP(suite_id) ‖ signingInput(...) )        LP = length-prefixed
// The DOMAIN_* tags live here as the SINGLE SOURCE OF TRUTH so the tag strings never drift between
// the format layer and the signing layer (which imports these).
// Spec §A2/A3

import { canonicalize } from './canonical';

// --- Domain-separation tags (shared vocab; the signing layer length-prefixes these before signing) ---
export const DOMAIN_TRUST_SIGNAL = 'svrnty:trust-signal:v1';
export const DOMAIN_CONTACT_UPDATE = 'svrnty:contact-update:v1';
export const DOMAIN_SLUG_CLAIM = 'svrnty:slug-claim:v1';
export const DOMAIN_IDENTITY_CARD = 'svrnty:identity-card:v1';
// Key-lineage sub-domains for the rotation/recovery signing. Crypto lives in the signing layer; the tag
// STRINGS live here so the domain-separation vocabulary stays single-source (a signer/verifier tag
// drift is a domain-confusion bug — centralizing eliminates that class).
export const DOMAIN_KEY_ROTATION = 'svrnty:key-rotation:v1';
export const DOMAIN_KEY_RECOVERY = 'svrnty:key-recovery:v1';
// Authority-key pre-rotation (KERI-style). Dedicated tag — must not collide with card-sign,
// mailbox-auth, note-auth, or DOMAIN_KEY_ROTATION. Both legs of sig_by_authority bind this domain
// via sign-envelope LP + suite framing.
export const DOMAIN_ROTATION = 'svrnty:rotation:v1';
// R1 mutual-connect (pending-joiner return channel + remote mutual-vouch). The crypto lives in the signing layer; the tag
// STRINGS live here as single-source so a signer/verifier drift can't cause domain confusion — a
// joiner-response signature can never verify as a contact-update / identity-card, and vice-versa.
export const DOMAIN_JOINER_RESPONSE = 'svrnty:joiner-response:v1';
export const DOMAIN_MUTUAL_VOUCH = 'svrnty:mutual-vouch:v1';

// --- A2: Durable identity + epoch/lineage (formats-cheap: fields only, no rotation UX) ---

/**
 * Successor authorization. `kind` is an OPEN discriminant — the verifier FAIL-CLOSES (throws) on
 * any kind it does not implement. Rotation is the launch kind (authority reveal + hybrid
 * authority signature). Recovery / revocation / authority-transfer kinds slot in later via a
 * schema version bump; an old verifier must never silently accept them.
 */
export type RotationSuccessorAuth = {
  kind: 'rotation';
  /** Revealed next-epoch authority pubs (hex of raw 32B ed25519 ‖ 2592B ML-DSA-87). */
  auth_pubkeys: { sign: string; pq_sig: string };
  /** Hybrid sig BY those pubs over rotationSigningInput (hex of ed25519-sig ‖ ML-DSA-sig). */
  sig_by_authority: string;
};

export type SuccessorAuth =
  | RotationSuccessorAuth
  | { kind: 'recovery'; quorum_sigs: string[]; threshold: number }
  | { kind: string; [key: string]: unknown };

/**
 * Durable identity: `fingerprint` is genesis-derived and NEVER changes across rotation;
 * `epoch` + `successor` carry the lineage so the living address book survives key rotation
 * (epoch-catch-up: accept a newer validly-successored epoch after verifying lineage).
 * `next_authority_commitment` is the anti-theft pin: SHA256 of the next epoch's raw hybrid
 * authority pubs, minted at genesis while the cold seed is in hand. '' for pre-mint/legacy cards.
 */
export interface DurableIdentity {
  fingerprint: string;      // immutable across rotations (= TrustEdge.peer_fingerprint)
  epoch: number;            // monotonic; +1 per rotation/recovery
  next_authority_commitment: string; // 64-hex SHA256(authEd ‖ authDsa) for epoch+1; '' if legacy
  successor?: {
    new_fingerprint: string;
    new_public_key: string;
    epoch: number;          // = this.epoch + 1
    next_authority_commitment: string; // the pin for the epoch AFTER this successor
    auth: SuccessorAuth;    // signing-layer crypto
  };
}

// --- A3: Envelopes (the field sets the signing layer signs) ---

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
 * R1 pending-joiner RETURN-CHANNEL envelope (KNOWN tier). Closes the one-directional Grow asymmetry
 * (the joiner adds the giver via a relay/QR invite, but the giver never learns → no
 * mutual edge → the contact.update wire can't reach the joiner). After the joiner adds the giver, the
 * joiner SIGNS this self-asserted identity claim and deposits it (per-peer-encrypted) to the giver's
 * mailbox; the giver verifies and surfaces the joiner as KNOWN (unverified TOFU — the 3-state floor)
 * Identity-only BY DESIGN: once the edge is mutual the giver holds the joiner's card,
 * so the already-live contact.update wire (0.4) carries METHODS both ways — this envelope only needs
 * to make the edge exist. NOT a monotonic stream (a one-shot handshake) → no `version`; replay is
 * bounded by the single-use `invite_nonce` (the giver's own relay code), not a version floor.
 */
export interface JoinerResponseEnvelope {
  joiner_fingerprint: string;         // self-asserted; the verifier re-derives H(joiner_public_key) (Invariant-1)
  joiner_epoch: number;               // the joiner's current key epoch — seeds the giver's future-update floor
  joiner_public_key: string;          // armored classical (OpenPGP/Ed25519) — the key the signature verifies against (TOFU)
  joiner_pq_sig_public_key?: string;  // base64(ML-DSA-87 pubkey); present iff hybrid. Bound by the classical sig (anti-swap). OMITTED when absent (canonical rejects null).
  joiner_pq_kem_public_key?: string;  // base64(ML-KEM-1024 pubkey, 1568B); §5 canonical-fp binding — with sign‖enc‖sig the verifier recomputes the 64-hex canonical id. OMITTED when absent (canonical rejects null).
  joiner_display_name: string;        // self-asserted (KNOWN = unverified, so a self-asserted name is the correct trust level)
  giver_fingerprint: string;          // the giver this response is FOR — binds it so a copied blob can't be replayed to another giver's mailbox
  invite_nonce: string;               // the giver's relay code the joiner used — proves the joiner used THIS giver's invite (anti-unsolicited); single-use, giver-side
  ts: string;                         // ISO-8601 UTC — audit/display only
}

/**
 * R1 remote mutual-VOUCH envelope (TRUSTED tier). Once a party has VERIFIED a KNOWN contact
 * out-of-band (KNOWN→VERIFIED is the receiver's LOCAL flag, no crypto — the key is already bound),
 * they may VOUCH: sign "I, voucher, have verified vouchee" and deposit it (encrypted) to the vouchee's
 * mailbox. When BOTH sides have vouched, the edge is TRUSTED (VERIFIED + MUTUAL).
 * Unlike the joiner-response this is NOT TOFU — the vouchee already holds the voucher's key (a
 * KNOWN/VERIFIED contact), so the vouch verifies against that HELD key. `vouchee_fingerprint` binds
 * the vouch to its intended recipient (no replay to a third party). In-person mutual QR/NFC grants
 * TRUSTED atomically and needs no wire; this is the REMOTE path.
 */
export interface MutualVouchEnvelope {
  voucher_fingerprint: string;   // who is vouching (the sender) — the vouchee already holds this key
  vouchee_fingerprint: string;   // who is being vouched for (= the recipient's own fp) — binds the recipient
  ts: string;                    // ISO-8601 UTC — audit/display only
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
  // §5 canonical-fp binding: the claimant's PQ PUBLIC keys, so a 64-hex canonical fingerprint recomputes
  // SHA256(sign‖enc‖kem‖sig) and matches. EXCLUDED from slugClaimSigningInput (below) — they bind via the
  // fp-match, NOT the signature, so the byte-exact input the LIVE Python satellite verifies is UNCHANGED.
  // Absent for a classical (40-hex OpenPGP) claim → the OpenPGP-fp path. OMITTED when absent (canonical rejects null).
  pq_kem_public_key?: string; // base64(ML-KEM-1024 pubkey, 1568B)
  pq_sig_public_key?: string; // base64(ML-DSA-87 pubkey, 2592B)
}

/**
 * Identity-exchange card (the QR/relay/copy-link payload). SIGNED so a receiver can re-verify
 * the pq keys were not swapped on an untrusted carrier — the signature binds `pq_kem_public_key`
 * (+ `pq_sig_public_key`) to the classical key that hashes to `identity.fingerprint` (Invariant-1).
 * Shape is byte-exact per the (A) crypto spec (§3);
 * `signature`/`pq_signature` attach TOP-LEVEL (canonical exclude is top-level-only) and live on
 * SignedIdentityCard in identity-card-sign.ts, NOT here.
 */
export interface IdentityCard {
  version: string;                  // '1.1' once next_authority_commitment is on the card; '1.0' legacy
  type: string;                     // 'identity-exchange'
  created_at: string;               // ISO-8601 UTC
  identity: {
    fingerprint: string;            // = H(public_key), Invariant-1
    display_name: string;
    public_key: string;             // classical (PGP armored)
    email: string;
    pq_sig_public_key: string;      // base64(ML-DSA pubkey)
    pq_kem_public_key: string;      // base64(ML-KEM pubkey) — the field the signature protects
    next_authority_commitment: string; // 64-hex authority pin; '' for pre-mint/legacy cards
  };
}

// --- Canonical signing inputs (the signing layer prefixes LP(domain)‖LP(suite_id) then signs) ---

/** Canonical bytes for a contact.update signature (excludes any attached `signature`). */
export function contactUpdateSigningInput(env: ContactUpdateEnvelope): string {
  return canonicalize(env, { exclude: ['signature'] });
}

/** Canonical bytes for an F6 slug-claim signature. Excludes the §5 PQ pubkeys so the signed byte-vector
 *  the LIVE Python satellite verifies stays UNCHANGED (they bind via the fp-match, not the signature);
 *  'signature' is a top-level attachment on SignedSlugClaim. */
export function slugClaimSigningInput(claim: SlugClaim): string {
  return canonicalize(claim, { exclude: ['signature', 'pq_kem_public_key', 'pq_sig_public_key'] });
}

/** Canonical bytes for a joiner-response signature (excludes any attached `signature`). */
export function joinerResponseSigningInput(env: JoinerResponseEnvelope): string {
  return canonicalize(env, { exclude: ['signature'] });
}

/** Canonical bytes for a mutual-vouch signature (excludes any attached `signature`). */
export function mutualVouchSigningInput(env: MutualVouchEnvelope): string {
  return canonicalize(env, { exclude: ['signature'] });
}

/**
 * Canonical bytes for an identity-card signature. Excludes BOTH top-level signature fields
 * (`signature` classical + `pq_signature` hybrid) — the signer signs the card without them, and
 * canonical's exclude is top-level-only so `identity.*` (incl. both pq keys) stays covered.
 * Sign and verify BOTH call this single-source helper → byte-exact by construction.
 */
export function identityCardSigningInput(card: IdentityCard): string {
  return canonicalize(card, { exclude: ['signature', 'pq_signature'] });
}

/** Fields the rotation-authority hybrid signature covers. Single-source with the verifier. */
export interface RotationSigningFields {
  durable_id: string;
  prior_epoch: number;
  prior_authority_commitment: string;
  successor_epoch: number;
  new_fingerprint: string;
  next_authority_commitment: string;
}

/**
 * Canonical bytes for a rotation-authority signature. identityCardSigningInput is unchanged —
 * next_authority_commitment on the card is covered by canonicalize (not excluded). This helper is
 * the GENERIC successor signing-input (authority domain), not the card domain.
 */
export function rotationSigningInput(fields: RotationSigningFields): string {
  return canonicalize(fields);
}
