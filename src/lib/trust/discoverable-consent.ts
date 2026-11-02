// src/lib/trust/discoverable-consent.ts
//
// Trust-PSI increment #2 (true-3-way, the C3 consent — Peter #172418, Flint #172667).
//
// The THIRD consent of the trust-PSI reveal: the REVEALED party's OWN "discoverable as trusted"
// willingness. The reveal "Alice & Bob both trust Carol" fires ONLY when all three consented —
// (C1) Alice opted Carol into trust_visibility, (C2) Bob did, AND (C3) Carol HERSELF published a
// signed "I'm discoverable as trusted." This module is C3: the signed object + sign + verify + the
// edge-store apply sink. C1/C2 live on the truster side (getTrustVisiblePeers, increment #1 @e89c1d4).
//
// ANTI-FORGE (Flint #172553/#172667): the flag on a truster's edge becomes true ONLY from the
// subject's GENUINELY SIGNED own opt-in. The truster verifies the consent signature against the
// subject's pubkeys IT ALREADY STORED (from adding the subject) → an attacker lacks the subject's
// private key, so it can't produce a consent that verifies as the subject, so it can't set the
// subject's flag on anyone's edge. No valid sig ⇒ flag stays false (fail-closed). (An attacker CAN
// sign its OWN willingness — that's correct; it still needs the trusters' independent per-contact
// opt-ins to be revealed.) Revocation = a higher-epoch signed {discoverable:false} supersedes.
//
// CANONICAL SIGNING-INPUT (Flint's lane, #172667 — injective, no raw-delimiter/pipe-canon trap):
//   preimage = u8(ver=1) ‖ u8(scope_tag) ‖ LP(scope_value) ‖ LP(subject_fp) ‖ u64be(epoch) ‖ u8(discoverable)
//   LP(x) = u32be(len) ‖ x  (length-prefixed ⇒ injective field boundaries)
// The preimage is hex-encoded to an ASCII string for signWithEnvelope (string signer); cross-TYPE
// separation + anti-downgrade come from buildSignedBytes = LP(domain) ‖ LP(suite) ‖ canonical_input
// (sign-envelope.ts already length-prefixes domain AND suite — Flint's injective-domain check: PASSES).
//
// SCOPE: GLOBAL v1 only (scope_tag=0x00, scope_value=''). subject_fp is the signer (the subject is a
// property of themselves; they may not even know who trusts them). Per-truster (scope_tag=0x01) is
// RESERVED for a future variant — v1 apply REJECTS any non-global scope (fail-closed, forward-safe).

import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { fromBase64 } from '../crypto/kdf';
import {
  signWithEnvelope,
  verifyWithEnvelope,
  type EnvelopeSignature,
} from '../crypto/sign-envelope';

/** Envelope domain tag (Flint #172667) — gives cross-TYPE replay separation (can't replay as a card/vouch/receipt). */
export const DOMAIN_DISCOVERABLE_CONSENT = 'svrnty:discoverable-consent:v1';

/** scope_tag values. v1 supports GLOBAL only; PER_TRUSTER is reserved (forward-compatible preimage slot). */
export const CONSENT_SCOPE_GLOBAL = 0x00;
export const CONSENT_SCOPE_PER_TRUSTER = 0x01; // reserved — NOT supported by v1 apply (fail-closed)

export interface DiscoverableConsent {
  /** The subject = the signer. For v1 global this is the only identity in the preimage. */
  subject_fp: string;
  /** Monotonic counter; a strictly-greater epoch supersedes (revocable-propagate). */
  epoch: number;
  /** true = opt-in (0x01); false = revoke (0x00). */
  discoverable: boolean;
  /** 0x00 global (v1). */
  scope_tag: number;
  /** '' for global. */
  scope_value: string;
}

export interface SignedDiscoverableConsent extends DiscoverableConsent {
  sig: EnvelopeSignature;
}

// ── canonical signing-input (Flint #172667) ─────────────────────────────────────────────────────

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false); // big-endian
  return b;
}
function u64be(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false); // big-endian
  return b;
}
/** Injective length prefix: u32be(len) ‖ bytes. */
function lp(bytes: Uint8Array): Uint8Array {
  return concatBytes(u32be(bytes.length), bytes);
}

/**
 * The canonical input passed to signWithEnvelope — Flint's exact injective binary framing,
 * hex-encoded to an ASCII string. Injective: fixed-width + length-prefixed fields can't collide
 * across boundaries (e.g. subject_fp='ab'+scope_value='c' ≠ subject_fp='a'+scope_value='bc').
 */
export function discoverableConsentInput(c: DiscoverableConsent): string {
  const preimage = concatBytes(
    Uint8Array.of(1), // u8 ver=1
    Uint8Array.of(c.scope_tag & 0xff), // u8 scope_tag
    lp(utf8ToBytes(c.scope_value)), // LP(scope_value)
    lp(utf8ToBytes(c.subject_fp)), // LP(subject_fp)
    u64be(c.epoch), // u64be epoch
    Uint8Array.of(c.discoverable ? 0x01 : 0x00), // u8 discoverable
  );
  return bytesToHex(preimage);
}

// ── sign (subject's device) / verify (truster's device) ──────────────────────────────────────────

/** Sign a DiscoverableConsent (the subject signs their OWN willingness). Hybrid when a PQ secret is supplied. */
export async function signDiscoverableConsent(
  consent: DiscoverableConsent,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<SignedDiscoverableConsent> {
  const sig = await signWithEnvelope(
    DOMAIN_DISCOVERABLE_CONSENT,
    discoverableConsentInput(consent),
    classicalPrivateKeyArmored,
    classicalPassphrase,
    pqSigningSecretKey,
  );
  return { ...consent, sig };
}

/**
 * Verify a signed consent against the SUBJECT's pubkeys. Returns true ONLY if the signature genuinely
 * binds to the subject's key (anti-forge). The suite (classical/hybrid) auto-binds via the envelope.
 */
export async function verifyDiscoverableConsent(
  signed: SignedDiscoverableConsent,
  subjectClassicalPublicKeyArmored: string,
  subjectPqSigPublicKey?: Uint8Array,
): Promise<boolean> {
  const { sig, ...consent } = signed;
  return verifyWithEnvelope(
    DOMAIN_DISCOVERABLE_CONSENT,
    discoverableConsentInput(consent),
    sig,
    subjectClassicalPublicKeyArmored,
    subjectPqSigPublicKey,
  );
}

// ── edge-store apply (the sink Athena's consume-mailbox routes to) ────────────────────────────────

/** Minimal contact shape the apply reads — the subject's stored pubkeys (for anti-forge verify) + metadata. */
export interface DiscoverableConsentContact {
  id: string;
  fingerprint: string;
  public_key: string;
  pq_sig_public_key?: string;
  metadata?: Record<string, unknown> | null;
}

/** Minimal store the apply needs. The real client-store satisfies this (getContactByFingerprint/updateContact). */
export interface DiscoverableConsentStore {
  getContactByFingerprint(fingerprint: string): Promise<DiscoverableConsentContact | null>;
  updateContact(id: string, updates: { metadata?: Record<string, unknown> }): Promise<void>;
}

export type ApplyConsentResult =
  | 'applied'
  | 'rejected-no-contact'
  | 'rejected-unsupported-scope'
  | 'rejected-sig'
  | 'rejected-stale';

/** The metadata keys the flag + its supersede-epoch live under (projected to the edge by contact-edge.ts). */
export const DISCOVERABLE_FLAG_KEY = 'peer_discoverable_as_trusted';
export const DISCOVERABLE_EPOCH_KEY = 'peer_discoverable_as_trusted_epoch';

/**
 * Verify-before-set apply. Fail-closed at every step; writes the subject's edge flag ONLY on a
 * genuinely-signed, in-scope, strictly-newer consent. (Athena's consume-mailbox route calls this with
 * the real client-store; satellite stays blind — all verification is client-side.)
 */
export async function applyDiscoverableConsent(
  signed: SignedDiscoverableConsent,
  store: DiscoverableConsentStore,
): Promise<ApplyConsentResult> {
  // v1 supports GLOBAL scope only. A per-truster (or unknown) scope is REJECTED — never mis-applied.
  if (signed.scope_tag !== CONSENT_SCOPE_GLOBAL) return 'rejected-unsupported-scope';

  // Never materialize a flag for a non-contact (mirror applyMutualResult's fail-closed boundary).
  const contact = await store.getContactByFingerprint(signed.subject_fp);
  if (!contact || contact.fingerprint !== signed.subject_fp) return 'rejected-no-contact';

  // Anti-forge: verify against the subject's STORED pubkeys. An attacker lacks the subject's key.
  const pqPub =
    signed.sig.pq_signature && contact.pq_sig_public_key
      ? fromBase64(contact.pq_sig_public_key)
      : undefined;
  const ok = await verifyDiscoverableConsent(signed, contact.public_key, pqPub);
  if (!ok) return 'rejected-sig'; // fail-closed — NO write

  // Monotonic epoch (supersede): strictly-greater wins; <= is stale/replayed → drop (no write).
  const md = contact.metadata ?? {};
  const storedEpoch =
    typeof md[DISCOVERABLE_EPOCH_KEY] === 'number' ? (md[DISCOVERABLE_EPOCH_KEY] as number) : -1;
  if (signed.epoch <= storedEpoch) return 'rejected-stale';

  await store.updateContact(contact.id, {
    metadata: {
      ...md,
      [DISCOVERABLE_FLAG_KEY]: signed.discoverable,
      [DISCOVERABLE_EPOCH_KEY]: signed.epoch,
    },
  });
  return 'applied';
}
