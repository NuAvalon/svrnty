// src/lib/trust/introduction.ts
// Introduce (3-party, KNOW-layer) — #173519. An INTRODUCER already in the recipient's KNOW set brings a
// NEWCOMER into the recipient's book. The newcomer becomes KNOWN (self-asserted TOFU), NOT trusted —
// "introduce has nothing to do with trust" (Peter #174972). `introduced_by` is historical provenance, never
// a live dependency: once the recipient accepts, removing the introducer does NOT eject the newcomer.
//
// WHY TWO SIGNATURES (the survivor-safety crux, S1). An introduction is only valid if BOTH:
//   (a) the INTRODUCER signs the envelope (DOMAIN_INTRODUCTION) — "I am introducing N to R", verified
//       against the introducer's HELD key (the recipient already knows the introducer; not TOFU), and
//   (b) the NEWCOMER signs a recipient-SCOPED consent token (DOMAIN_INTRODUCTION_CONSENT) — "I consent to
//       being introduced to R by this introducer." The token names recipient_fingerprint, so a consent
//       harvested once can't be sprayed into other graphs.
// Without the newcomer's consent, an abuser cannot push a survivor's card into a stranger's book. The
// consent verifies against the newcomer's own key (the one that hashes to introduced_fingerprint, Invariant-1).
//
// SOLICITED-GATE = KNOW-SET MEMBERSHIP (not trust). The recipient accepts an introduction ONLY from an
// introducer currently in its KNOW set (the `introducerLookup` oracle — which also hands back the held key
// to verify against). This is the Introduce analog of joiner-response's invite-nonce gate. It applies to a
// PENDING introduction: an intro from an introducer the recipient has since dropped simply fails this gate
// and is dismissed — it never ejects an already-accepted contact (Fork 1 = weak, Peter #174972).
//
// CORRECT-BY-CONSTRUCTION. Mirrors joiner-response.ts: the same domain-separated envelope sign/verify, the
// single-source signing-input helpers (introductionSigningInput / introductionConsentSigningInput — byte-drift
// impossible), the shared Invariant-1 fingerprintMatchesKey, and the classical-OpenPGP E2E to the recipient
// (relay-opaque, recipient-only decrypt). Two domain tags → an introduction signature can never verify as a
// joiner-response / contact-update / consent, and vice-versa.
//
// FAIL-CLOSED / SILENT-DROP (I-1/I-2). verifyIntroduction returns PendingIntroduction | null and NEVER throws:
// the mailbox is an open channel carrying other envelope types and noise, so a non-matching / malformed /
// wrong-recipient blob drops silently (no reason leak, no crash on garbage). Build-side helpers throw loudly
// (the sender controls their own inputs). `introducerLookup` is a REQUIRED argument → the know-set gate cannot
// be skipped by an eager caller.

import {
  DOMAIN_INTRODUCTION,
  DOMAIN_INTRODUCTION_CONSENT,
  introductionSigningInput,
  introductionConsentSigningInput,
  type IntroductionConsent,
  type IntroductionEnvelope,
} from '../format/envelope';
import { signWithEnvelope, verifyWithEnvelope, type EnvelopeSignature } from '../crypto/sign-envelope';
import { fingerprintMatchesKey, KEM_PUB_LEN } from '../identity/fingerprint';
import { base64ToUint8 } from '../crypto/pq';
import {
  sealLivingBookHybrid,
  openLivingBookHybrid,
  resolveHybrid,
  type HybridSecretsSource,
} from '../crypto/living-book-sleeve';
import { asMailboxEnvelopePackage } from '../sync/hybrid-dual-read';

/** The wire artifact: the introducer's envelope + BOTH signatures (introducer over the envelope, newcomer
 *  over the consent token). Opaque once encrypted to the recipient. */
export interface SignedIntroduction {
  envelope: IntroductionEnvelope;
  signature: EnvelopeSignature;          // by the INTRODUCER, over introductionSigningInput(envelope)
  consent_signature: EnvelopeSignature;  // by the NEWCOMER, over introductionConsentSigningInput(envelope.consent)
}

/**
 * The verified newcomer surfaced to the recipient as a PENDING KNOWN introduction. Shaped to seed a contact
 * record + a `pending_intro` (introduced_by = the introducer, historical provenance). `trusted` is NOT set —
 * introduce is KNOW-layer only.
 */
export interface PendingIntroduction {
  fingerprint: string;              // the newcomer's fingerprint
  publicKeyArmored: string;
  pqSigningPublicKey?: Uint8Array;
  pqKemPublicKey?: Uint8Array;
  displayName: string;
  /** Historical provenance for the `pending_intro` edge — who introduced them. NOT a live dependency. */
  introducedByFingerprint: string;
  context: string;
  nonce: string;
  ts: string;
}

/** Thrown at BUILD time (send side) for a structurally invalid introduction — fail loud for the sender. */
export class IntroductionSignError extends Error {
  constructor(
    public readonly reason:
      | 'bad-introducer-fingerprint'
      | 'bad-recipient-fingerprint'
      | 'bad-introduced-fingerprint'
      | 'bad-introduced-public-key'
      | 'bad-introduced-name'
      | 'bad-context'
      | 'bad-nonce'
      | 'bad-ts'
      | 'bad-pq-key'
      | 'consent-mismatch',
    detail?: string,
  ) {
    super(detail ? `introduction build refused (${reason}): ${detail}` : `introduction build refused (${reason})`);
    this.name = 'IntroductionSignError';
  }
}

function isNonEmptyString(v: unknown): v is string {
  return typeof v === 'string' && v.length > 0;
}
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

// ─────────────────────────── NEWCOMER side: build + sign the consent token ───────────────────────────

export interface BuildConsentArgs {
  introducedFp: string;   // the newcomer's own durable fingerprint (= H(their public key))
  introducerFp: string;   // the introducer they consent to be introduced BY
  recipientFp: string;    // the recipient they consent to be introduced TO (scopes the consent)
  displayName: string;    // the NAME they consent to be introduced UNDER (Flint S1 — deadname/survivor-safety); may be empty
  nonce: string;          // binds this introduction instance
  ts?: string;            // ISO-8601 UTC; inject for deterministic tests
}

/** Build the recipient-scoped consent token (structural guarantees). Done on the NEWCOMER's device. */
export function buildIntroductionConsent(args: BuildConsentArgs): IntroductionConsent {
  if (!isNonEmptyString(args.introducedFp)) throw new IntroductionSignError('bad-introduced-fingerprint');
  if (!isNonEmptyString(args.introducerFp)) throw new IntroductionSignError('bad-introducer-fingerprint');
  if (!isNonEmptyString(args.recipientFp)) throw new IntroductionSignError('bad-recipient-fingerprint');
  if (typeof args.displayName !== 'string') throw new IntroductionSignError('bad-introduced-name', 'consent display_name');
  if (!isNonEmptyString(args.nonce)) throw new IntroductionSignError('bad-nonce');
  return {
    introduced_fingerprint: args.introducedFp,
    introducer_fingerprint: args.introducerFp,
    recipient_fingerprint: args.recipientFp,
    display_name: args.displayName,
    nonce: args.nonce,
    ts: args.ts ?? new Date().toISOString(),
  };
}

/** Sign a consent token (DOMAIN_INTRODUCTION_CONSENT) with the NEWCOMER's key. Hybrid iff a PQ secret given. */
export async function signIntroductionConsent(
  consent: IntroductionConsent,
  introducedPrivateKeyArmored: string,
  passphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<EnvelopeSignature> {
  return signWithEnvelope(
    DOMAIN_INTRODUCTION_CONSENT,
    introductionConsentSigningInput(consent),
    introducedPrivateKeyArmored,
    passphrase,
    pqSigningSecretKey,
  );
}

// ─────────────────────────── INTRODUCER side: build + sign the introduction ───────────────────────────

export interface BuildIntroductionArgs {
  introducerFp: string;
  recipientFp: string;
  /** The newcomer's self-asserted card. */
  introducedFp: string;
  introducedPubKeyArmored: string;
  introducedPqSigPublicKey?: string;  // base64(ML-DSA-87)
  introducedPqKemPublicKey?: string;  // base64(ML-KEM-1024, 1568B)
  introducedName: string;             // may be empty (KNOWN = unverified)
  /** The newcomer's signed, recipient-scoped consent (token + the newcomer's signature over it). */
  consent: IntroductionConsent;
  consentSignature: EnvelopeSignature;
  context: string;                    // may be empty
  ts?: string;
}

/** Build the introduction envelope, enforcing the structural + consent-binding rules the verifier relies on. */
export function buildIntroductionEnvelope(args: BuildIntroductionArgs): IntroductionEnvelope {
  if (!isNonEmptyString(args.introducerFp)) throw new IntroductionSignError('bad-introducer-fingerprint');
  if (!isNonEmptyString(args.recipientFp)) throw new IntroductionSignError('bad-recipient-fingerprint');
  if (!isNonEmptyString(args.introducedFp)) throw new IntroductionSignError('bad-introduced-fingerprint');
  if (!isNonEmptyString(args.introducedPubKeyArmored)) throw new IntroductionSignError('bad-introduced-public-key');
  if (typeof args.introducedName !== 'string') throw new IntroductionSignError('bad-introduced-name');
  if (typeof args.context !== 'string') throw new IntroductionSignError('bad-context');
  if (args.introducedPqSigPublicKey !== undefined && !isNonEmptyString(args.introducedPqSigPublicKey))
    throw new IntroductionSignError('bad-pq-key', 'sig present but empty');
  if (args.introducedPqKemPublicKey !== undefined && !isNonEmptyString(args.introducedPqKemPublicKey))
    throw new IntroductionSignError('bad-pq-key', 'kem present but empty');

  // Consent-binding: the token the introducer forwards MUST name this exact (introduced, introducer, recipient)
  // triple, or the introducer is forwarding a consent for a different introduction (refuse loudly).
  const c = args.consent;
  if (!isPlainObject(c)) throw new IntroductionSignError('consent-mismatch', 'consent not an object');
  if (c.introduced_fingerprint !== args.introducedFp) throw new IntroductionSignError('consent-mismatch', 'introduced fp');
  if (c.introducer_fingerprint !== args.introducerFp) throw new IntroductionSignError('consent-mismatch', 'introducer fp');
  if (c.recipient_fingerprint !== args.recipientFp) throw new IntroductionSignError('consent-mismatch', 'recipient fp');
  // S1 (Flint #175185): the card's display_name MUST equal the name the newcomer signed consent for —
  // the introducer cannot introduce them under a different/deadname than they consented to.
  if (c.display_name !== args.introducedName) throw new IntroductionSignError('consent-mismatch', 'display_name');
  if (!isNonEmptyString(c.nonce)) throw new IntroductionSignError('bad-nonce', 'consent nonce');

  const env: IntroductionEnvelope = {
    introducer_fingerprint: args.introducerFp,
    recipient_fingerprint: args.recipientFp,
    introduced_fingerprint: args.introducedFp,
    introduced_public_key: args.introducedPubKeyArmored,
    introduced_display_name: args.introducedName,
    consent: c,
    context: args.context,
    nonce: c.nonce, // bound to the consent token's nonce
    ts: args.ts ?? new Date().toISOString(),
  };
  if (args.introducedPqSigPublicKey !== undefined) env.introduced_pq_sig_public_key = args.introducedPqSigPublicKey;
  if (args.introducedPqKemPublicKey !== undefined) env.introduced_pq_kem_public_key = args.introducedPqKemPublicKey;
  return env;
}

/** Common send path: build the envelope + sign it with the INTRODUCER's key → SignedIntroduction. */
export async function buildSignedIntroduction(
  args: BuildIntroductionArgs,
  introducerPrivateKeyArmored: string,
  passphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<SignedIntroduction> {
  const envelope = buildIntroductionEnvelope(args);
  const signature = await signWithEnvelope(
    DOMAIN_INTRODUCTION,
    introductionSigningInput(envelope),
    introducerPrivateKeyArmored,
    passphrase,
    pqSigningSecretKey,
  );
  return { envelope, signature, consent_signature: args.consentSignature };
}

/** Encrypt a signed introduction to the RECIPIENT's public key → opaque armored blob (relay stores opaquely). */
export async function encryptIntroductionTo(
  signed: SignedIntroduction,
  recipientPublicKeyArmored: string,
  recipientPqKemB64?: string,
): Promise<string> {
  // HYBRID ONLY (HNDL), the same rule as every other deposit since #310: wraps the ALREADY-SIGNED introduction with the recipient's ML-KEM-1024
  // pubkey. Without that key this THROWS (like sealNoteTo / encryptJoinerResponseTo): the send-site skips a recipient with no pq_kem, so this is
  // the loud backstop for a caller bug, never a silent classical send. (P1 was written 10-19 as OpenPGP-only; it was never deployed.)
  if (!recipientPqKemB64) {
    throw new Error('encryptIntroductionTo: refusing to seal without the recipient ML-KEM key (no classical downgrade)');
  }
  return sealLivingBookHybrid(new TextEncoder().encode(JSON.stringify(signed)), recipientPublicKeyArmored, recipientPqKemB64);
}

// ─────────────────────────── RECIPIENT side: verify ───────────────────────────

/** Narrow structural check BEFORE any field/crypto logic — demultiplexes a mixed mailbox (a joiner-response
 *  / contact-update / noise blob structurally mismatches here → the caller's null). */
function isWellFormed(signed: unknown): signed is SignedIntroduction {
  if (!isPlainObject(signed)) return false;
  const { envelope, signature, consent_signature } = signed as Record<string, unknown>;
  if (!isPlainObject(envelope) || !isPlainObject(signature) || !isPlainObject(consent_signature)) return false;
  if (typeof (signature as Record<string, unknown>).classical !== 'string') return false;
  if (typeof (consent_signature as Record<string, unknown>).classical !== 'string') return false;
  const e = envelope as Record<string, unknown>;
  if (!isNonEmptyString(e.introducer_fingerprint)) return false;
  if (!isNonEmptyString(e.recipient_fingerprint)) return false;
  if (!isNonEmptyString(e.introduced_fingerprint)) return false;
  if (!isNonEmptyString(e.introduced_public_key)) return false;
  if (typeof e.introduced_display_name !== 'string') return false;
  if (typeof e.context !== 'string') return false;
  if (!isNonEmptyString(e.nonce)) return false;
  if (typeof e.ts !== 'string') return false;
  if (e.introduced_pq_sig_public_key !== undefined && !isNonEmptyString(e.introduced_pq_sig_public_key)) return false;
  if (e.introduced_pq_kem_public_key !== undefined) {
    if (!isNonEmptyString(e.introduced_pq_kem_public_key)) return false;
    try {
      if (atob(e.introduced_pq_kem_public_key as string).length !== KEM_PUB_LEN) return false;
    } catch {
      return false;
    }
  }
  // Consent token shape.
  const c = e.consent;
  if (!isPlainObject(c)) return false;
  const cc = c as Record<string, unknown>;
  if (!isNonEmptyString(cc.introduced_fingerprint)) return false;
  if (!isNonEmptyString(cc.introducer_fingerprint)) return false;
  if (!isNonEmptyString(cc.recipient_fingerprint)) return false;
  if (typeof cc.display_name !== 'string') return false; // S1: present (may be empty); bound by the newcomer's sig
  if (!isNonEmptyString(cc.nonce)) return false;
  if (typeof cc.ts !== 'string') return false;
  return true;
}

async function decryptIntroBlob(
  blob: string,
  hybrid: HybridSecretsSource | undefined,
  onOpenLeg?: (leg: 'hybrid') => void,
): Promise<SignedIntroduction | null> {
  // HYBRID ONLY: there are no classical-era introductions to keep reading (this wire never shipped), so a blob that is not a hybrid package,
  // or a recipient with no derivable hybrid secrets, is a silent null, never a fallback to an OpenPGP leg.
  if (!hybrid || asMailboxEnvelopePackage(blob) == null) return null;
  try {
    const h = await resolveHybrid(hybrid);
    const pt = h ? await openLivingBookHybrid(blob, h.secrets, h.myFp) : null;
    if (!pt) return null;
    const parsed = JSON.parse(new TextDecoder().decode(pt)) as unknown;
    if (!isWellFormed(parsed)) return null;
    try {
      onOpenLeg?.('hybrid');
    } catch {
      /* a counter fault must never change what opens */
    }
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Verify an inbound introduction → the KNOWN newcomer, or null (silent drop). THE ONLY WAY to obtain a
 * {@link PendingIntroduction}. Order is cheap→crypto for DoS resistance (the mailbox is open — garbage must
 * not burn signature CPU):
 *   1. open the hybrid package with our mailbox secrets (else null; there is no classical leg); 2. structural well-formedness (in decrypt);
 *   3. recipient-binding: envelope.recipient_fingerprint === our own fp  [cheap] (no replay to another recipient)
 *   4. KNOW-SET gate: introducerLookup(introducer_fp) → the HELD introducer key, or null if not in our know-set [cheap]
 *   5. consent cross-binding: the consent token names EXACTLY (introduced, introducer, recipient=us) + nonce===envelope.nonce [cheap]
 *   6. Invariant-1: fingerprintMatchesKey(introduced_fp, introduced_public_key, pq)  [medium]
 *   7. INTRODUCER signature (DOMAIN_INTRODUCTION) vs the HELD introducer key  [expensive]
 *   8. NEWCOMER consent signature (DOMAIN_INTRODUCTION_CONSENT) vs introduced_public_key (TOFU, self-consistent per step 6) [expensive]
 * Steps 3–5 read the not-yet-sig-verified envelope as a cheap pre-filter; steps 7–8 then confirm every field
 * was signed, so a tampered recipient/introducer/consent fails.
 *
 * ANTI-REPLAY is the caller's to complete: after a non-null return, record (result.nonce, result.fingerprint)
 * so a replayed blob is dropped. The know-set gate also means an intro from a since-dropped introducer fails
 * at step 4 (pending dismissal) — it never touches an already-accepted contact.
 *
 * @param introducerLookup REQUIRED. `(introducerFp) => {publicKeyArmored, pqSigningPublicKey?} | null`: the
 *   HELD key for an introducer that is CURRENTLY in our KNOW set, or null to reject. Required (not optional)
 *   so the know-set gate can never be skipped.
 */
export async function verifyIntroduction(
  blob: string,
  recipient: { fingerprint: string; hybrid?: HybridSecretsSource; onOpenLeg?: (leg: 'hybrid') => void },
  introducerLookup: (introducerFp: string) => { publicKeyArmored: string; pqSigningPublicKey?: Uint8Array } | null,
  opts: { requirePq?: boolean } = {},
): Promise<PendingIntroduction | null> {
  const signed = await decryptIntroBlob(blob, recipient.hybrid, recipient.onOpenLeg);
  if (!signed) return null;
  const { envelope, signature, consent_signature } = signed;

  // 3) Recipient-binding — the introduction must be addressed to US.
  if (envelope.recipient_fingerprint.toUpperCase() !== recipient.fingerprint.toUpperCase()) return null;

  // 4) Know-set gate — the introducer must currently be in OUR know set; the oracle hands back their held key.
  let introducerKey: { publicKeyArmored: string; pqSigningPublicKey?: Uint8Array } | null = null;
  try {
    introducerKey = introducerLookup(envelope.introducer_fingerprint);
  } catch {
    return null; // a throwing oracle is treated as reject (fail-closed)
  }
  if (!introducerKey || !isNonEmptyString(introducerKey.publicKeyArmored)) return null;

  // 5) Consent cross-binding — the newcomer's consent must name this exact triple + bind our fp + match the nonce.
  const c = envelope.consent;
  if (c.introduced_fingerprint !== envelope.introduced_fingerprint) return null;
  if (c.introducer_fingerprint !== envelope.introducer_fingerprint) return null;
  if (c.recipient_fingerprint.toUpperCase() !== recipient.fingerprint.toUpperCase()) return null;
  if (c.nonce !== envelope.nonce) return null;
  // S1 (Flint #175185): the displayed name must be EXACTLY the one the newcomer signed consent for —
  // reject a card that renames them (deadname/survivor-safety). This is NOT a fast-fail duplicate of the signatures: a hostile INTRODUCER
  // can sign an envelope that says "Deadname" while carrying the newcomer's genuine consent for "Newt". Both signatures then verify, and
  // this cross-check is the only thing that stops it (Flint #2685: pinned by a test that re-signs the hostile envelope).
  if (c.display_name !== envelope.introduced_display_name) return null;

  // 6) Invariant-1 — the newcomer's self-asserted fp must hash to the presented key (canonical recompute if PQ). Also load-bearing against a
  //    hostile introducer: it can sign introduced_fingerprint = a VICTIM's fp with the ATTACKER's key and a consent the attacker signs with that same
  //    key; both signatures verify and only this check refuses to bind the victim's fp to the attacker's key (Flint #2685).
  if (!(await fingerprintMatchesKey(envelope.introduced_fingerprint, envelope.introduced_public_key, {
    kem_public_key: envelope.introduced_pq_kem_public_key,
    sig_public_key: envelope.introduced_pq_sig_public_key,
  }))) return null;

  // Suite floor (both signatures) — reject classical-only if PQ required.
  if (opts.requirePq && (!signature.pq_signature || !consent_signature.pq_signature)) return null;

  // 7) INTRODUCER signature over the envelope, vs the HELD introducer key (verified, not TOFU).
  let introducerOk = false;
  try {
    introducerOk = await verifyWithEnvelope(
      DOMAIN_INTRODUCTION,
      introductionSigningInput(envelope),
      signature,
      introducerKey.publicKeyArmored,
      introducerKey.pqSigningPublicKey,
    );
  } catch {
    return null;
  }
  if (!introducerOk) return null;

  // 8) NEWCOMER consent signature over the consent token, vs introduced_public_key (self-consistent per step 6).
  let pqSigningPublicKey: Uint8Array | undefined;
  if (envelope.introduced_pq_sig_public_key !== undefined) {
    try {
      pqSigningPublicKey = base64ToUint8(envelope.introduced_pq_sig_public_key);
    } catch {
      return null;
    }
  }
  if (consent_signature.pq_signature && !pqSigningPublicKey) return null; // hybrid sig w/ no PQ key → fail closed

  let consentOk = false;
  try {
    consentOk = await verifyWithEnvelope(
      DOMAIN_INTRODUCTION_CONSENT,
      introductionConsentSigningInput(c),
      consent_signature,
      envelope.introduced_public_key,
      pqSigningPublicKey,
    );
  } catch {
    return null;
  }
  if (!consentOk) return null;

  let pqKemPublicKey: Uint8Array | undefined;
  if (envelope.introduced_pq_kem_public_key !== undefined) {
    try {
      pqKemPublicKey = base64ToUint8(envelope.introduced_pq_kem_public_key);
    } catch {
      return null;
    }
  }

  return {
    fingerprint: envelope.introduced_fingerprint,
    publicKeyArmored: envelope.introduced_public_key,
    ...(pqSigningPublicKey ? { pqSigningPublicKey } : {}),
    ...(pqKemPublicKey ? { pqKemPublicKey } : {}),
    displayName: envelope.introduced_display_name,
    introducedByFingerprint: envelope.introducer_fingerprint,
    context: envelope.context,
    nonce: envelope.nonce,
    ts: envelope.ts,
  };
}
