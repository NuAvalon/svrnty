// src/lib/identity/introduction.ts
// Transitive INTRODUCTION — B (voucher) introduces subject A to recipient C, relaying A's SignedIdentityCard.
// Consent-model LOCKED by Archie #171921: A's consent = A-initiates the export (Nov-5 minimal; an A-signed
// authorization token is the roadmap hardening); B's vouch CLAIMS provenance-only ("B knows A / relaying A's
// card"), NEVER "B verified A"; recipient_fingerprint is bound (anti-replay). Flint co-verifies the 3 points;
// Hypatia gates the copy. This module is the CRYPTO half (build/verify + the card-relay MITM-safety assertion).
//
// WHY NO NEW CRYPTO CORE. The signature is the EXISTING sign-envelope (signWithEnvelope / verifyWithEnvelope):
//   signed = LP(DOMAIN_INTRODUCTION) ‖ LP(suite_id) ‖ canonicalize(envelope)
// — length-prefixed domain-sep (Flint point-(a): NOT a raw `|`/`:` concat; LP is injective), anti-downgrade
// suite binding (classical-only at launch, ML-DSA-ready), single-source signing-input (introductionSigningInput)
// so sign≡verify can't drift. A's identity authenticity is the EXISTING SignedIdentityCard path — self-certifying
// and CARRIER-INDEPENDENT (verifySignedIdentityCard/classifyImportedCard bind to the card's OWN key), so B
// relaying it cannot tamper a key without breaking A's signature. The introduction adds ONE signed object.
//
// ★ STRUCTURALLY TRUST-BLIND (Flint point-(c) / Hypatia #3). IntroductionEnvelope has NO trust field and this
// module grants NO trust. A successful verify yields PROVENANCE ONLY + the subject's normal card-import
// disposition; the caller routes the subject into the Grow GATE as KNOWN (never trusted, never auto-added to a
// galaxy). "B vouches" ≠ "you may trust". That guarantee lives in the mechanism here, not only in the copy.

import {
  DOMAIN_INTRODUCTION,
  introductionSigningInput,
  type IntroductionEnvelope,
} from '../format/envelope';
import { signWithEnvelope, verifyWithEnvelope, type EnvelopeSignature } from '../crypto/sign-envelope';
import {
  classifyImportedCard,
  type SignedIdentityCard,
  type ImportDisposition,
} from './identity-card-sign';

/** An introduction envelope plus B's envelope signature over it (TOP-LEVEL, like SignedIdentityCard). */
export interface SignedIntroduction extends IntroductionEnvelope {
  signature: string;      // classical (ED25519 / PGP armored)
  pq_signature?: string;  // ML-DSA-87 (hybrid — follow-up, not launch; launch signs classical-only)
}

/**
 * BUILD a signed introduction (voucher-side = B). Signs the envelope under DOMAIN_INTRODUCTION with B's
 * classical identity key; pass B's ML-DSA secret to also bind the hybrid suite (anti-downgrade). LAUNCH =
 * classical-only (omit pqSigningSecretKey), matching the identity-card launch posture. Needs B's private
 * key ⇒ the session must be unlocked; the caller loads it via loadKey() and handles the locked case.
 */
export async function buildIntroduction(
  env: IntroductionEnvelope,
  voucherClassicalPrivateKeyArmored: string,
  voucherClassicalPassphrase: string,
  voucherPqSigningSecretKey?: Uint8Array,
): Promise<SignedIntroduction> {
  if (!env?.voucher_fingerprint || !env?.subject_fingerprint || !env?.recipient_fingerprint || !env?.ts) {
    throw new Error('cannot build introduction — envelope is missing a bound field (voucher/subject/recipient/ts)');
  }
  const sig = await signWithEnvelope(
    DOMAIN_INTRODUCTION,
    introductionSigningInput(env),
    voucherClassicalPrivateKeyArmored,
    voucherClassicalPassphrase,
    voucherPqSigningSecretKey,
  );
  const signed: SignedIntroduction = { ...env, signature: sig.classical };
  if (sig.pq_signature) signed.pq_signature = sig.pq_signature;
  return signed;
}

/** Why an introduction was rejected (fail-closed; the caller shows nothing / drops silently). */
export type IntroductionRejectReason =
  | 'malformed'                  // structurally invalid intro or subject card
  | 'recipient-mismatch'         // not addressed to this recipient (replay to a third party)
  | 'subject-card-mismatch'      // the attached card is not the subject B vouched for
  | 'subject-card-invalid'       // the attached card fails its own fp↔key binding / signature
  | 'voucher-signature-invalid'; // B's signature doesn't verify against B's HELD key

export type IntroductionVerdict =
  | { ok: false; reason: IntroductionRejectReason }
  | {
      ok: true;
      /** PROVENANCE ONLY — deliberately carries NO trust. The subject is KNOWN, not trusted. */
      provenance: { introduced_by: string; subject_fingerprint: string; ts: string };
      /** The validated subject card to route into the Grow Gate (as KNOWN, with introduced_by provenance). */
      subjectCard: SignedIdentityCard;
      /** The subject card's normal fail-closed import disposition (pq / mailbox / alarm) — applied exactly
       *  as a direct card import would, so introduced contacts get no weaker (and no stronger) treatment. */
      subjectImport: ImportDisposition;
    };

/**
 * VERIFY a received introduction (recipient-side = C). Returns a fail-closed verdict; NEVER throws on
 * hostile input (the carrier controls these bytes). ALL must hold:
 *   1. structural: intro + subject card well-formed, signature present.
 *   2. recipient binding: intro.recipient_fingerprint === this recipient's OWN fp (anti cross-party replay).
 *   3. subject binding: the attached card's fingerprint === intro.subject_fingerprint (B can't swap the card).
 *   4. subject card self-validity: classifyImportedCard says the classical identity imports (fp↔key binds).
 *   5. voucher signature: verifies against B's HELD public key over the canonical envelope.
 *
 * ★ `voucherHeldPublicKeyArmored` MUST be B's key as C ALREADY HOLDS it (from C's contact record), NOT a key
 *   read off the introduction wire — otherwise a forger supplies their own key + a matching signature. This
 *   is the "you can only be introduced by someone you already know" premise; if C doesn't hold B, reject.
 */
export async function verifyIntroduction(params: {
  intro: SignedIntroduction;
  subjectCard: SignedIdentityCard;
  recipientFingerprint: string;
  voucherHeldPublicKeyArmored: string;
  voucherPqSigPublicKey?: Uint8Array;
}): Promise<IntroductionVerdict> {
  try {
    const { intro, subjectCard, recipientFingerprint, voucherHeldPublicKeyArmored, voucherPqSigPublicKey } = params;

    // (1) structural
    if (
      !intro ||
      typeof intro.voucher_fingerprint !== 'string' || intro.voucher_fingerprint.length === 0 ||
      typeof intro.subject_fingerprint !== 'string' || intro.subject_fingerprint.length === 0 ||
      typeof intro.recipient_fingerprint !== 'string' || intro.recipient_fingerprint.length === 0 ||
      typeof intro.ts !== 'string' || intro.ts.length === 0 ||
      typeof intro.signature !== 'string' || intro.signature.length === 0
    ) {
      return { ok: false, reason: 'malformed' };
    }
    const subjId = subjectCard?.identity;
    if (!subjId || typeof subjId.fingerprint !== 'string' || typeof subjId.public_key !== 'string') {
      return { ok: false, reason: 'malformed' };
    }
    if (typeof recipientFingerprint !== 'string' || recipientFingerprint.length === 0) {
      return { ok: false, reason: 'malformed' };
    }

    // (2) recipient binding — this intro must be addressed to US, not replayed from another recipient.
    if (intro.recipient_fingerprint !== recipientFingerprint) {
      return { ok: false, reason: 'recipient-mismatch' };
    }

    // (3) subject binding — the relayed card must be the exact subject B vouched for (fp is H(key[+pq])).
    if (subjId.fingerprint !== intro.subject_fingerprint) {
      return { ok: false, reason: 'subject-card-mismatch' };
    }

    // (4) subject card self-validity — A's card verifies end-to-end on its OWN key, carrier-independent.
    //     importClassical is false ONLY for branch 1 (fp↔key fail / malformed) → the identity is unverifiable.
    const subjectImport = await classifyImportedCard(subjectCard);
    if (!subjectImport.importClassical) {
      return { ok: false, reason: 'subject-card-invalid' };
    }

    // (5) voucher signature over the canonical envelope, against B's HELD key. Strip the signature fields
    //     before recomputing the signing input (the signer signed the envelope without them).
    const { signature, pq_signature, ...envFields } = intro;
    const envSig: EnvelopeSignature = pq_signature ? { classical: signature, pq_signature } : { classical: signature };
    const sigOk = await verifyWithEnvelope(
      DOMAIN_INTRODUCTION,
      introductionSigningInput(envFields as IntroductionEnvelope),
      envSig,
      voucherHeldPublicKeyArmored,
      voucherPqSigPublicKey,
    );
    if (!sigOk) {
      return { ok: false, reason: 'voucher-signature-invalid' };
    }

    // Accept — PROVENANCE ONLY. No trust is granted; the caller routes the subject to the Grow Gate as KNOWN.
    return {
      ok: true,
      provenance: {
        introduced_by: intro.voucher_fingerprint,
        subject_fingerprint: intro.subject_fingerprint,
        ts: intro.ts,
      },
      subjectCard,
      subjectImport,
    };
  } catch {
    // Any unexpected error on hostile input → fail closed.
    return { ok: false, reason: 'malformed' };
  }
}
