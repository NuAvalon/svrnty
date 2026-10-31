// src/lib/sync/send-introduction.ts
// The INTRODUCER's deposit — the 3-party KNOW-layer counterpart of send-joiner-response.ts. After a
// NEWCOMER (N) signs a recipient-scoped consent token and hands it to an INTRODUCER (I) who is already
// in the RECIPIENT (R)'s know-set, this signs the introduction envelope with I's key (carrying N's
// self-consented card + N's consent-signature), E2E-encrypts it to R, and deposits it into R's mailbox.
// R polls (consume-mailbox → buildIntroductionSeam), runs verifyIntroduction, and surfaces N as a
// PENDING KNOWN intro (introduced_by = I, historical provenance). "Introduce has nothing to do with
// trust" (Peter #174972) — N becomes KNOWN, never trusted, by this path.
//
// SECURITY SHAPE (mirror send-joiner-response.ts / send-contact-update.ts — same E2E envelope, no new
// key material):
//  • DUAL-SIGN (the survivor-safety crux, S1). The envelope carries BOTH I's signature (the vouch) AND
//    N's recipient-scoped consent-signature. Neither alone is valid at R. buildSignedIntroduction +
//    buildIntroductionEnvelope enforce the consent cross-binding (the forwarded consent must name this
//    exact (introduced, introducer, recipient) triple + display_name + nonce) and throw loudly on any
//    mismatch — so an introducer cannot forward a consent harvested for a different introduction, and
//    cannot rename N to a deadname they didn't consent to.
//  • ENCRYPT to R's public key → opaque armored blob; the relay stores ciphertext only (custody / I-1:
//    it cannot read N's card, I's identity, or reconstruct the edge).
//  • ADDRESS by deriveMailboxId(recipient fingerprint) — the same deterministic mailbox id R polls.
//  • BIND to THIS recipient — recipient_fingerprint is signed and re-checked === R's own fp on consume,
//    so a captured blob re-deposited to a different recipient's mailbox fails there (no cross-recipient
//    replay). The know-set gate (introducer ∈ R's current know-set) is the solicited-gate, applied on
//    consume — a pending intro from a since-dropped introducer simply fails and is dismissed.
//  • CARD-ONLY — carries ONLY N's self-consented {fp, key, pq-keys, display_name} + context, NEVER
//    anything about R's other contacts (S4 graph-leak). introduced_by provenance stays owner-local at R
//    (it is derived from the verified introducer_fingerprint on consume, never a wire field R trusts).
//  • FAIL-CLOSED — a recipient with no usable public key or no ML-KEM key, or a malformed card/consent, yields no deposit
//    (null), never a downgraded send; the caller (the Introduce UI) is fail-soft and never blocks on it.
//
// HYBRID ONLY (HNDL, the #310 no-downgrade posture): the deposit is sealed ML-KEM-1024 + X25519 to the recipient. A recipient whose card carries no
// verified ML-KEM key gets NO deposit (null / 'encrypt-failed'), never a classical one. The signatures are the existing classical (+ optional PQ) pair;
// the SEAL is what must be hybrid. Kept fetch-free/pure (buildIntroductionDeposit) so it is unit-testable; the component injects identities.

import { deriveMailboxId } from '../relay/mailbox-auth';
import {
  buildSignedIntroduction,
  encryptIntroductionTo,
  type BuildIntroductionArgs,
} from '../trust/introduction';
import type { IntroductionConsent } from '../format/envelope';
import type { EnvelopeSignature } from '../crypto/sign-envelope';

/** The introducer's signing identity (from the unlocked vault) — who vouches/forwards. Classical for launch. */
export interface IntroducerIdentity {
  /** The introducer's durable fingerprint — MUST be in R's know-set (the consume-side gate verifies this). */
  fingerprint: string;
  privateKeyArmored: string;
  passphrase: string;
  /** Hybrid upgrade: the introducer's ML-DSA-87 secret. Omit for a classical (launch) introduction. */
  pqSigningSecretKey?: Uint8Array;
}

/**
 * The newcomer's self-consented card + their signed consent token. The introducer FORWARDS this; it is
 * produced on the NEWCOMER's device (buildIntroductionConsent + signIntroductionConsent). The introducer
 * cannot alter it without invalidating N's signature — display_name is bound by the consent (S1).
 */
export interface NewcomerCard {
  fingerprint: string;
  publicKeyArmored: string;
  /** The name N consented to be introduced UNDER (may be empty = KNOWN/unverified). Bound by N's consent-sig. */
  displayName: string;
  /** §5 canonical-fp: N's ML-KEM-1024 public (base64, 1568B). Thread with sigPublicKeyB64 so R recomputes
   *  N's 64-hex canonical id; a classical newcomer omits both (R's OpenPGP-fp path). */
  pqKemPublicKeyB64?: string;
  /** §5 canonical-fp: N's ML-DSA-87 public (base64) — the other half. */
  pqSigPublicKeyB64?: string;
  /** N's recipient-scoped consent token (names introduced/introducer/recipient + display_name + nonce). */
  consent: IntroductionConsent;
  /** N's signature over the consent token (DOMAIN_INTRODUCTION_CONSENT), verified at R against N's key. */
  consentSignature: EnvelopeSignature;
}

/** The recipient R being introduced TO: fingerprint (→ mailbox + binding) + pubkey (→ encrypt-to). */
export interface IntroductionTarget {
  fingerprint: string;
  publicKeyArmored: string;
  /** R's verified ML-KEM-1024 pubkey (base64). Present => sealed PQ-hybrid. ABSENT => fail-closed: no deposit, never a classical send. */
  pqKemPublicKey?: string;
}

/** Outcome of the single deposit — best-effort accounting; the caller (Introduce UI) is fail-soft. */
export interface IntroductionSendResult {
  ok: boolean;
  /** relay status on success, or the failure classifier ('encrypt-failed' | 'network-error' | HTTP status). */
  status?: number | string;
}

/**
 * Pure: build + dual-sign + encrypt the introduction → one ready-to-POST deposit {mailbox_id, blob}, or
 * null if the recipient has no usable public key or the build/encrypt fails (never sent downgraded).
 * fetch-free so it is unit-testable; the caller POSTs it. The consent cross-binding + display_name bind
 * are enforced inside buildSignedIntroduction (it THROWS on mismatch) → caught here as no-deposit.
 */
export async function buildIntroductionDeposit(
  introducer: IntroducerIdentity,
  newcomer: NewcomerCard,
  recipient: IntroductionTarget,
  context: string,
  ts?: string,
): Promise<{ mailbox_id: string; blob: string } | null> {
  if (
    typeof recipient.fingerprint !== 'string' || recipient.fingerprint.length === 0 ||
    typeof recipient.publicKeyArmored !== 'string' || recipient.publicKeyArmored.length === 0
  ) {
    return null;
  }
  // fail-closed (HNDL): no verified recipient ML-KEM key => no deposit.
  if (typeof recipient.pqKemPublicKey !== 'string' || recipient.pqKemPublicKey.length === 0) return null;
  try {
    const args: BuildIntroductionArgs = {
      introducerFp: introducer.fingerprint,
      recipientFp: recipient.fingerprint,
      introducedFp: newcomer.fingerprint,
      introducedPubKeyArmored: newcomer.publicKeyArmored,
      introducedName: newcomer.displayName,
      consent: newcomer.consent,
      consentSignature: newcomer.consentSignature,
      context,
      // §5: carry N's PQ pubkeys so R recomputes N's 64-hex canonical id. Only when BOTH are present
      // (a canonical identity); a classical newcomer omits them → R's OpenPGP-fp path.
      ...(newcomer.pqKemPublicKeyB64 && newcomer.pqSigPublicKeyB64
        ? { introducedPqKemPublicKey: newcomer.pqKemPublicKeyB64, introducedPqSigPublicKey: newcomer.pqSigPublicKeyB64 }
        : {}),
      ...(ts ? { ts } : {}),
    };
    const signed = await buildSignedIntroduction(
      args,
      introducer.privateKeyArmored,
      introducer.passphrase,
      introducer.pqSigningSecretKey,
    );
    const blob = await encryptIntroductionTo(signed, recipient.publicKeyArmored, recipient.pqKemPublicKey);
    return { mailbox_id: deriveMailboxId(recipient.fingerprint), blob };
  } catch {
    // A malformed card/consent (consent-mismatch, bad display_name, unreadable recipient key) must not
    // throw to the UI — report as no-deposit. The build-side throws are the sender's own-input guard.
    return null;
  }
}

/**
 * The drop-in: build + POST the introduction to R's mailbox via the EXISTING /envelope relay (no new
 * endpoint — mirrors joiner-response's deposit). Best-effort — a POST failure is reported (retryable),
 * never thrown to the caller. Idempotent-safe at R: a redelivered blob re-verifies to the same pending
 * intro, and the caller-side (nonce, introduced_fp) dedup on consume drops the duplicate.
 */
export async function sendIntroduction(
  introducer: IntroducerIdentity,
  newcomer: NewcomerCard,
  recipient: IntroductionTarget,
  context: string,
  opts: { fetchImpl?: typeof fetch; relayBase?: string; ts?: string } = {},
): Promise<IntroductionSendResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const relayBase = opts.relayBase ?? '/api/relay';

  const deposit = await buildIntroductionDeposit(introducer, newcomer, recipient, context, opts.ts);
  if (!deposit) return { ok: false, status: 'encrypt-failed' };

  try {
    const res = await doFetch(`${relayBase}/envelope`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mailbox_id: deposit.mailbox_id, blob: deposit.blob }),
    });
    return res.ok ? { ok: true, status: res.status } : { ok: false, status: res.status };
  } catch {
    return { ok: false, status: 'network-error' };
  }
}
