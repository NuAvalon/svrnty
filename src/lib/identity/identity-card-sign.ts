// src/lib/identity/identity-card-sign.ts
// (A) signed identity card — the pq_kem_public_key carry + its authentication. Mirrors
// trust/slug-claim.ts field-for-field (the Tier-0 signed-object exemplar); do NOT hand-roll crypto.
//
// WHY SIGNED. An identity-exchange card carries the peer's post-quantum keys (pq_kem for hybrid
// encryption; pq_sig for future ML-DSA verify). On a NON-enveloped carrier (ContactManagement
// QR/NFC/copy-paste) a channel-MITM could swap pq_kem undetected, because the fingerprint binds
// ONLY the classical public_key (fingerprint.ts hashes public_key; no kem in the fingerprint path).
// A future quantum adversary who harvested the ciphertext + broke classical DH would then hold both
// legs — the exact HNDL attack ML-KEM exists to stop. So the card is SIGNED and every carrier
// re-verifies on import:
//   (a) the envelope signature verifies against card.identity.public_key, AND
//   (b) card.identity.fingerprint === H(card.identity.public_key)  (fingerprintMatchesKey, Invariant-1).
// Together they bind pq_kem to the fingerprint via the classical key — the signature COMPLETES
// Invariant-1 to cover the pq key it doesn't today.
//
// The byte-exact envelope lives in crypto/sign-envelope.ts; the canonical bytes in format/canonical.ts;
// the domain tag + signing-input in format/envelope.ts (single-source, so sign≡verify can't drift).

import type { IdentityCard } from '../format/envelope';
import { DOMAIN_IDENTITY_CARD, identityCardSigningInput } from '../format/envelope';
import { signWithEnvelope, verifyWithEnvelope, type EnvelopeSignature } from '../crypto/sign-envelope';
import { fingerprintMatchesKey } from './fingerprint';

// ── §6 Suite-length validation: the ek length IS the suite discriminant ──────────
// ML-KEM ek (public-key) sizes are bijective with the parameter set, so a valid card needs no
// separate suite_id field — the length names the suite under the signature. This is the SINGLE
// SOURCE of suite-truth. Two load-bearing conditions:
//   1. DOWNGRADE-FLOOR: the map holds ONLY svrnty-sanctioned suites. ML-KEM-512 (800 B) is BELOW
//      the security floor and is deliberately absent → a 512 key derives `undefined` → 4c (dropped).
//   2. ENCAP MUST DERIVE IDENTICALLY: when `hybridEncapsulate` gets its first caller it MUST pick
//      ML-KEM params from the STORED key's length via THIS SAME map — never hardcode 1024. Import-
//      validate and encrypt-time must agree, or length-as-suite is unsound. (Zero callers today.)
export const EK_LEN_TO_SUITE: Record<number, string> = {
  1184: 'ML-KEM-768',   // Cat-3
  1568: 'ML-KEM-1024',  // Cat-5
};

/**
 * Decoded byte length of a base64 string, computed arithmetically (no atob/Buffer — identical in
 * browser and the tsc→node test env). Throws on non-base64 / bad padding so a malformed key routes
 * to 4c (undefined suite), never to a false accept.
 */
function base64ByteLength(b64: string): number {
  const s = b64.trim();
  if (s.length === 0 || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) {
    throw new Error('not valid base64');
  }
  const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
  return (s.length * 3) / 4 - pad;
}

/** The svrnty suite implied by a base64 ML-KEM public key's decoded length, or undefined if
 *  unsupported/below-floor/malformed. undefined ⇒ import branch 4c (soft-info, pq dropped). */
export function suiteFromKemLength(pqKemPublicKeyB64: string): string | undefined {
  if (!pqKemPublicKeyB64) return undefined;
  try {
    return EK_LEN_TO_SUITE[base64ByteLength(pqKemPublicKeyB64)];
  } catch {
    return undefined;
  }
}

/** A signed identity card: the card fields plus the envelope signature over them (TOP-LEVEL). */
export interface SignedIdentityCard extends IdentityCard {
  signature: string;      // classical (ED25519 / PGP armored)
  pq_signature?: string;  // ML-DSA-87 (hybrid — follow-up §7, not launch)
}

/**
 * Sign an identity card (client-side). Binds the WHOLE card — incl. pq_sig_public_key AND
 * pq_kem_public_key — under the identity-card domain, proving private-key possession over exactly
 * this card. LAUNCH = classical-only (omit pqSigningSecretKey → SUITE_CLASSICAL); the anti-downgrade
 * envelope makes adding ML-DSA later clean and un-strippable.
 */
export async function signIdentityCard(
  card: IdentityCard,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<SignedIdentityCard> {
  const sig = await signWithEnvelope(
    DOMAIN_IDENTITY_CARD,
    identityCardSigningInput(card),
    classicalPrivateKeyArmored,
    classicalPassphrase,
    pqSigningSecretKey,
  );
  const signed: SignedIdentityCard = { ...card, signature: sig.classical };
  if (sig.pq_signature) signed.pq_signature = sig.pq_signature;
  return signed;
}

/**
 * Verify a signed identity card — mirrors verifySignedSlugClaim (returns false, NEVER throws).
 * BOTH must hold:
 *   1. card.identity.fingerprint === H(card.identity.public_key)  (Invariant-1), and
 *   2. the envelope signature verifies against card.identity.public_key over the canonical card.
 * A false result means the caller (JoinerCeremony) MUST NOT store the pq keys — degrade to
 * classical-only per the fail-closed table (§4). This returns a single boolean; the caller
 * distinguishes "no signature present" (branch 2, quiet) from "signature invalid" (branch 3, loud)
 * by checking for the `signature` field before calling.
 */
export async function verifySignedIdentityCard(
  card: SignedIdentityCard,
  pqSigningPublicKey?: Uint8Array,
): Promise<boolean> {
  // Defensive fail-closed: a card parsed from an untrusted carrier may be malformed.
  const id = card?.identity;
  if (!id || typeof id.public_key !== 'string' || typeof id.fingerprint !== 'string') return false;
  if (typeof card.signature !== 'string' || card.signature.length === 0) return false;

  // (1) fingerprint↔classical-key binding — Invariant-1, cheap, checked first.
  if (!(await fingerprintMatchesKey(id.fingerprint, id.public_key))) return false;

  // (2) envelope signature over the canonical card. Strip BOTH signature fields before recomputing
  // the signing input — the signer signed the card without them (identityCardSigningInput excludes them).
  const { signature, pq_signature, ...cardFields } = card;
  const envSig: EnvelopeSignature = pq_signature
    ? { classical: signature, pq_signature }
    : { classical: signature };
  return verifyWithEnvelope(
    DOMAIN_IDENTITY_CARD,
    identityCardSigningInput(cardFields),
    envSig,
    id.public_key,
    pqSigningPublicKey,
  );
}

// ── SEND side: assemble + sign a card from a stored identity (both send-paths share this) ────
// Ceremony (relay) and ContactManagement (QR/copy) both call this so the signed shape can NEVER
// drift between carriers. pq_* come from the identity's post_quantum block (its PUBLIC keys); a
// v1/no-PQ identity yields '' → the card is signed over the ABSENCE, which the receiver reads as
// branch-4a (quiet, no pq). Signing needs the classical private key ⇒ the session must be unlocked;
// the caller loads it via loadKey() and handles the locked case.
export async function buildSignedIdentityCard(
  identity: any,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
): Promise<SignedIdentityCard> {
  const idData = identity?.identity ?? identity;
  if (!idData?.fingerprint || !idData?.public_key) {
    throw new Error('cannot sign identity card — identity is missing fingerprint or public_key');
  }
  const pq = idData.post_quantum;
  const card: IdentityCard = {
    version: '1.0',
    type: 'identity-exchange',
    created_at: new Date().toISOString(),
    identity: {
      fingerprint: idData.fingerprint,
      display_name: idData.display_name || idData.name || idData.slug || '',
      public_key: idData.public_key,
      email: idData.email || '',
      pq_sig_public_key: pq?.sig_public_key || '',
      pq_kem_public_key: pq?.kem_public_key || '',
    },
  };
  return signIdentityCard(card, classicalPrivateKeyArmored, classicalPassphrase);
}

// ── RECEIVE side: the fail-closed 4-branch import disposition (both receive-paths share this) ──
// JoinerCeremony (relay/QR) and ContactManagement.handleImportExchange (copy/paste) BOTH call this
// so the security decision can't drift between carriers (every carrier ends at
// verifySignedIdentityCard). Pure decision — it stores nothing; the caller applies `pq` + `alarm`.
export interface ImportDisposition {
  /** Import the classical contact at all? false ONLY for branch 1 (fp-fail / malformed card). */
  importClassical: boolean;
  /** Authenticated pq fields to STORE on the record, or null (drop pq). Non-null ONLY for 4b. */
  pq: { pq_kem_public_key: string; pq_sig_public_key: string } | null;
  /** UI disposition: reject (no import) · quiet (benign) · loud (possible tampering) · soft-info (unsupported suite). */
  alarm: 'reject' | 'quiet' | 'loud' | 'soft-info';
  /** Which branch fired — for tests, the UI message, and telemetry. */
  branch: 1 | 2 | 3 | '4a' | '4b' | '4c';
  /** Derived svrnty suite (4b only). */
  suite?: string;
}

/**
 * Classify a parsed identity-exchange card into its fail-closed import disposition.
 *   1  fp↔key FAILS / malformed        → REJECT the whole card (classical identity unverifiable).
 *   2  fp↔key OK, no `signature`        → classical-only, DROP pq, QUIET (benign pre-PQ peer).
 *   3  signature PRESENT but INVALID    → classical-only, DROP pq, LOUD (possible tampering).
 *   4  signature VALID → pq sub-disposition:
 *      4a pq_kem absent/empty           → QUIET, no pq (legit v1 signer; sig covers the absence).
 *      4b length ∈ EK_LEN_TO_SUITE      → STORE the authenticated pq (derived suite).
 *      4c length ∉ EK_LEN_TO_SUITE      → SOFT-INFO, no pq (sender bug, NOT tamper — a valid sig
 *                                         means a swapped kem is unreachable; §6/4c).
 * The core `verifySignedIdentityCard` collapses 2 and 3 into `false`; we split them here on the
 * PRESENCE of a non-empty `signature` field (branch 2 never calls verify).
 */
export async function classifyImportedCard(card: any): Promise<ImportDisposition> {
  const id = card?.identity;
  // Malformed classical identity → branch 1 (nothing to import, nothing to trust).
  if (
    !id ||
    typeof id.public_key !== 'string' || id.public_key.length === 0 ||
    typeof id.fingerprint !== 'string' || id.fingerprint.length === 0
  ) {
    return { importClassical: false, pq: null, alarm: 'reject', branch: 1 };
  }
  // BRANCH 1: fp↔classical-key binding (Invariant-1). Checked independently of verify — branch 2
  // never calls verify, and this decides classical-import for every branch.
  if (!(await fingerprintMatchesKey(id.fingerprint, id.public_key))) {
    return { importClassical: false, pq: null, alarm: 'reject', branch: 1 };
  }
  // fp↔key OK → the classical contact imports for branches 2/3/4.
  const hasSig = typeof card.signature === 'string' && card.signature.length > 0;
  // BRANCH 2: no signature → classical-only, quiet. Must NOT alarm (benign transition-era peer).
  if (!hasSig) {
    return { importClassical: true, pq: null, alarm: 'quiet', branch: 2 };
  }
  // Signature present → verify (re-checks fp↔key internally; keeps verify self-contained).
  const valid = await verifySignedIdentityCard(card as SignedIdentityCard);
  // BRANCH 3: present but invalid → classical-only, LOUD. Reserve the tamper alarm for THIS only.
  if (!valid) {
    return { importClassical: true, pq: null, alarm: 'loud', branch: 3 };
  }
  // BRANCH 4: valid signature → pq sub-disposition.
  const kem = typeof id.pq_kem_public_key === 'string' ? id.pq_kem_public_key : '';
  // 4a: absent/empty pq_kem under a valid sig → legit v1/no-PQ signer. Quiet, no pq.
  if (kem === '') {
    return { importClassical: true, pq: null, alarm: 'quiet', branch: '4a' };
  }
  const suite = suiteFromKemLength(kem);
  // 4c: valid sig, unsupported/malformed suite length → sender bug, NOT tampering. Soft-info, no pq.
  if (!suite) {
    return { importClassical: true, pq: null, alarm: 'soft-info', branch: '4c' };
  }
  // 4b: valid sig + supported suite → STORE the authenticated pq (both keys, as carried).
  const sig = typeof id.pq_sig_public_key === 'string' ? id.pq_sig_public_key : '';
  return {
    importClassical: true,
    pq: { pq_kem_public_key: kem, pq_sig_public_key: sig },
    alarm: 'quiet',
    branch: '4b',
    suite,
  };
}
