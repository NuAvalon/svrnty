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
// AUTHORITATIVE spec: shared/outbox/flint/svrnty_identity_card_signing_spec_flint.md (Flint, s904).
// The byte-exact envelope lives in crypto/sign-envelope.ts; the canonical bytes in format/canonical.ts;
// the domain tag + signing-input in format/envelope.ts (single-source, so sign≡verify can't drift).

import type { IdentityCard } from '../format/envelope';
import { DOMAIN_IDENTITY_CARD, identityCardSigningInput } from '../format/envelope';
import { signWithEnvelope, verifyWithEnvelope, type EnvelopeSignature } from '../crypto/sign-envelope';
import { fingerprintMatchesKey } from './fingerprint';

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
