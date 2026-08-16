// src/lib/trust/slug-claim.ts
// F6 real-fix — a slug claim must PROVE possession of the private key behind `public_key`.
//
// The pre-fix flow (SoverentityFrontend handleClaimUrl → POST /slug/:slug/claim { fingerprint })
// sent only a fingerprint; PR#1 additionally sent a public_key. NEITHER proves the claimant holds
// the matching private key — so anyone could claim a slug for someone else's fingerprint/key. That
// is the "F6 false-closed" gap: presenting a public key is not authenticating with it.
//
// The fix: the claimant SIGNS the SlugClaim under the slug-claim domain, and the verifier checks
//   (a) the signature verifies against the presented public_key, AND
//   (b) fingerprint === H(public_key)   (fingerprintMatchesKey — Canon Invariant-1)
// Together these prove: "the holder of the private key for THIS key — whose fingerprint is the one
// being claimed — authorized THIS slug at THIS time." (b) alone lets an attacker pair a victim's
// fingerprint with the victim's key but no private key; (a) alone lets an attacker sign with their
// own key under a fingerprint that isn't theirs. Both together close it.
//
// The authoritative server-side check runs on the satellite (Python, live svrnty.is) and must
// mirror the byte-exact envelope in src/lib/crypto/sign-envelope.ts. This module is the TypeScript
// reference: the client uses signSlugClaim to sign, and tests use verifySignedSlugClaim to pin the
// envelope so the two implementations cannot drift. Design: KB#85978.

import type { SlugClaim } from '../format/envelope';
import { DOMAIN_SLUG_CLAIM, slugClaimSigningInput } from '../format/envelope';
import { signWithEnvelope, verifyWithEnvelope, type EnvelopeSignature } from '../crypto/sign-envelope';
import { fingerprintMatchesKey } from '../identity/fingerprint';

/** A signed slug claim: the claim fields plus the envelope signature over them. */
export interface SignedSlugClaim extends SlugClaim {
  signature: string; // classical (ED25519 / PGP)
  pq_signature?: string; // ML-DSA-87 (hybrid)
}

/**
 * Sign a slug claim (client-side). Binds slug + fingerprint + public_key + timestamp under the
 * slug-claim domain, proving private-key possession over exactly this claim.
 */
export async function signSlugClaim(
  claim: SlugClaim,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<SignedSlugClaim> {
  const sig = await signWithEnvelope(
    DOMAIN_SLUG_CLAIM,
    slugClaimSigningInput(claim),
    classicalPrivateKeyArmored,
    classicalPassphrase,
    pqSigningSecretKey,
  );
  const signed: SignedSlugClaim = { ...claim, signature: sig.classical };
  if (sig.pq_signature) signed.pq_signature = sig.pq_signature;
  return signed;
}

/**
 * Verify a signed slug claim — the reference the satellite verifier mirrors. BOTH must hold:
 *   1. the envelope signature verifies against `claim.public_key`, and
 *   2. `claim.fingerprint === H(claim.public_key)`.
 * Returns false (never throws) on any failure — a verifier refuses the claim.
 */
export async function verifySignedSlugClaim(
  claim: SignedSlugClaim,
  pqSigningPublicKey?: Uint8Array,
): Promise<boolean> {
  // (2) fingerprint↔key binding — cheap, and the whole point of the fix.
  if (!(await fingerprintMatchesKey(claim.fingerprint, claim.public_key))) return false;

  // (1) signature over the canonical claim, under the slug-claim domain. Strip BOTH signature
  // fields before recomputing the signing input — the signer signed the claim without them.
  const { signature, pq_signature, ...claimFields } = claim;
  const envSig: EnvelopeSignature = pq_signature
    ? { classical: signature, pq_signature }
    : { classical: signature };
  return verifyWithEnvelope(
    DOMAIN_SLUG_CLAIM,
    slugClaimSigningInput(claimFields),
    envSig,
    claim.public_key,
    pqSigningPublicKey,
  );
}
