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
import { fingerprintMatchesKey, KEM_PUB_LEN, SIG_PUB_LEN } from '../identity/fingerprint';

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
  kemPublicKey?: string, // §5: claimant's ML-KEM-1024 public (base64) — canonical-fp binding
  sigPublicKey?: string, // §5: claimant's ML-DSA-87 public (base64) — canonical-fp binding
): Promise<SignedSlugClaim> {
  // §5: attach the claimant's PQ pubkeys so the verifier recomputes the 64-hex canonical fp. Only when
  // BOTH are present (a canonical identity); a classical claim omits them. They are EXCLUDED from
  // slugClaimSigningInput, so the signed bytes (and the satellite's byte-exact input) are UNCHANGED.
  const claimToSign: SlugClaim = { ...claim };
  if (kemPublicKey && sigPublicKey) {
    claimToSign.pq_kem_public_key = kemPublicKey;
    claimToSign.pq_sig_public_key = sigPublicKey;
  }
  const sig = await signWithEnvelope(
    DOMAIN_SLUG_CLAIM,
    slugClaimSigningInput(claimToSign),
    classicalPrivateKeyArmored,
    classicalPassphrase,
    pqSigningSecretKey,
  );
  const signed: SignedSlugClaim = { ...claimToSign, signature: sig.classical };
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
  // (0) §5 defense-in-depth: length-gate the PQ pubkeys at the boundary (fail-loud). A CANONICAL claim
  // carries BOTH kem+sig at FIPS length; a half-present or wrong-length pair is malformed ⇒ refuse rather
  // than silently fall back to the 40-hex OpenPGP path. Preserves the never-throws contract.
  const hasKem = typeof claim.pq_kem_public_key === 'string';
  const hasSig = typeof claim.pq_sig_public_key === 'string';
  if (hasKem !== hasSig) return false; // half-present ⇒ malformed
  if (hasKem && hasSig) {
    try {
      if (atob(claim.pq_kem_public_key!).length !== KEM_PUB_LEN) return false;
      if (atob(claim.pq_sig_public_key!).length !== SIG_PUB_LEN) return false;
    } catch {
      return false; // undecodable base64 ⇒ reject
    }
  }

  // (2) fingerprint↔key binding — cheap, and the whole point of the fix. §5: thread the PQ pubkeys so a
  // 64-hex CANONICAL id recomputes SHA256(sign‖enc‖kem‖sig) and matches; a classical (40-hex) claim omits
  // them → fingerprintMatchesKey falls back to the OpenPGP path. Runs BEFORE the signature (step 1) — the
  // PQ pubkeys are SELF-PROTECTED by this fp-match, so signing them is optional and swapping them fails.
  if (!(await fingerprintMatchesKey(claim.fingerprint, claim.public_key, {
    kem_public_key: claim.pq_kem_public_key,
    sig_public_key: claim.pq_sig_public_key,
  }))) return false;

  // (1) signature over the canonical claim, under the slug-claim domain. Strip BOTH signature fields
  // before recomputing the signing input; the §5 PQ pubkeys are additionally EXCLUDED by
  // slugClaimSigningInput → the signed bytes (and the satellite's byte-exact input) are UNCHANGED.
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
