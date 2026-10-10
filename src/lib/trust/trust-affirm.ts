// src/lib/trust/trust-affirm.ts
// MUTUAL-TRUST AFFIRMATION v0 — the deposit+consume signal that flips they_trust_me / reciprocal.
//
// THE GAP (Apollo, grounded ☀8178). `reciprocal = trusted && they_trust_me` (trust-graph.ts), but
// `they_trust_me` flips ONLY via updateMutualState() — which has ZERO live callers (the KNOW-layer
// PSI sync is gated-off for alpha). So no trusted contact ever flips to MUTUAL — every one shows
// "awaiting mutual" PERMANENTLY. TRUST_RECIPE.md:38 says it verbatim: "Local Trust is a one-way mark
// (stub-not-live). Need deposit + consume so they_trust_me / reciprocal flips. Same for break."
//
// THIS MODULE is the SIGNAL half of that deposit+consume. When A trusts B, A deposits a SIGNED
// trust-affirmation to B's blind mailbox (sealed, sender-anonymous — rides the SAME over-wire note
// substrate, so the relay stays content-blind + edge-blind, I-4 intact). B consumes it, authenticates
// the sender (this module), confirms A is in B's book, and calls updateMutualState(A_fp, trusts) →
// B's reciprocal flips. "Same for break": trusts=false.
//
// EXACT MIRROR of messaging/note-auth.ts (itself the proven mailbox-auth template): sign a canonical()
// input under a domain tag with signWithEnvelope; on receipt bind public_key↔from_fingerprint with
// fingerprintMatchesKey (Canon Invariant-1) THEN verify with verifyWithEnvelope. Classical-or-canonical
// sender exactly like notes (PQ pubkeys bind the 64-hex canonical fp via the fp-match, NOT the sig).
//
// Run tests: npx tsx --test src/lib/trust/trust-affirm.test.ts

import { signWithEnvelope, verifyWithEnvelope } from '@/lib/crypto/sign-envelope';
import type { EnvelopeSignature } from '@/lib/crypto/sign-envelope';
import { fingerprintMatchesKey, KEM_PUB_LEN, SIG_PUB_LEN } from '@/lib/identity/fingerprint';
import { canonicalize } from '@/lib/format/canonical';

/** Domain-separation tag — a trust-affirm sig can NOT verify as a note / joiner-response / contact-update. */
export const DOMAIN_TRUST_AFFIRM = 'svrnty:trust-affirm:v0';

/** Wire discriminator inside a decrypted mailbox blob (the mailbox's inbound type, alongside svrnty-note-v0). */
export const TRUST_AFFIRM_WIRE_TYPE = 'svrnty-trust-affirm-v0';

export interface TrustAffirmWireV0 {
  type: typeof TRUST_AFFIRM_WIRE_TYPE;
  affirm_id: string; // unique (anti-replay handle; the consumer may also dedup by (from,to))
  from_fingerprint: string; // the affirmer (the sender) — bound to public_key by fingerprintMatchesKey
  to_fingerprint: string; // the peer being affirmed (the recipient) — bound in the signed preimage
  trusts: boolean; // true = "I trust you" (flip they_trust_me→true); false = "I broke trust" (→false)
  sent_at: string; // ISO; bound in the preimage

  // Sender authentication (mirrors note-auth; OPTIONAL on the base wire, REQUIRED to admit). Without
  // these the affirmation is only ENCRYPTED, not SIGNED → from_fingerprint would be attacker-set and
  // a stranger could forge "X trusts you". public_key = sender's openpgp key; signature =
  // signWithEnvelope(DOMAIN_TRUST_AFFIRM, trustAffirmSigningInput(wire)).
  public_key?: string;
  signature?: EnvelopeSignature;

  // Canonical-identity (64-hex) binding: the sender's ML-KEM-1024 + ML-DSA-87 public keys (base64), so
  // the verifier recomputes SHA256(sign‖enc‖kem‖sig) and matches from_fingerprint. Public keys only;
  // possession is proved by the signature. EXCLUDED from the signing preimage (bind via the fp-match).
  pq_kem_public_key?: string;
  pq_sig_public_key?: string;
}

/**
 * Bytes signed for a trust-affirmation. Excludes the signature-attachment fields (`signature`,
 * `public_key`) and the canonical-fp PQ pubkeys — identical preimage before attaching (sign side) and
 * after they arrive (verify side). Everything else — `from_fingerprint`, `to_fingerprint`, `trusts`,
 * `affirm_id`, `sent_at` — is bound, so tampering ANY of it fails verification (incl. flipping `trusts`).
 */
export function trustAffirmSigningInput(wire: TrustAffirmWireV0): string {
  return canonicalize(wire, {
    exclude: ['signature', 'public_key', 'pq_kem_public_key', 'pq_sig_public_key'],
  });
}

/**
 * Sign a trust-affirmation and attach {public_key, signature}. The returned wire is what gets sealed +
 * deposited to the peer's mailbox. Passing both PQ pubkeys marks a CANONICAL sender (64-hex fp).
 */
export async function signTrustAffirm(
  wire: TrustAffirmWireV0,
  senderPublicKeyArmored: string,
  senderPrivateKeyArmored: string,
  passphrase: string,
  senderPqKemPublicKey?: string,
  senderPqSigPublicKey?: string,
): Promise<TrustAffirmWireV0> {
  const signature = await signWithEnvelope(
    DOMAIN_TRUST_AFFIRM,
    trustAffirmSigningInput(wire),
    senderPrivateKeyArmored,
    passphrase,
  );
  const signed: TrustAffirmWireV0 = { ...wire, public_key: senderPublicKeyArmored, signature };
  if (senderPqKemPublicKey && senderPqSigPublicKey) {
    signed.pq_kem_public_key = senderPqKemPublicKey;
    signed.pq_sig_public_key = senderPqSigPublicKey;
  }
  return signed;
}

/**
 * True iff the affirmation carries a valid sender signature AND its public_key binds to
 * `from_fingerprint`. Returns false (never throws) on any missing field, fp↔key mismatch, or bad sig.
 *
 * AUTHENTICATION floor only — proves WHO signed. Whether that authenticated sender is in the
 * recipient's book (so updateMutualState should fire) is a SEPARATE admit check in the consume seam —
 * exactly like notes: an unsigned/forged affirmation fails HERE; a genuine stranger fails at admit.
 */
export async function verifyTrustAffirmSender(wire: TrustAffirmWireV0): Promise<boolean> {
  if (wire.type !== TRUST_AFFIRM_WIRE_TYPE) return false; // wrong type ⇒ not ours
  if (!wire.public_key || !wire.signature) return false; // unsigned ⇒ unauthenticated
  try {
    // (0) length-gate the PQ pubkeys at the boundary (fail-loud): a canonical affirmation carries BOTH
    //     kem+sig at FIPS length; half-present or wrong-length ⇒ malformed ⇒ refuse (no silent fallback).
    const hasKem = typeof wire.pq_kem_public_key === 'string';
    const hasSig = typeof wire.pq_sig_public_key === 'string';
    if (hasKem !== hasSig) return false;
    if (hasKem && hasSig) {
      if (atob(wire.pq_kem_public_key!).length !== KEM_PUB_LEN) return false;
      if (atob(wire.pq_sig_public_key!).length !== SIG_PUB_LEN) return false;
    }
    // (1) fp↔key binding (Canon Invariant-1) BEFORE the signature — the carried key MUST hash to the
    //     claimed from_fingerprint, else an attacker pairs a victim's fp with their own key.
    if (
      !(await fingerprintMatchesKey(wire.from_fingerprint, wire.public_key, {
        kem_public_key: wire.pq_kem_public_key,
        sig_public_key: wire.pq_sig_public_key,
      }))
    )
      return false;
    // (2) possession: the affirmation content (from/to/trusts/affirm_id/sent_at) was signed by that key
    //     under DOMAIN_TRUST_AFFIRM. Flipping `trusts` (or any bound field) breaks this.
    return await verifyWithEnvelope(
      DOMAIN_TRUST_AFFIRM,
      trustAffirmSigningInput(wire),
      wire.signature,
      wire.public_key,
    );
  } catch {
    return false; // any crypto/parse failure ⇒ refuse (fail-closed)
  }
}
