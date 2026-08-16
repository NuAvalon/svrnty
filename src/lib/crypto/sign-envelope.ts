// src/lib/crypto/sign-envelope.ts
// 0.1 canonical sign-envelope — the domain-separated, suite-bound signing wrapper for svrnty
// Tier-0 signed objects (trust signals, slug claims, and — later — key-lineage). This is Flint's
// signing layer over Archie's canonical bytes (src/lib/format/canonical.ts) and domain-tag
// vocabulary (src/lib/format/envelope.ts). Design: KB#85978.
//
// WHAT THIS FIXES. The pre-0.1 signer used raw JSON.stringify({...}) as the signed bytes
// (src/lib/trust/signals.ts canonicalSignPayload). That is key-order dependent, NFC-blind, and has
// no float/null discipline — a cross-implementation verifier, or a unicode display_name in a
// different normal form, silently breaks verification. It also bound neither the message DOMAIN nor
// the crypto SUITE, so:
//   - a signature over one object type could be replayed as another (domain confusion), and
//   - a hybrid (classical+PQ) signature could be stripped to classical-only and replayed
//     (a downgrade), because the classical half had signed the exact same bytes either way.
//
// THE ENVELOPE. The bytes actually signed are:
//
//     signed_bytes = LP(domain_tag) ‖ LP(suite_id) ‖ canonical_input
//
//   where ‖ is concatenation, canonical_input is the output of canonicalize(...) (already
//   NFC-normalized, key-sorted, integer-only, null-free), and LP is an injective length prefix:
//
//     LP(s) = utf8ByteLength(s) + ":" + s          (netstring-style; decimal ASCII length)
//
//   LP makes the concatenation injective: a verifier reads the decimal length, the ':', then
//   exactly that many UTF-8 bytes — so (domain_tag, suite_id) are always recovered unambiguously
//   and the tail is exactly canonical_input, even though the tags themselves contain ':' (we split
//   by LENGTH, never by delimiter). Different domains or suites therefore produce different signed
//   bytes — which is the whole point (domain separation + anti-downgrade). canonical_input is the
//   tail and is NOT length-prefixed: nothing follows it, so it stays unambiguous.
//
//   This is a STRING framing on purpose. The underlying signer (hybrid.ts) is string-based (openpgp
//   text message + TextEncoder for ML-DSA), so keeping the envelope a string avoids changing the
//   crypto API while staying byte-exact and trivially reproducible in any language — a Python
//   satellite verifier reproduces it as  str(len(s.encode('utf-8'))) + ':' + s. domain_tag and
//   suite_id are pure ASCII and canonical_input is single-line, so the string↔byte mapping is 1:1.
//
// SUITE BINDING (anti-downgrade). suite_id names the crypto suite that produced the signature and is
// DERIVED, not stored: a hybrid signature (pq_signature present) binds SUITE_HYBRID; a
// classical-only signature binds SUITE_CLASSICAL. Stripping the PQ half flips the derived suite,
// which changes signed_bytes, so the surviving classical signature no longer verifies. No new stored
// field is needed — signer and verifier derive suite_id by the same rule.

import {
  createMessage,
  readMessage,
  readPrivateKey,
  decryptKey,
  sign as pgpSign,
} from 'openpgp';
import { hybridSign, hybridVerify } from './hybrid';

/**
 * Crypto suite identifiers bound into the signed bytes (anti-downgrade). DERIVED from whether a PQ
 * signature is present — never a stored field. The hybrid id mirrors HybridSignature.algorithm.
 */
export const SUITE_CLASSICAL = 'ed25519';
export const SUITE_HYBRID = 'ed25519+ml-dsa-87';

/**
 * Injective length prefix: decimal UTF-8 byte length, a colon, then the string.
 *   lengthPrefix("svrnty:slug-claim:v1") === "20:svrnty:slug-claim:v1"
 */
export function lengthPrefix(s: string): string {
  return new TextEncoder().encode(s).length + ':' + s;
}

/** The exact bytes (as a string) that get signed: LP(domain) ‖ LP(suite) ‖ canonical_input. */
export function buildSignedBytes(domainTag: string, suiteId: string, canonicalInput: string): string {
  return lengthPrefix(domainTag) + lengthPrefix(suiteId) + canonicalInput;
}

/** A signature produced by the envelope. `pq_signature` present ⇒ the hybrid suite was bound. */
export interface EnvelopeSignature {
  classical: string;
  pq_signature?: string;
}

/**
 * Sign `canonicalInput` under `domainTag`. Uses hybrid (classical + PQ) when a PQ secret key is
 * supplied, else classical-only. The suite is bound into the signed bytes automatically, so the
 * caller cannot accidentally produce a downgradeable signature.
 */
export async function signWithEnvelope(
  domainTag: string,
  canonicalInput: string,
  classicalPrivateKeyArmored: string,
  classicalPassphrase: string,
  pqSigningSecretKey?: Uint8Array,
): Promise<EnvelopeSignature> {
  const suiteId = pqSigningSecretKey ? SUITE_HYBRID : SUITE_CLASSICAL;
  const signedBytes = buildSignedBytes(domainTag, suiteId, canonicalInput);

  if (pqSigningSecretKey) {
    const sig = await hybridSign(
      signedBytes,
      classicalPrivateKeyArmored,
      classicalPassphrase,
      pqSigningSecretKey,
    );
    return { classical: sig.classical, pq_signature: sig.post_quantum };
  }

  const privateKeyObj = await readPrivateKey({ armoredKey: classicalPrivateKeyArmored });
  const decryptedKey = await decryptKey({ privateKey: privateKeyObj, passphrase: classicalPassphrase });
  const message = await createMessage({ text: signedBytes });
  const classicalSig = await pgpSign({ message, signingKeys: decryptedKey });
  return { classical: classicalSig.toString() };
}

/**
 * True iff the inline (openpgp) classical signature was made over EXACTLY `expected`.
 *
 * This is load-bearing. `hybridVerify` validates the classical signature against the literal message
 * embedded INSIDE the armored blob — NOT against any caller-provided bytes (see hybrid.ts: the
 * `payload` argument is only used for the PQ half). So for a classical-only signature, hybridVerify
 * answers "is this a validly-signed message?" but not "does it sign OUR bytes?". Without this check
 * the JSON fields wrapping the signature are malleable: an attacker keeps a validly-signed inner
 * message and swaps payload/from/to, and verification still passes. Binding the embedded literal to
 * our reconstructed `signedBytes` closes that, and — because the suite is part of `signedBytes` —
 * also defeats stripping the PQ half of a hybrid signature (the embedded HYBRID-suite bytes no
 * longer equal the reconstructed CLASSICAL-suite bytes).
 */
export async function classicalSignatureBinds(armoredClassical: string, expected: string): Promise<boolean> {
  try {
    const msg = await readMessage({ armoredMessage: armoredClassical });
    const data = msg.getLiteralData();
    return data != null && new TextDecoder().decode(data) === expected;
  } catch {
    return false;
  }
}

/**
 * Verify a signature produced by {@link signWithEnvelope}. The suite is derived from the presence of
 * a PQ signature, so a hybrid signature stripped to classical-only reconstructs DIFFERENT signed
 * bytes and fails (downgrade resistance). `acceptClassicalOnly` is derived the same way: a classical
 * signal legitimately has no PQ half; a caller that must REQUIRE PQ enforces it upstream (by
 * refusing signals whose pq_signature is absent) rather than here.
 */
export async function verifyWithEnvelope(
  domainTag: string,
  canonicalInput: string,
  signature: EnvelopeSignature,
  classicalPublicKeyArmored: string,
  pqSigningPublicKey?: Uint8Array,
): Promise<boolean> {
  const suiteId = signature.pq_signature ? SUITE_HYBRID : SUITE_CLASSICAL;
  const signedBytes = buildSignedBytes(domainTag, suiteId, canonicalInput);

  // Bind OUR bytes: hybridVerify only checks the signature against its own embedded message.
  if (!(await classicalSignatureBinds(signature.classical, signedBytes))) return false;

  const hybridSig = signature.pq_signature
    ? {
        classical: signature.classical,
        post_quantum: signature.pq_signature,
        algorithm: 'ED25519+ML-DSA-87' as const,
      }
    : { classical: signature.classical };

  return hybridVerify(
    signedBytes,
    hybridSig,
    classicalPublicKeyArmored,
    pqSigningPublicKey,
    !signature.pq_signature, // acceptClassicalOnly exactly when there is no PQ half to require
  );
}
