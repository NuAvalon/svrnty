// src/lib/crypto/sign-envelope-framing.ts
// The openpgp-FREE framing core of sign-envelope.ts: the crypto-suite identifiers and the
// decimal-colon netstring length-prefix that define the exact signed_bytes format
//     signed_bytes = LP(domain_tag) ‖ LP(suite_id) ‖ canonical_input,   LP(s) = utf8ByteLen(s)+":"+s
//
// Split out of sign-envelope.ts (which imports openpgp for signWithEnvelope/verifyWithEnvelope) so
// that pure signed-bytes consumers — release-object.ts (release signing input) and
// identity/fingerprint.ts (rotation authority) — import the suite id + framing WITHOUT dragging
// openpgp into their dependency graph. That keeps the air-gap release signer bundle @noble-only and
// minimal/auditable (no ~600KB of inert openpgp). Byte-IDENTICAL to the original sign-envelope.ts
// definitions — sign-envelope.ts now imports + re-exports from here, so every existing importer is
// unaffected and NO signed bytes change.
//
// NOTE (Flint guard 2): this decimal-colon netstring framing (cross-language — a Python satellite
// re-verifies it as  str(len(s.encode('utf-8'))) + ':' + s) is DISTINCT from lp-tlv.ts's binary
// uint32_be framing (structurally client-only byte crypto). Kept in separate homes on purpose — do
// NOT conflate the two.

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
