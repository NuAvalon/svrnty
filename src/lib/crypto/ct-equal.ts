// src/lib/crypto/ct-equal.ts
/**
 * One constant-time byte comparison for svrnty's client-side crypto, beside lp-tlv.ts for the same reason: private copies diverge.
 *
 * Time depends on the LENGTH only: for equal-length inputs every byte is visited and the result is a single accumulated difference, so a
 * mismatch at the first byte takes as long as a match. A length mismatch returns false up front, because lengths are public in every
 * caller (fixed-width tags, keys and framed fields).
 *
 * Run: npx tsx --test src/lib/crypto/ct-equal.test.ts
 */
export function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}
