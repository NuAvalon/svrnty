// src/lib/crypto/beacon-public-inputs.ts
// #588 R1 (Flint 532343bb): the CANONICAL encoding of the slot-binding proof's public inputs {e, H_e, N, K}, enforced BEFORE any proof is verified.
// In-circuit values live mod p (the BN254 scalar field), so N and N+p are the same field element. Whether a verifier library rejects N+p is
// the LIBRARY's business and version-dependent (snarkjs 0.7.6 does, measured; others reduce); the matcher's dedupe and match rule are OURS and must
// never see two spellings of one value. So exactly ONE spelling is accepted: 32 bytes big-endian as 64 lowercase hex characters, value < p.
// Anything else (0x prefix, uppercase, short/leading-zero-stripped, decimal, negative, whitespace, a number/bigint, >= p) is refused.

/** The BN254 scalar field order (circom / snarkjs `bn128`). */
export const BN254_P = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const ZERO = BigInt(0);

export const PUBLIC_INPUT_KEYS = ['e', 'H_e', 'N', 'K'] as const;
export type PublicInputKey = (typeof PUBLIC_INPUT_KEYS)[number];

/** The values the verifier sees: canonical field elements. */
export type PublicInputs = Record<PublicInputKey, bigint>;
/** What travels on the wire: the pinned spelling of each, as strings. */
export type WirePublicInputs = Record<PublicInputKey, string>;

const CANONICAL = /^[0-9a-f]{64}$/;

/** The one spelling of a field element. THROWS for a value outside [0, p) (a caller bug, never wire input). */
export function encodeCanonical(v: bigint): string {
  if (typeof v !== 'bigint' || v < ZERO || v >= BN254_P) throw new RangeError('encodeCanonical: not a canonical field element');
  return v.toString(16).padStart(64, '0');
}

/** The value of a canonical spelling, or null for ANY other input (never throws). */
export function parseCanonical(s: unknown): bigint | null {
  if (typeof s !== 'string' || !CANONICAL.test(s)) return null;
  const v = BigInt('0x' + s);
  return v < BN254_P ? v : null;
}

/** All four public inputs, exactly those four keys, each canonical; else null. */
export function parsePublicInputs(w: unknown): PublicInputs | null {
  if (typeof w !== 'object' || w === null || Array.isArray(w)) return null;
  const keys = Object.keys(w);
  if (keys.length !== PUBLIC_INPUT_KEYS.length || !PUBLIC_INPUT_KEYS.every((k) => keys.includes(k))) return null;
  const out = {} as PublicInputs;
  for (const k of PUBLIC_INPUT_KEYS) {
    const v = parseCanonical((w as Record<string, unknown>)[k]);
    if (v === null) return null;
    out[k] = v;
  }
  return out;
}
