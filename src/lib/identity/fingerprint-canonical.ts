// src/lib/identity/fingerprint-canonical.ts
// The openpgp-FREE canonical-fingerprint core of fingerprint.ts: the FIPS pubkey lengths, the byte
// coercion helper, and the two pure functions the RELEASE SIGNER path needs —
// deriveCanonicalFingerprintHex (SHA256(sign‖enc‖kem‖sig)) and normalizeFingerprintHex.
//
// Split out of fingerprint.ts (which imports `readKey` from openpgp for its armored-key / PWA
// identity helpers) so the air-gap release signer + release-object derive the canonical fingerprint
// WITHOUT dragging openpgp into the bundle. @noble-only. Byte-IDENTICAL to the original fingerprint.ts
// definitions — fingerprint.ts now imports + re-exports from here, so every existing importer is
// unaffected and NO fingerprint bytes change.
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

export const SIGN_PUB_LEN = 32;
export const ENC_PUB_LEN = 32;
export const KEM_PUB_LEN = 1568;
export const SIG_PUB_LEN = 2592;

/** Lowercase hex only — strips spaces, colons, 0x, etc. */
export function normalizeFingerprintHex(raw: string): string {
  return (raw || '').toLowerCase().replace(/[^0-9a-f]/g, '');
}

export function asU8(value: unknown, label: string): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value && typeof (value as { length?: unknown }).length === 'number') {
    return new Uint8Array(value as ArrayLike<number>);
  }
  throw new Error(`canonical fingerprint: ${label} is not bytes`);
}

/**
 * SHA256(sign ‖ enc ‖ kem ‖ sig) as lowercase hex (64 chars).
 * Throws if any key is not the required FIPS length — never mint a truncated bundle.
 */
export function deriveCanonicalFingerprintHex(
  signPub: Uint8Array,
  encPub: Uint8Array,
  kemPub: Uint8Array,
  sigPub: Uint8Array,
): string {
  const sign = asU8(signPub, 'sign');
  const enc = asU8(encPub, 'enc');
  const kem = asU8(kemPub, 'kem');
  const sig = asU8(sigPub, 'sig');
  if (
    sign.length !== SIGN_PUB_LEN ||
    enc.length !== ENC_PUB_LEN ||
    kem.length !== KEM_PUB_LEN ||
    sig.length !== SIG_PUB_LEN
  ) {
    throw new Error('canonical fingerprint: a public key is not the required length');
  }
  const bundle = new Uint8Array(SIGN_PUB_LEN + ENC_PUB_LEN + KEM_PUB_LEN + SIG_PUB_LEN);
  bundle.set(sign, 0);
  bundle.set(enc, SIGN_PUB_LEN);
  bundle.set(kem, SIGN_PUB_LEN + ENC_PUB_LEN);
  bundle.set(sig, SIGN_PUB_LEN + ENC_PUB_LEN + KEM_PUB_LEN);
  return bytesToHex(sha256(bundle));
}
