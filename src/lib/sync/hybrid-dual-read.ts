// src/lib/sync/hybrid-dual-read.ts
// L7 living-book HYBRID-SLEEVE consume dual-read (Apollo's seam; Flint's integration map #168137).
//
// The living-book deposits (notes / contact-updates / joiner-responses / trust-affirms) are migrating
// from a classical OpenPGP seal to the EXISTING hybrid mailbox envelope (sealToMailbox, X25519+ML-KEM-1024,
// reject-classical — src/lib/crypto/mailbox-envelope.ts). During the migration a mailbox holds BOTH blob
// shapes, so every per-type consume `verify` must DUAL-READ: try the hybrid opener first, fall back to the
// classical opener for in-flight OpenPGP blobs. Once the fleet's in-flight classical blobs DRAIN (no real
// users yet — Peter #168078), the classical fallback is removed; isPQEncapLive flips WITH the first real
// hybrid caller + e2e (claim-gates.ts, test-locked).
//
// NO NEW CRYPTO: this is pure composition over Flint's injected openMailboxEnvelope + the per-type wire
// parsers the classical path already uses. The crypto (envelope open) + the owner-secrets are INJECTED, so
// this module is unit-testable with stubs and decoupled from the sleeve's key-extraction.
//
// INVARIANTS PRESERVED (verified by the tests + the consume-mailbox demux, unchanged):
//  • 4-WAY NO-CROSS-SWALLOW: the hybrid opener returns null for a package whose INNER wire is not THIS
//    type (same verify-first-per-type discriminator as classical) → the seam falls through, never eats
//    another type. The envelope-shape is NOT the discriminator; the inner wire-type still is.
//  • NO SILENT-LOSS: a non-hybrid blob (armored PGP), a wrong-key open (null), OR a malformed/throwing
//    hybrid parse ALL fall through to the classical opener — a hybrid-parse failure can never strand an
//    in-flight classical blob. ack-follows-persist is downstream + unchanged (this only swaps the open step).

import type { MailboxEnvelopePackage } from '@/lib/crypto/mailbox-envelope';

/**
 * Shape-discriminator (Flint #168137): a hybrid blob is the MailboxEnvelopePackage JSON ({v:1, epk, kem_ct,
 * nonce, ct}); a classical blob is armored PGP (`-----BEGIN PGP MESSAGE-----`, not JSON). Unambiguous:
 * armored PGP never JSON-parses to this shape. Fail-closed — any missing/mistyped field ⇒ not-a-package.
 */
export function asMailboxEnvelopePackage(blob: string): MailboxEnvelopePackage | null {
  let obj: unknown;
  try {
    obj = JSON.parse(blob);
  } catch {
    return null; // armored PGP / non-JSON → classical
  }
  if (!obj || typeof obj !== 'object') return null;
  const o = obj as Record<string, unknown>;
  if (o.v !== 1) return null;
  if (typeof o.mailbox_fp !== 'string') return null;
  if (typeof o.epk !== 'string' || typeof o.kem_ct !== 'string') return null;
  if (typeof o.nonce !== 'string' || typeof o.ct !== 'string') return null;
  return o as unknown as MailboxEnvelopePackage;
}

/** Open the hybrid envelope to the inner plaintext bytes (owner-secrets bound by the caller), or null. */
export type EnvelopeOpener = (pkg: MailboxEnvelopePackage) => Promise<Uint8Array | null>;

/** Parse decrypted inner bytes as THIS deposit type's wire, or null if it is not that type (the per-type
 *  discriminator — identical to the classical path's type-check, so no-cross-swallow is unchanged). */
export type WireParser<T> = (innerUtf8: string) => T | null;

/**
 * Build a per-type HYBRID opener (Flint's makeHybridOpener shape): blob → MailboxEnvelopePackage? →
 * openEnvelope → inner bytes → parse as THIS type's wire → T | null. Returns null (never throws) for:
 * a non-package blob (→ classical fallback), a wrong-key/corrupt open, or an inner wire of another type
 * (→ the demux falls through, no cross-swallow).
 */
export function makeHybridOpener<T>(openEnvelope: EnvelopeOpener, parseWire: WireParser<T>): (blob: string) => Promise<T | null> {
  return async (blob: string): Promise<T | null> => {
    const pkg = asMailboxEnvelopePackage(blob);
    if (!pkg) return null; // not a hybrid envelope → classical fallback
    let inner: Uint8Array | null;
    try {
      inner = await openEnvelope(pkg);
    } catch {
      return null; // wrong keys / corrupt → not-ours-hybrid; classical fallback still tried by the dual-read
    }
    if (!inner) return null;
    try {
      return parseWire(new TextDecoder().decode(inner));
    } catch {
      return null; // inner not JSON / not this type
    }
  };
}

/**
 * Compose a hybrid opener + a classical opener into one dual-read `verify`: try hybrid FIRST, fall back to
 * classical. The ONLY thing the migration changes per seam. Fail-safe both ways: a null OR throwing hybrid
 * open falls through to classical (no in-flight classical blob is ever stranded = no silent-loss); both
 * null ⇒ null ⇒ the consume demux falls through to the next type (no-cross-swallow, unchanged).
 */
export function dualReadOpener<T>(
  hybridOpen: (blob: string) => Promise<T | null>,
  classicalOpen: (blob: string) => Promise<T | null>,
): (blob: string) => Promise<T | null> {
  return async (blob: string): Promise<T | null> => {
    try {
      const viaHybrid = await hybridOpen(blob);
      if (viaHybrid != null) return viaHybrid;
    } catch {
      /* defensive: a throwing hybrid open must not strand the classical fallback */
    }
    return classicalOpen(blob);
  };
}
