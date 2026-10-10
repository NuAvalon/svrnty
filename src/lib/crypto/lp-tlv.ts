// src/lib/crypto/lp-tlv.ts
/**
 * LP-TLV — the length-prefixed binary framing shared by svrnty's client-only byte crypto.
 *
 *   LP(x)   = uint32_be(byteLen(x)) ‖ x        (Flint byte-pin #141596, guard 1)
 *   LP(str) = LP(utf8(str))
 *   u64be(n)= unsigned 64-bit big-endian
 *
 * Injective by fixed-width length prefix (no parse-until-delimiter subtlety), so concatenations
 * cannot boundary-shift into a second preimage regardless of field contents.
 *
 * WHY THIS FILE EXISTS (Flint's tracked "lpBin → shared-util promote" follow-up, minimal slice):
 * the exact same helper is currently inlined privately in trust-rendezvous.ts (R + beacon preimage)
 * and exported from hybrid-seal.ts (note-seal). Flint's guard 1 is "never inline-duplicate — copies
 * diverge." The mailbox-pointer grammar (KB#90104 item 4) needs it too, so rather than add a THIRD
 * copy this is the shared low-level home. Byte-IDENTICAL to both existing copies — pinned by lp-tlv
 * KATs (00000000 / 00000001ab / 00000100…) that mirror hybrid-seal.test.ts + trust-rendezvous vectors.
 * Rewiring trust-rendezvous.ts + hybrid-seal.ts to import from here is the REMAINDER of Flint's
 * follow-up (byte-identical, its own KAT re-run) — intentionally NOT done here to keep this diff tight.
 *
 * FRAMING SCOPE (Flint guard 2): binary-TLV is for STRUCTURALLY CLIENT-ONLY byte crypto — the relay
 * cannot compute R nor open/verify the sealed beacon/pointer, so no cross-language reproducer exists.
 * DISTINCT from sign-envelope.ts `lengthPrefix` (decimal-colon netstring, for CROSS-LANGUAGE signed
 * objects a Python satellite re-verifies). Do not conflate the two — right framing per domain.
 */
import { utf8ToBytes } from '@noble/hashes/utils.js';

/** LP(x) = uint32_be(byteLen(x)) ‖ x. */
export function lpBin(x: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + x.length);
  new DataView(out.buffer).setUint32(0, x.length, false); // big-endian length prefix
  out.set(x, 4);
  return out;
}

/** utf8-then-length-prefix, for string fields (domain tags, DIDs). */
export function lpStr(s: string): Uint8Array {
  return lpBin(utf8ToBytes(s));
}

/** epoch as unsigned 64-bit big-endian (fixed width — no decimal-length variance). */
export function u64be(n: number): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), false); // big-endian
  return b;
}
