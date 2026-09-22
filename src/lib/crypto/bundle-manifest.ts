// src/lib/crypto/bundle-manifest.ts
/**
 * svrnty:manifest:v1 — Node Zero served-asset MANIFEST → bundle_hash (release grammar §4, Apollo's (b)).
 *
 * `bundle_hash` (the 32B field wire-committed into svrnty:release:v1's signing preimage — see
 * release-object.ts) is SHA256 over a DETERMINISTIC manifest of every asset the served app loads:
 * HTML shell, /_next/* chunks, sw.js itself, manifest.json, icons, and the verifier module (Q8 self-
 * inclusion). THREE independent implementations must produce byte-identical manifest bytes or every
 * verify false-mismatches (Flint #141748 — the critical cross-dependency):
 *   - the release SIGNER (G-C pipeline)           — computes bundle_hash to sign a release,
 *   - the G-D service-worker VERIFIER             — recomputes it to gate updates + per-asset SRI (WARN, never brick),
 *   - the external WATCHTOWER (off-origin monitor) — reconstructs it from served assets to diff the release log.
 * This module is the SINGLE canonical framing all three import (like release-object.ts). It does NOT
 * walk assets or read files — WHICH paths count, and the exact path STRING, are each consumer's
 * environment (build output / SW request.url / watchtower fetch) and MUST be pinned identically by the
 * caller (Athena's gd-pathname convention: URL.pathname, leading '/', no query/fragment, %-encoding
 * as-served, no decode). This module takes an already-hashed (path, contentHash) entry list and defines
 * the ONE canonical byte layout + bundle_hash over it.
 *
 * CANONICAL MANIFEST PREIMAGE (Apollo (b), grammar §4 — KAT-locked, pending Flint two-impl co-witness):
 *
 *   manifest = lpStr("svrnty:manifest:v1")               // domain tag (C1: distinct from release/beacon/mailbox/rotation)
 *            ‖ u64be(entryCount)                          // N — BARE fixed-width, self-delimiting (like version_counter/epoch)
 *            ‖ FOR each entry, sorted ASC by raw UTF-8 path BYTES:
 *                  lpStr(path) ‖ lpBin(contentHash[32])   // path variable → LP; hash → lpBin (matches release-object's lpBin(bundle_hash))
 *   bundle_hash = SHA256(manifest)
 *
 * LP(x)=uint32_be(byteLen(x))‖x is inherited byte-for-byte from lp-tlv.ts (already KAT'd; Flint
 * reproduced it 9/21). This module defines ONLY the domain tag, entry ORDER (deterministic byte-sort),
 * COUNT, and per-entry field widths — it never redefines the framing.
 *
 * PATH STRINGS ARE OPAQUE HERE: no decode, no normalization, no %-decoding. The manifest frames the
 * path string exactly as given; the caller guarantees the same (as-served) encoding across signer / SW
 * / watchtower. Sort is on the raw UTF-8 bytes of that string (NOT locale collation — byte order is the
 * only cross-language-deterministic choice Flint's Python two-impl can reproduce). Duplicate paths are
 * REJECTED (throw) — two entries for one path have no well-defined per-asset SRI lookup.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, utf8ToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { lpBin, lpStr, u64be } from './lp-tlv.js';

export const MANIFEST_DOMAIN = 'svrnty:manifest:v1';
const CONTENT_HASH_LEN = 32; // SHA256(asset content)

/** One manifest entry: an asset path and the SHA256 of its served bytes. */
export interface ManifestEntry {
  path: string; // origin-relative pathname, canonicalized identically by all consumers (the caller's contract)
  contentHash: Uint8Array; // 32B = SHA256(asset content)
}

/**
 * Compare two path strings by raw UTF-8 BYTES, ascending. Deterministic + language-portable
 * (Flint's Python reproduces via sorted(key=lambda p: p.encode('utf-8'))). NOT String.localeCompare.
 */
function compareUtf8Path(a: string, b: string): number {
  const ba = utf8ToBytes(a);
  const bb = utf8ToBytes(b);
  const n = Math.min(ba.length, bb.length);
  for (let i = 0; i < n; i++) {
    if (ba[i] !== bb[i]) return ba[i] - bb[i];
  }
  return ba.length - bb.length;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/**
 * Encode the canonical manifest preimage (Apollo (b), grammar §4). OUR encoder over OUR manifest —
 * throws on malformed input (wrong hash length, duplicate path). The returned bytes are EXACTLY what
 * SHA256 → bundle_hash, AND exactly what should be served (parseManifest reads them back verbatim).
 */
export function encodeManifest(entries: ManifestEntry[]): Uint8Array {
  const seen = new Set<string>();
  for (const e of entries) {
    if (e.contentHash.length !== CONTENT_HASH_LEN) {
      throw new Error(
        `bundle-manifest: contentHash for "${e.path}" must be ${CONTENT_HASH_LEN} bytes, got ${e.contentHash.length}`,
      );
    }
    if (seen.has(e.path)) {
      throw new Error(`bundle-manifest: duplicate path "${e.path}" — manifest paths must be unique`);
    }
    seen.add(e.path);
  }
  const sorted = entries.slice().sort((x, y) => compareUtf8Path(x.path, y.path));
  const parts: Uint8Array[] = [lpStr(MANIFEST_DOMAIN), u64be(entries.length)];
  for (const e of sorted) {
    parts.push(lpStr(e.path), lpBin(e.contentHash));
  }
  return concatBytes(...parts);
}

/**
 * bundle_hash = SHA256(encodeManifest(entries)) — the 32B committed into the release signing input
 * (release-object.ts). Used by the SIGNER (to sign a release) and the WATCHTOWER (to diff vs the log).
 */
export function computeBundleHash(entries: ManifestEntry[]): Uint8Array {
  return sha256(encodeManifest(entries));
}

/**
 * Serialize the manifest for serving alongside the signed release object (Q4a). The served bytes ARE
 * the hashed bytes — a client does SHA256(served)==release.bundle_hash with NO re-canonicalization,
 * then parseManifest() for the per-asset SRI map. Identity: serializeManifest === encodeManifest.
 */
export function serializeManifest(entries: ManifestEntry[]): Uint8Array {
  return encodeManifest(entries);
}

/**
 * STRICT bounds-safe parse of a served canonical manifest back into entries (for the SW per-asset SRI
 * map + the watchtower). Served over UNTRUSTED transport → throws a typed Error on ANY structural
 * malformation (out-of-bounds length, wrong domain, bad hash width, trailing bytes, duplicate path,
 * non-UTF-8 path); it NEVER reads past the buffer. AUTHENTICITY is NOT established here — the caller
 * MUST verify SHA256(bytes) === release.bundle_hash (that check also enforces canonical ordering, since
 * bundle_hash was computed over the canonical bytes). Use verifyServedManifest() to do both in order.
 *
 * The decoder is FATAL (Flint #142014): invalid UTF-8 → throw, not a silent U+FFFD. This makes the
 * parse-side dedup (on decoded strings) exactly mirror encode-side dedup (on raw bytes) — two distinct
 * byte-paths can no longer collide to one string — so the parser is safe even if called WITHOUT the
 * verifyServedManifest SHA256 gate. Authentic (verify-first) manifests always have valid-UTF-8 paths,
 * so this never rejects a legitimate manifest.
 */
export function parseManifest(bytes: Uint8Array): ManifestEntry[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const dec = new TextDecoder('utf-8', { fatal: true });
  let off = 0;
  const readLP = (): Uint8Array => {
    if (off + 4 > bytes.length) throw new Error('bundle-manifest: truncated length prefix');
    const len = view.getUint32(off, false);
    off += 4;
    if (off + len > bytes.length) throw new Error('bundle-manifest: length prefix exceeds buffer');
    const out = bytes.subarray(off, off + len);
    off += len;
    return out;
  };
  const domain = dec.decode(readLP());
  if (domain !== MANIFEST_DOMAIN) {
    throw new Error(`bundle-manifest: wrong domain "${domain}" (expected "${MANIFEST_DOMAIN}")`);
  }
  if (off + 8 > bytes.length) throw new Error('bundle-manifest: truncated entry count');
  const n = Number(view.getBigUint64(off, false));
  off += 8;
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('bundle-manifest: entry count out of range');
  const entries: ManifestEntry[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < n; i++) {
    const path = dec.decode(readLP());
    const contentHash = readLP();
    if (contentHash.length !== CONTENT_HASH_LEN) {
      throw new Error(`bundle-manifest: entry ${i} hash width ${contentHash.length} (expected ${CONTENT_HASH_LEN})`);
    }
    if (seen.has(path)) throw new Error(`bundle-manifest: duplicate path "${path}" in served manifest`);
    seen.add(path);
    entries.push({ path, contentHash: contentHash.slice() }); // copy out of the shared buffer
  }
  if (off !== bytes.length) throw new Error('bundle-manifest: trailing bytes after manifest');
  return entries;
}

/**
 * The SAFE entry point for the SW + watchtower: verify SHA256(served) === expectedBundleHash FIRST
 * (authenticity + canonicality), THEN parse. Throws if the served bytes don't match the signed
 * bundle_hash (→ the SW folds this into WARN, never brick). Returns the per-asset entries on success.
 */
export function verifyServedManifest(bytes: Uint8Array, expectedBundleHash: Uint8Array): ManifestEntry[] {
  const got = sha256(bytes);
  if (!bytesEqual(got, expectedBundleHash)) {
    throw new Error(
      `bundle-manifest: served manifest hash ${bytesToHex(got)} != release.bundle_hash ${bytesToHex(expectedBundleHash)}`,
    );
  }
  return parseManifest(bytes);
}
