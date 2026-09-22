// src/lib/crypto/bundle-manifest.test.ts
// KAT + property tests for svrnty:manifest:v1 (grammar §4, Apollo's (b)).
// Frozen anchors: bundle_hash is SHA256 over the full canonical manifest bytes, so freezing it pins
// EVERY byte (any framing/order/width drift changes it). Full manifest_hex lives in the KAT vector
// (/app/shared/outbox/apollo/manifest_v1_kat_vector.json) for Flint's independent Python two-impl.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import {
  encodeManifest,
  computeBundleHash,
  serializeManifest,
  parseManifest,
  verifyServedManifest,
  MANIFEST_DOMAIN,
  type ManifestEntry,
} from './bundle-manifest.js';
import { lpStr, lpBin, u64be } from './lp-tlv.js';

// Intentionally UNSORTED input (proves sort-independence). Realistic app assets + case-sensitivity edge.
const PATHS = [
  '/sw.js',
  '/',
  '/manifest.json',
  '/_next/static/chunks/main.js',
  '/_next/static/chunks/app.js',
  '/icons/Icon-192.png',
  '/icons/icon-512.png',
];
function mkEntries(): ManifestEntry[] {
  return PATHS.map((p) => ({ path: p, contentHash: sha256(utf8ToBytes('svrnty-manifest-kat:content:' + p)) }));
}
// Expected canonical order: raw UTF-8 byte sort ('_'0x5f < 'i'0x69 < 'm'0x6d < 's'0x73; 'I'0x49 < 'i'0x69).
const SORTED_PATHS = [
  '/',
  '/_next/static/chunks/app.js',
  '/_next/static/chunks/main.js',
  '/icons/Icon-192.png',
  '/icons/icon-512.png',
  '/manifest.json',
  '/sw.js',
];

// --- Frozen KAT anchors (from _manifest_kat_emit.mts; mirror manifest_v1_kat_vector.json) ---
const BUNDLE_HASH_HEX = '2fef78485b54a635d01a3263f0c9dfb305fa3d45312c15ad8d7835ffb365b124';
const EMPTY_MANIFEST_HEX = '000000127376726e74793a6d616e69666573743a76310000000000000000';
const EMPTY_BUNDLE_HASH_HEX = 'ae66c74bfcfa92cbd3ea72fe6db4b768f34219c2dec7d076fab59769362a4147';
// lpStr("svrnty:manifest:v1") || u64be(7): the domain tag + entry count that must open every manifest.
const MANIFEST_PREFIX_HEX = '000000127376726e74793a6d616e69666573743a76310000000000000007';
const MANIFEST_LEN = 424;

test('KAT: bundle_hash + structural prefix + length are byte-locked', () => {
  const e = mkEntries();
  const bytes = encodeManifest(e);
  assert.equal(bytes.length, MANIFEST_LEN);
  assert.equal(bytesToHex(bytes).startsWith(MANIFEST_PREFIX_HEX), true);
  assert.equal(bytesToHex(computeBundleHash(e)), BUNDLE_HASH_HEX);
});

test('KAT: empty manifest is well-defined (domain + u64be(0))', () => {
  assert.equal(bytesToHex(encodeManifest([])), EMPTY_MANIFEST_HEX);
  assert.equal(bytesToHex(computeBundleHash([])), EMPTY_BUNDLE_HASH_HEX);
});

test('sort-independence: input order does not change the bytes (all 3 impls converge)', () => {
  const e = mkEntries();
  const reversed = e.slice().reverse();
  assert.equal(bytesToHex(encodeManifest(reversed)), bytesToHex(encodeManifest(e)));
  assert.equal(bytesToHex(computeBundleHash(reversed)), BUNDLE_HASH_HEX);
});

test('round-trip: parse(encode) yields canonical sorted entries, hashes preserved', () => {
  const e = mkEntries();
  const parsed = parseManifest(encodeManifest(e));
  assert.deepEqual(parsed.map((x) => x.path), SORTED_PATHS);
  const wantHash = new Map(e.map((x) => [x.path, bytesToHex(x.contentHash)]));
  for (const p of parsed) assert.equal(bytesToHex(p.contentHash), wantHash.get(p.path));
});

test('serializeManifest === encodeManifest (served bytes ARE the hashed bytes)', () => {
  const e = mkEntries();
  assert.equal(bytesToHex(serializeManifest(e)), bytesToHex(encodeManifest(e)));
});

test('verifyServedManifest: matches bundle_hash → entries; tampered bundle_hash → throws', () => {
  const e = mkEntries();
  const bytes = serializeManifest(e);
  const bh = computeBundleHash(e);
  assert.equal(verifyServedManifest(bytes, bh).length, e.length);
  const wrong = bh.slice();
  wrong[0] ^= 0xff;
  assert.throws(() => verifyServedManifest(bytes, wrong), /!=/);
});

test('encode rejects duplicate paths', () => {
  const h = sha256(utf8ToBytes('x'));
  assert.throws(
    () => encodeManifest([{ path: '/a', contentHash: h }, { path: '/a', contentHash: h }]),
    /duplicate path/,
  );
});

test('encode rejects a wrong-width content hash', () => {
  assert.throws(() => encodeManifest([{ path: '/a', contentHash: new Uint8Array(31) }]), /must be 32 bytes/);
});

test('parse is bounds-safe: trailing bytes / wrong domain / truncation all throw (never OOB read)', () => {
  const good = encodeManifest(mkEntries());
  const trailing = new Uint8Array(good.length + 1);
  trailing.set(good);
  assert.throws(() => parseManifest(trailing), /trailing bytes/);
  assert.throws(() => parseManifest(good.subarray(0, good.length - 5)), /exceeds buffer|truncated/);
  const wrongDom = good.slice();
  wrongDom[4] ^= 0xff; // flip a byte inside the domain string
  assert.throws(() => parseManifest(wrongDom), /wrong domain/);
});

test('parse rejects a served manifest that decodes to duplicate paths', () => {
  const h = sha256(utf8ToBytes('x'));
  const forged = concatBytes(lpStr(MANIFEST_DOMAIN), u64be(2), lpStr('/a'), lpBin(h), lpStr('/a'), lpBin(h));
  assert.throws(() => parseManifest(forged), /duplicate path .* in served manifest/);
});
