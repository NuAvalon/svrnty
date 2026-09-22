// src/sw/gd-verifycore.e2e.test.ts
// End-to-end verify-core KAT: sign a REAL release over a REAL §4 manifest with a test genesis, then assert the
// G-D verify layer (gd-verify.verifyReleaseEpoch0 + bundle-manifest.verifyServedManifest + gd-verify-flow's
// verifyAsset/verifyShell/shellHashSet) ACCEPTS the honest bundle and REJECTS tampered variants. This exercises
// the actual @noble crypto + the frozen release-object/manifest grammars through MY wrappers — the mint-critical
// path — without the IndexedDB/Cache persistence layers (those are thin wrappers over these pure functions).
// Runner: node --import tsx --test src/sw/gd-verifycore.e2e.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { deriveCanonicalFingerprintHex } from '../lib/identity/fingerprint.js';
import { encodeReleaseSigningInput, signRelease, type ReleaseObject } from '../lib/crypto/release-object.js';
import { computeBundleHash, serializeManifest, verifyServedManifest, type ManifestEntry } from '../lib/crypto/bundle-manifest.js';
import { verifyReleaseEpoch0, type PinnedLineage } from './gd-verify.js';
import { verifyAsset, verifyShell, shellHashSet } from './gd-verify-flow.js';

const fill = (len: number, byte: number) => new Uint8Array(len).fill(byte);

// ── test genesis (deterministic; enc/kem pubs are fills — only in the fp preimage, never in the release sig) ──
const ED_SEED = fill(32, 0x11);
const DSA_SEED = fill(32, 0x22);
const ENC_PUB = fill(32, 0x33);
const KEM_PUB = fill(1568, 0x44);
const edPub = ed25519.getPublicKey(ED_SEED);
const dsa = ml_dsa87.keygen(DSA_SEED);
const GENESIS = { signPub: edPub, encPub: ENC_PUB, kemPub: KEM_PUB, sigPub: dsa.publicKey };
const FP_HEX = deriveCanonicalFingerprintHex(GENESIS.signPub, GENESIS.encPub, GENESIS.kemPub, GENESIS.sigPub);
const FP_RAW = hexToBytes(FP_HEX);

// ── a REAL bundle: one static chunk + one shell (route-template path) ──
const CHUNK_PATH = '/_next/static/chunks/main-abc123.js';
const CHUNK_BYTES = new TextEncoder().encode('self.__chunk=1;console.log("main");');
const SHELL_PATH = '/u/[name]'; // route-template → manifestPathClass 'shell'
const SHELL_BYTES = new TextEncoder().encode('<!doctype html><html><body>RESOLVING…<script src="/_next/static/chunks/main-abc123.js"></script></body></html>');
const ENTRIES: ManifestEntry[] = [
  { path: CHUNK_PATH, contentHash: sha256(CHUNK_BYTES) },
  { path: SHELL_PATH, contentHash: sha256(SHELL_BYTES) },
];
const BUNDLE_HASH = computeBundleHash(ENTRIES);
const MANIFEST_BYTES = serializeManifest(ENTRIES);

function makeRelease(versionCounter: number, epoch: number, bundleHash = BUNDLE_HASH, publisherFp = FP_RAW): ReleaseObject {
  const si = encodeReleaseSigningInput({ publisherFp, bundleHash, versionCounter, epoch });
  return { bundleHash, versionCounter, epoch, sig: signRelease(si, ED_SEED, dsa.secretKey) };
}
function pinned(hwm: number): PinnedLineage {
  return { publisherFpHex: FP_HEX, genesis: GENESIS, hwm, followedEpoch: 0 };
}
// The accepted path→hashHex map (what loadAcceptedManifest builds from the verified manifest bytes).
function acceptedMap(bytes: Uint8Array): Map<string, string> {
  const entries = verifyServedManifest(bytes, BUNDLE_HASH);
  const m = new Map<string, string>();
  for (const e of entries) m.set(e.path, bytesToHex(e.contentHash));
  return m;
}

test('E2E-1 honest release verifies (epoch-0), HWM advances 0→1', () => {
  const res = verifyReleaseEpoch0(makeRelease(1, 0), FP_RAW, pinned(0));
  assert.equal(res.accepted, true, 'honest epoch-0 release accepts');
  assert.equal(res.newHwm, 1, 'HWM advances to the release counter');
});

test('E2E-2 served manifest binds to the signed bundle_hash; a tampered manifest is rejected', () => {
  const entries = verifyServedManifest(MANIFEST_BYTES, BUNDLE_HASH); // SHA256(served)==bundle_hash then parse
  assert.equal(entries.length, 2);
  const tampered = Uint8Array.from(MANIFEST_BYTES);
  tampered[tampered.length - 1] ^= 0x01;
  assert.throws(() => verifyServedManifest(tampered, BUNDLE_HASH), 'manifest that does not hash to bundle_hash throws');
});

test('E2E-3 per-asset SRI: exact-path static verify (ok / mismatch / unknown)', () => {
  const m = acceptedMap(MANIFEST_BYTES);
  assert.equal(verifyAsset(m, CHUNK_PATH, CHUNK_BYTES), 'ok', 'honest chunk bytes verify');
  const tampered = Uint8Array.from(CHUNK_BYTES);
  tampered[0] ^= 0x01;
  assert.equal(verifyAsset(m, CHUNK_PATH, tampered), 'mismatch', 'a swapped chunk is a mismatch');
  assert.equal(verifyAsset(m, '/_next/static/chunks/other.js', CHUNK_BYTES), 'unknown', 'a path not in the manifest is unknown');
});

test('E2E-4 shell content-hash membership: only the shell hash is in the set; static is not', () => {
  const m = acceptedMap(MANIFEST_BYTES);
  const shells = shellHashSet(m);
  assert.equal(shells.size, 1, 'exactly one shell entry (/u/[name])');
  assert.ok(shells.has(bytesToHex(sha256(SHELL_BYTES))), 'the shell hash is in the set');
  assert.ok(!shells.has(bytesToHex(sha256(CHUNK_BYTES))), 'the static chunk hash is NOT a shell');
  assert.equal(verifyShell(shells, SHELL_BYTES), 'ok', 'served shell matches the publisher set');
  const tampered = Uint8Array.from(SHELL_BYTES);
  tampered[10] ^= 0x01;
  assert.equal(verifyShell(shells, tampered), 'mismatch', 'an injected/swapped shell is a mismatch');
});

test('E2E-5 fail-closed: epoch != 0 rejected (no silent accept)', () => {
  const res = verifyReleaseEpoch0(makeRelease(1, 1), FP_RAW, pinned(0));
  assert.equal(res.accepted, false, 'epoch 1 rejected at launch');
  assert.match(res.reason ?? '', /epoch/);
});

test('E2E-6 anti-rollback: counter must be strictly > HWM', () => {
  assert.equal(verifyReleaseEpoch0(makeRelease(3, 0), FP_RAW, pinned(2)).accepted, true, '3 > HWM 2 accepts');
  assert.equal(verifyReleaseEpoch0(makeRelease(2, 0), FP_RAW, pinned(2)).accepted, false, '2 == HWM 2 rejects');
  assert.equal(verifyReleaseEpoch0(makeRelease(1, 0), FP_RAW, pinned(2)).accepted, false, 'valid-but-older 1 < HWM 2 rejects');
});

test('E2E-7 anchor-binding: a release for a different pinned lineage is rejected', () => {
  const wrongFp = hexToBytes(deriveCanonicalFingerprintHex(ed25519.getPublicKey(fill(32, 0x99)), ENC_PUB, KEM_PUB, dsa.publicKey));
  const res = verifyReleaseEpoch0(makeRelease(1, 0), wrongFp, pinned(0));
  assert.equal(res.accepted, false, 'releasePublisherFp != pinned anchor ⇒ reject');
});

test('E2E-8 tampered signature is rejected (both-legs hybrid)', () => {
  const r = makeRelease(1, 0);
  const badSig = Uint8Array.from(r.sig);
  badSig[0] ^= 0x01; // corrupt the ed25519 leg
  const res = verifyReleaseEpoch0({ ...r, sig: badSig }, FP_RAW, pinned(0));
  assert.equal(res.accepted, false, 'corrupt sig ⇒ reject');
});
