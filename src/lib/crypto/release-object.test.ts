// src/lib/crypto/release-object.test.ts
//
// KAT for the svrnty:release:v1 release-object grammar (Flint pin #141747; grammar_version per Peter
// ruling #142110 + Flint refinements #142106). Runner: node --import tsx --test src/lib/crypto/release-object.test.ts
//
// The §6 vectors + grammar-version dispatch. Fixtures are DETERMINISTIC and documented (byte-fills +
// fixed seeds) so Flint's independent encoder reproduces the signing_input + fp byte-for-byte (two-impl
// lock). Only the PREIMAGE is byte-locked; signatures are verified, not byte-compared (ML-DSA signing
// need not be deterministic across impls).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js';
import { lpStr, lpBin, u64be } from './lp-tlv.js';
import { SUITE_HYBRID } from './sign-envelope.js';
import { deriveCanonicalFingerprintHex } from '../identity/fingerprint.js';
import {
  RELEASE_DOMAIN,
  RELEASE_GRAMMAR_VERSION,
  encodeReleaseSigningInput,
  signRelease,
  verifyReleaseSig,
  recognizeRelease,
  type ReleaseObject,
  type NodeZeroGenesisPubkeys,
} from './release-object.js';

const fill = (len: number, byte: number) => new Uint8Array(len).fill(byte);

// ── Node Zero genesis, publisher A (deterministic) ──
const A_ED_SEED = fill(32, 0x11);
const A_DSA_SEED = fill(32, 0x22);
const A_ENC_PUB = fill(32, 0x33); // x25519 enc pub — only in the fp preimage, never in the release sig
const A_KEM_PUB = fill(1568, 0x44); // ml-kem-1024 ek — only in the fp preimage
const aEdPub = ed25519.getPublicKey(A_ED_SEED);
const aDsa = ml_dsa87.keygen(A_DSA_SEED); // { publicKey, secretKey }
const A_GENESIS: NodeZeroGenesisPubkeys = { signPub: aEdPub, encPub: A_ENC_PUB, kemPub: A_KEM_PUB, sigPub: aDsa.publicKey };
const A_FP_HEX = deriveCanonicalFingerprintHex(A_GENESIS.signPub, A_GENESIS.encPub, A_GENESIS.kemPub, A_GENESIS.sigPub);
const A_FP_RAW = hexToBytes(A_FP_HEX);
const A_EPOCH_KEYS = { edPub: aEdPub, dsaPub: aDsa.publicKey };

// ── Node Zero genesis, publisher B (a DIFFERENT lineage — for cross-lineage tests) ──
const B_ED_SEED = fill(32, 0x55);
const B_DSA_SEED = fill(32, 0x66);
const bEdPub = ed25519.getPublicKey(B_ED_SEED);
const bDsa = ml_dsa87.keygen(B_DSA_SEED);
const B_FP_HEX = deriveCanonicalFingerprintHex(bEdPub, fill(32, 0x77), fill(1568, 0x88), bDsa.publicKey);
const B_FP_RAW = hexToBytes(B_FP_HEX);
const B_EPOCH_KEYS = { edPub: bEdPub, dsaPub: bDsa.publicKey };

const BUNDLE_HASH = fill(32, 0xab);

/** Sign a release for publisher A over the exact frozen preimage. */
function makeReleaseA(
  versionCounter: number,
  epoch: number,
  publisherFp = A_FP_RAW,
  bundleHash = BUNDLE_HASH,
  grammarVersion = RELEASE_GRAMMAR_VERSION,
): ReleaseObject {
  const si = encodeReleaseSigningInput({ grammarVersion, publisherFp, bundleHash, versionCounter, epoch });
  return { grammarVersion, bundleHash, versionCounter, epoch, sig: signRelease(si, A_ED_SEED, aDsa.secretKey) };
}

// ── Vector 1: fp preimage (P4/P5) — order sign‖enc‖kem‖sig, independent recompute ──
test('KAT-1 publisher_fp preimage = SHA256(sign32 ‖ enc32 ‖ kem1568 ‖ sig2592)', () => {
  const independent = bytesToHex(sha256(concatBytes(A_GENESIS.signPub, A_GENESIS.encPub, A_GENESIS.kemPub, A_GENESIS.sigPub)));
  assert.equal(A_FP_HEX, independent, 'canonical fp must equal independent SHA256 over sign‖enc‖kem‖sig');
  assert.equal(A_FP_HEX.length, 64);
  // lengths are the FIPS surface (32/32/1568/2592 = 4224 preimage bytes)
  assert.equal(A_GENESIS.signPub.length + A_GENESIS.encPub.length + A_GENESIS.kemPub.length + A_GENESIS.sigPub.length, 4224);
});

// ── Vector 2: signing_input byte-lock (the two-impl anchor) — NOW with grammar_version ──
test('KAT-2 signing_input = lpStr(domain)‖u64be(gv)‖lpStr(suite)‖lpBin(fp)‖lpBin(bundle)‖u64be(ctr)‖u64be(epoch), BARE u64be', () => {
  const si = encodeReleaseSigningInput({ grammarVersion: 1, publisherFp: A_FP_RAW, bundleHash: BUNDLE_HASH, versionCounter: 1, epoch: 0 });
  // Independent structural re-assembly (field-set / order / widths) over the already-KAT'd lp-tlv helpers.
  const expected = concatBytes(
    lpStr(RELEASE_DOMAIN),
    u64be(1), // grammar_version
    lpStr(SUITE_HYBRID),
    lpBin(A_FP_RAW),
    lpBin(BUNDLE_HASH),
    u64be(1), // version_counter
    u64be(0), // epoch
  );
  assert.deepEqual(si, expected, 'encoder must match the documented field structure');
  assert.equal(si.length, 138, 'preimage length: 21+8+21+36+36+8+8 = 138 (BARE u64be, no LP wrapper; +8 grammar_version)');
  // Position guards: grammar_version at [21,29); version_counter at [122,130); epoch at [130,138).
  assert.deepEqual(si.subarray(21, 29), u64be(1), 'grammar_version is bare u64be (bytes 21..29), right after the domain tag');
  assert.deepEqual(si.subarray(122, 130), u64be(1), 'version_counter is bare u64be (bytes 122..130)');
  assert.deepEqual(si.subarray(130, 138), u64be(0), 'epoch is bare u64be (bytes 130..138)');
  assert.equal(SUITE_HYBRID, 'ed25519+ml-dsa-87', 'suite id literal is the sign-envelope constant');
  assert.equal(RELEASE_GRAMMAR_VERSION, 1, 'v1 grammar version');
});

// ── Vector 3: hybrid two-leg sign/verify + BOTH-legs-required ──
test('KAT-3 both legs required — flip either leg, truncate, or wrong pubkey ⇒ reject', () => {
  const si = encodeReleaseSigningInput({ grammarVersion: 1, publisherFp: A_FP_RAW, bundleHash: BUNDLE_HASH, versionCounter: 1, epoch: 0 });
  const sig = signRelease(si, A_ED_SEED, aDsa.secretKey);
  assert.equal(verifyReleaseSig(si, sig, aEdPub, aDsa.publicKey), true, 'honest sig verifies');

  const flipEd = Uint8Array.from(sig); flipEd[0] ^= 0x01; // corrupt ed leg
  assert.equal(verifyReleaseSig(si, flipEd, aEdPub, aDsa.publicKey), false, 'corrupt ed leg ⇒ reject');
  const flipDsa = Uint8Array.from(sig); flipDsa[64] ^= 0x01; // corrupt first dsa byte
  assert.equal(verifyReleaseSig(si, flipDsa, aEdPub, aDsa.publicKey), false, 'corrupt dsa leg ⇒ reject');

  assert.equal(verifyReleaseSig(si, sig.subarray(0, 64), aEdPub, aDsa.publicKey), false, 'ed-only (no dsa leg) ⇒ reject');
  assert.equal(verifyReleaseSig(si, sig, bEdPub, aDsa.publicKey), false, 'wrong ed pubkey ⇒ reject');
  assert.equal(verifyReleaseSig(si, sig, aEdPub, bDsa.publicKey), false, 'wrong dsa pubkey ⇒ reject');
  // preimage tamper (any bit) ⇒ reject
  const si2 = Uint8Array.from(si); si2[si2.length - 1] ^= 0x01;
  assert.equal(verifyReleaseSig(si2, sig, aEdPub, aDsa.publicKey), false, 'tampered preimage ⇒ reject');
});

// ── Vector 4: anti-rollback high-water-mark ──
test('KAT-4 anti-rollback: counter must be strictly > HWM (equal and lower both rejected)', () => {
  const common = { releasePublisherFp: A_FP_RAW, pinnedPublisherFp: A_FP_HEX, epochSigningKeys: A_EPOCH_KEYS, presentedGenesis: A_GENESIS };
  const r6 = recognizeRelease({ ...common, release: makeReleaseA(6, 0), hwm: 5 });
  assert.equal(r6.accepted, true, 'counter 6 > HWM 5 ⇒ accept');
  assert.equal(r6.newHwm, 6, 'HWM advances to 6');
  const r5 = recognizeRelease({ ...common, release: makeReleaseA(5, 0), hwm: 5 });
  assert.equal(r5.accepted, false, 'counter 5 == HWM 5 ⇒ reject');
  assert.equal(r5.newHwm, 5, 'HWM unchanged on reject');
  const r4 = recognizeRelease({ ...common, release: makeReleaseA(4, 0), hwm: 5 });
  assert.equal(r4.accepted, false, 'valid-but-older counter 4 < HWM 5 ⇒ reject (anti-rollback)');
});

// ── Vector 5: substitution-reject (fp ≠ SHA256(presented pubkeys)) ──
test('KAT-5 substitution: presented genesis pubkeys must hash to the pin', () => {
  const tampered: NodeZeroGenesisPubkeys = { ...A_GENESIS, signPub: bEdPub };
  const res = recognizeRelease({
    release: makeReleaseA(1, 0), releasePublisherFp: A_FP_RAW, pinnedPublisherFp: A_FP_HEX,
    hwm: 0, epochSigningKeys: A_EPOCH_KEYS, presentedGenesis: tampered,
  });
  assert.equal(res.accepted, false, 'fp != SHA256(pubkeys) ⇒ reject');
  assert.match(res.reason ?? '', /SHA256/);
  const ok = recognizeRelease({
    release: makeReleaseA(1, 0), releasePublisherFp: A_FP_RAW, pinnedPublisherFp: A_FP_HEX,
    hwm: 0, epochSigningKeys: A_EPOCH_KEYS, presentedGenesis: A_GENESIS,
  });
  assert.equal(ok.accepted, true, 'honest genesis ⇒ accept');
});

// ── Vector 6: cross-lineage replay reject (publisher_fp binding is CRYPTOGRAPHIC, not a label) ──
test('KAT-6 cross-lineage: A-release under pinned B rejected; relabel attack fails at verify', () => {
  const aRelease = makeReleaseA(1, 0); // honest, publisher_fp = A
  const r6a = recognizeRelease({
    release: aRelease, releasePublisherFp: A_FP_RAW, pinnedPublisherFp: B_FP_HEX,
    hwm: 0, epochSigningKeys: B_EPOCH_KEYS, presentedGenesis: undefined,
  });
  assert.equal(r6a.accepted, false, 'A-release under pinned B ⇒ reject');
  assert.match(r6a.reason ?? '', /anchor/);
  const r6b = recognizeRelease({
    release: aRelease, releasePublisherFp: B_FP_RAW, pinnedPublisherFp: B_FP_HEX,
    hwm: 0, epochSigningKeys: B_EPOCH_KEYS, presentedGenesis: undefined,
  });
  assert.equal(r6b.accepted, false, 'relabeled A-release under B ⇒ reject at signature');
  assert.match(r6b.reason ?? '', /signature/);
});

// ── Vector 7: grammar-version DISPATCH (Peter #142110 + Flint refinements #142106) ──
test('KAT-7 grammar-version: ahead⇒updateRequired(distinct); invalid⇒reject; version is bound; encode rejects gv<1', () => {
  const common = { releasePublisherFp: A_FP_RAW, pinnedPublisherFp: A_FP_HEX, epochSigningKeys: A_EPOCH_KEYS, presentedGenesis: A_GENESIS };

  // (1) version AHEAD of this client ⇒ benign, DISTINCT "update required" — NOT a forgery/anchor reject,
  //     and NOT accepted. This is the state Peter's addendum requires to render differently from an attack.
  const ahead = makeReleaseA(1, 0, A_FP_RAW, BUNDLE_HASH, RELEASE_GRAMMAR_VERSION + 1); // gv=2, validly signed
  const rAhead = recognizeRelease({ ...common, release: ahead, hwm: 0 });
  assert.equal(rAhead.accepted, false, 'version-ahead ⇒ not accepted');
  assert.equal(rAhead.updateRequired, true, 'version-ahead ⇒ updateRequired (a THIRD, benign state)');
  assert.match(rAhead.reason ?? '', /update required/i);

  // (2) invalid grammar_version (0) ⇒ reject (never throws), and it is a REJECT not an updateRequired.
  const bad: ReleaseObject = { grammarVersion: 0, bundleHash: BUNDLE_HASH, versionCounter: 1, epoch: 0, sig: new Uint8Array(64 + 100) };
  const rBad = recognizeRelease({ ...common, release: bad, hwm: 0 });
  assert.equal(rBad.accepted, false, 'invalid grammar_version ⇒ reject');
  assert.equal(rBad.updateRequired, undefined, 'invalid version is a REJECT, not updateRequired');
  assert.match(rBad.reason ?? '', /invalid grammar_version/);

  // (3) BIND-CONSISTENCY (Flint refinement 2): grammar_version is in the signed preimage, so changing it
  //     changes the bytes and a sig over gv=1 does NOT verify over gv=2 ⇒ mis-dispatch spoofing fails.
  const si1 = encodeReleaseSigningInput({ grammarVersion: 1, publisherFp: A_FP_RAW, bundleHash: BUNDLE_HASH, versionCounter: 1, epoch: 0 });
  const si2 = encodeReleaseSigningInput({ grammarVersion: 2, publisherFp: A_FP_RAW, bundleHash: BUNDLE_HASH, versionCounter: 1, epoch: 0 });
  assert.notDeepEqual(si1, si2, 'grammar_version is BOUND — changing it changes the preimage');
  const sig1 = signRelease(si1, A_ED_SEED, aDsa.secretKey);
  assert.equal(verifyReleaseSig(si1, sig1, aEdPub, aDsa.publicKey), true, 'sig over gv=1 verifies over gv=1');
  assert.equal(verifyReleaseSig(si2, sig1, aEdPub, aDsa.publicKey), false, 'sig over gv=1 does NOT verify over gv=2 (bound)');

  // (4) encoder rejects grammar_version < 1 (our-side malformed input).
  assert.throws(
    () => encodeReleaseSigningInput({ grammarVersion: 0, publisherFp: A_FP_RAW, bundleHash: BUNDLE_HASH, versionCounter: 1, epoch: 0 }),
    /grammar_version must be/,
  );

  // (5) ⭐ VERSION-SPOOF at the recognize layer (Flint #142134 case 4b — the critical anti-bypass): a
  //     release SIGNED over gv=2 but presenting WIRE grammar_version=1 (to force v1-verify) ⇒ recognize
  //     dispatches v1, re-encodes with gv=1, and the sig (over gv=2) FAILS ⇒ reject at signature. The
  //     pre-verify dispatch read is a HINT; it can NEVER bypass the signed-version bind.
  const si2signed = encodeReleaseSigningInput({ grammarVersion: 2, publisherFp: A_FP_RAW, bundleHash: BUNDLE_HASH, versionCounter: 1, epoch: 0 });
  const spoof: ReleaseObject = { grammarVersion: 1, bundleHash: BUNDLE_HASH, versionCounter: 1, epoch: 0, sig: signRelease(si2signed, A_ED_SEED, aDsa.secretKey) };
  const rSpoof = recognizeRelease({ ...common, release: spoof, hwm: 0 });
  assert.equal(rSpoof.accepted, false, 'v2-signed object claiming wire gv=1 ⇒ reject');
  assert.equal(rSpoof.updateRequired, undefined, 'spoof is a forgery reject, NOT update-required (no attack-WARN dodge)');
  assert.match(rSpoof.reason ?? '', /signature/);

  // sanity: an honest current-version release still fully verifies (isolates the dispatch from the rest).
  const okv1 = recognizeRelease({ ...common, release: makeReleaseA(1, 0), hwm: 0 });
  assert.equal(okv1.accepted, true, 'honest v1 release ⇒ accept');
  assert.equal(okv1.updateRequired, undefined, 'accepted release has no updateRequired flag');
});
