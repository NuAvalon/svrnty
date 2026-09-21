// src/lib/crypto/release-object.test.ts
//
// KAT for the svrnty:release:v1 release-object grammar (Flint pin #141747, mint-gate G-B).
// Runner: node --import tsx --test src/lib/crypto/release-object.test.ts
//
// The 6 §6 vectors. Fixtures are DETERMINISTIC and documented (byte-fills + fixed seeds) so Flint's
// independent encoder reproduces the signing_input + fp byte-for-byte (two-impl lock, same loop as the
// mailbox keystone). Only the PREIMAGE is byte-locked; signatures are verified, not byte-compared
// (ML-DSA signing need not be deterministic across impls).

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
function makeReleaseA(versionCounter: number, epoch: number, publisherFp = A_FP_RAW, bundleHash = BUNDLE_HASH): ReleaseObject {
  const si = encodeReleaseSigningInput({ publisherFp, bundleHash, versionCounter, epoch });
  return { bundleHash, versionCounter, epoch, sig: signRelease(si, A_ED_SEED, aDsa.secretKey) };
}

// ── Vector 1: fp preimage (P4/P5) — order sign‖enc‖kem‖sig, independent recompute ──
test('KAT-1 publisher_fp preimage = SHA256(sign32 ‖ enc32 ‖ kem1568 ‖ sig2592)', () => {
  const independent = bytesToHex(sha256(concatBytes(A_GENESIS.signPub, A_GENESIS.encPub, A_GENESIS.kemPub, A_GENESIS.sigPub)));
  assert.equal(A_FP_HEX, independent, 'canonical fp must equal independent SHA256 over sign‖enc‖kem‖sig');
  assert.equal(A_FP_HEX.length, 64);
  // lengths are the FIPS surface (32/32/1568/2592 = 4224 preimage bytes)
  assert.equal(A_GENESIS.signPub.length + A_GENESIS.encPub.length + A_GENESIS.kemPub.length + A_GENESIS.sigPub.length, 4224);
});

// ── Vector 2: signing_input byte-lock (the two-impl anchor) ──
test('KAT-2 signing_input = lpStr(domain)‖lpStr(suite)‖lpBin(fp)‖lpBin(bundle)‖u64be(ctr)‖u64be(epoch), BARE u64be', () => {
  const si = encodeReleaseSigningInput({ publisherFp: A_FP_RAW, bundleHash: BUNDLE_HASH, versionCounter: 1, epoch: 0 });
  // Independent structural re-assembly (field-set / order / widths) over the already-KAT'd lp-tlv helpers.
  const expected = concatBytes(
    lpStr(RELEASE_DOMAIN),
    lpStr(SUITE_HYBRID),
    lpBin(A_FP_RAW),
    lpBin(BUNDLE_HASH),
    u64be(1),
    u64be(0),
  );
  assert.deepEqual(si, expected, 'encoder must match the documented field structure');
  assert.equal(si.length, 130, 'preimage length: 21+21+36+36+8+8 = 130 (BARE u64be, no LP wrapper)');
  // Guard against a silent LP-wrap regression on the counters: the last 16 bytes are two bare u64be.
  assert.deepEqual(si.subarray(114, 122), u64be(1), 'version_counter is bare u64be (bytes 114..122)');
  assert.deepEqual(si.subarray(122, 130), u64be(0), 'epoch is bare u64be (bytes 122..130)');
  assert.equal(SUITE_HYBRID, 'ed25519+ml-dsa-87', 'suite id literal is the sign-envelope constant');
});

// ── Vector 3: hybrid two-leg sign/verify + BOTH-legs-required ──
test('KAT-3 both legs required — flip either leg, truncate, or wrong pubkey ⇒ reject', () => {
  const si = encodeReleaseSigningInput({ publisherFp: A_FP_RAW, bundleHash: BUNDLE_HASH, versionCounter: 1, epoch: 0 });
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
  // HWM = 5: a validly-signed counter=6 is accepted, HWM advances.
  const r6 = recognizeRelease({ ...common, release: makeReleaseA(6, 0), hwm: 5 });
  assert.equal(r6.accepted, true, 'counter 6 > HWM 5 ⇒ accept');
  assert.equal(r6.newHwm, 6, 'HWM advances to 6');
  // counter == HWM ⇒ reject (never equal)
  const r5 = recognizeRelease({ ...common, release: makeReleaseA(5, 0), hwm: 5 });
  assert.equal(r5.accepted, false, 'counter 5 == HWM 5 ⇒ reject');
  assert.equal(r5.newHwm, 5, 'HWM unchanged on reject');
  // counter < HWM ⇒ reject even though the signature is valid (the verifier never goes backwards)
  const r4 = recognizeRelease({ ...common, release: makeReleaseA(4, 0), hwm: 5 });
  assert.equal(r4.accepted, false, 'valid-but-older counter 4 < HWM 5 ⇒ reject (anti-rollback)');
});

// ── Vector 5: substitution-reject (fp ≠ SHA256(presented pubkeys)) ──
test('KAT-5 substitution: presented genesis pubkeys must hash to the pin', () => {
  // Present a genesis whose signPub is swapped ⇒ derived fp ≠ pinned A_FP.
  const tampered: NodeZeroGenesisPubkeys = { ...A_GENESIS, signPub: bEdPub };
  const res = recognizeRelease({
    release: makeReleaseA(1, 0),
    releasePublisherFp: A_FP_RAW,
    pinnedPublisherFp: A_FP_HEX,
    hwm: 0,
    epochSigningKeys: A_EPOCH_KEYS,
    presentedGenesis: tampered,
  });
  assert.equal(res.accepted, false, 'fp != SHA256(pubkeys) ⇒ reject');
  assert.match(res.reason ?? '', /SHA256/);
  // sanity: the same call with the HONEST genesis accepts (isolates the substitution check)
  const ok = recognizeRelease({
    release: makeReleaseA(1, 0), releasePublisherFp: A_FP_RAW, pinnedPublisherFp: A_FP_HEX,
    hwm: 0, epochSigningKeys: A_EPOCH_KEYS, presentedGenesis: A_GENESIS,
  });
  assert.equal(ok.accepted, true, 'honest genesis ⇒ accept');
});

// ── Vector 6: cross-lineage replay reject (publisher_fp binding is CRYPTOGRAPHIC, not a label) ──
test('KAT-6 cross-lineage: A-release under pinned B rejected; relabel attack fails at verify', () => {
  const aRelease = makeReleaseA(1, 0); // honest, publisher_fp = A
  // 6a: A's honest release under B's pin ⇒ reject at anchor-binding (release claims A, pin is B).
  const r6a = recognizeRelease({
    release: aRelease, releasePublisherFp: A_FP_RAW, pinnedPublisherFp: B_FP_HEX,
    hwm: 0, epochSigningKeys: B_EPOCH_KEYS, presentedGenesis: undefined,
  });
  assert.equal(r6a.accepted, false, 'A-release under pinned B ⇒ reject');
  assert.match(r6a.reason ?? '', /anchor/);
  // 6b: attacker RELABELS the release to claim B (to pass anchor-binding). The re-encoded preimage now
  //     differs from what A signed ⇒ two-leg verify under B's keys fails. Binding is load-bearing.
  const r6b = recognizeRelease({
    release: aRelease, releasePublisherFp: B_FP_RAW, pinnedPublisherFp: B_FP_HEX,
    hwm: 0, epochSigningKeys: B_EPOCH_KEYS, presentedGenesis: undefined,
  });
  assert.equal(r6b.accepted, false, 'relabeled A-release under B ⇒ reject at signature');
  assert.match(r6b.reason ?? '', /signature/);
});
