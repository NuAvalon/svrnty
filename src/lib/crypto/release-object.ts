// src/lib/crypto/release-object.ts
/**
 * svrnty:release:v1 — Node Zero RELEASE-OBJECT grammar (Flint pin #141747, mint-gate G-B).
 *
 * A release object binds one code bundle to Node Zero's key lineage at a point in its version
 * history. Early clients pin Node Zero's fingerprint at first install (P4) and, on every update,
 * verify the served bundle against a signed release object from the pinned lineage (G-D). This is
 * the PERMANENT, mint-gate-frozen surface: it is wire-committed into what already-signed releases
 * verify against, so the preimage below is byte-KAT-locked before a single wallet is minted.
 *
 * FROZEN SIGNING PREIMAGE (Flint pin #141747 — KAT these exact bytes, this order):
 *
 *   payload = lpStr("svrnty:release:v1")     // domain tag  (C1: distinct from mailbox-ptr/beacon/reg/rotation)
 *           ‖ lpStr(SUITE_HYBRID)            // "ed25519+ml-dsa-87" — the EXACT sign-envelope.ts constant (anti-downgrade, matches buildSignedBytes suite-binding)
 *           ‖ lpBin(publisher_fp[32])        // binds THIS Node Zero lineage (belt-and-suspenders vs cross-lineage replay + wrong-pubkey selection; a bound field can be ignored, an unbound one can't be added later without a flag day)
 *           ‖ lpBin(bundle_hash[32])         // SHA256 over the served-asset manifest
 *           ‖ u64be(version_counter)         // BARE fixed-width (self-delimiting — NO LP wrapper; corrects the grammar-doc §1 LP(u64be) redundancy per #141747)
 *           ‖ u64be(epoch)                   // BARE fixed-width — Node Zero key-epoch that signed this release
 *
 * LP(x) = uint32_be(byteLen(x)) ‖ x is inherited byte-for-byte from crypto/lp-tlv.ts (already
 * KAT'd; Flint reproduced it 9/21). This module DEFINES ONLY the field-set / order / widths — it does
 * not redefine the framing.
 *
 * SIGNATURE: sig = ed25519_sign(k_ed^epoch, payload) ‖ ml_dsa87_sign(k_dsa^epoch, payload), under Node
 * Zero's epoch-`epoch` signing keys. Verify = BOTH legs valid (same two-leg discipline as
 * fingerprint.ts verifyRotationAuthority) against the pubkeys the client derives by following its
 * pinned NZ lineage to `epoch`. The suite binding makes a strip-to-classical downgrade change the
 * payload, so the surviving classical leg no longer verifies.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { bytesToHex, concatBytes } from '@noble/hashes/utils.js';
import { lpBin, lpStr, u64be } from './lp-tlv.js';
// The suite id is the EXACT constant the rest of svrnty binds (anti-downgrade); never hand-typed here.
import { SUITE_HYBRID } from './sign-envelope.js';
// Reuse the canonical fp preimage (P4 = identical to the user fingerprint) — never reimplement it.
import { deriveCanonicalFingerprintHex, normalizeFingerprintHex } from '../identity/fingerprint.js';

export const RELEASE_DOMAIN = 'svrnty:release:v1';

const FP_LEN = 32; // publisher_fp = SHA256(sign32 ‖ enc32 ‖ kem1568 ‖ sig2592) — 32B
const BUNDLE_HASH_LEN = 32; // SHA256 over the served-asset manifest
const ED_SIG_LEN = 64; // Ed25519 signature

/** The immutable, signed fields of a release (sig is over the encoded preimage of the other four). */
export interface ReleaseObject {
  bundleHash: Uint8Array; // 32
  versionCounter: number; // uint64, strictly monotonic per-lineage, starts at 1
  epoch: number; // uint64, Node Zero key-epoch that signed this release
  sig: Uint8Array; // ed25519(64B) ‖ ML-DSA-87 sig
}

/**
 * Encode the FROZEN signing preimage (Flint pin #141747). publisher_fp and bundle_hash are raw 32B.
 * version_counter / epoch are BARE u64be (fixed width, self-delimiting — no LP wrapper). This is OUR
 * encoder over our own release object; it throws on malformed input (not an attacker-input surface —
 * verification parses attacker input elsewhere).
 */
export function encodeReleaseSigningInput(args: {
  publisherFp: Uint8Array; // 32 raw (the pinned Node Zero lineage anchor)
  bundleHash: Uint8Array; // 32 raw
  versionCounter: number;
  epoch: number;
}): Uint8Array {
  if (args.publisherFp.length !== FP_LEN) throw new Error(`publisher_fp must be ${FP_LEN}B, got ${args.publisherFp.length}`);
  if (args.bundleHash.length !== BUNDLE_HASH_LEN) throw new Error(`bundle_hash must be ${BUNDLE_HASH_LEN}B, got ${args.bundleHash.length}`);
  // version_counter starts at 1 (§3); both counters must be exactly representable (u64be tolerates <2^53).
  if (!Number.isSafeInteger(args.versionCounter) || args.versionCounter < 1) throw new Error(`version_counter must be a safe integer >= 1, got ${args.versionCounter}`);
  if (!Number.isSafeInteger(args.epoch) || args.epoch < 0) throw new Error(`epoch must be a non-negative safe integer, got ${args.epoch}`);
  return concatBytes(
    lpStr(RELEASE_DOMAIN),
    lpStr(SUITE_HYBRID),
    lpBin(args.publisherFp),
    lpBin(args.bundleHash),
    u64be(args.versionCounter), // BARE — NOT lpBin(u64be(...))
    u64be(args.epoch), // BARE
  );
}

/**
 * Produce the hybrid two-leg signature over the encoded preimage: ed25519(64B) ‖ ML-DSA-87 sig, under
 * Node Zero's epoch signing secrets. (The KAT does not byte-compare sig bytes — ML-DSA signing is not
 * required to be deterministic across impls — only the PREIMAGE is byte-locked; sigs are verified.)
 */
export function signRelease(signingInput: Uint8Array, edSecret: Uint8Array, dsaSecret: Uint8Array): Uint8Array {
  return concatBytes(ed25519.sign(signingInput, edSecret), ml_dsa87.sign(signingInput, dsaSecret));
}

/**
 * Verify BOTH legs of a release signature over `signingInput` under the epoch-`epoch` public keys.
 * Returns false (never throws) on any malformation or either-leg failure — an attacker-input surface.
 * BOTH legs required: a stripped/forged leg fails the whole check.
 */
export function verifyReleaseSig(signingInput: Uint8Array, sig: Uint8Array, edPub: Uint8Array, dsaPub: Uint8Array): boolean {
  if (sig.length <= ED_SIG_LEN) return false;
  const edSig = sig.subarray(0, ED_SIG_LEN);
  const dsaSig = sig.subarray(ED_SIG_LEN);
  try {
    if (!ed25519.verify(edSig, signingInput, edPub)) return false;
    return ml_dsa87.verify(dsaSig, signingInput, dsaPub);
  } catch {
    return false;
  }
}

// ── Recognition core (Flint §2): recognize(anchor, object, counterField), Node Zero instantiation ──

/** Node Zero genesis pubkeys — the fp preimage set (P4/P5). signPub/sigPub double as epoch-0 signing keys. */
export interface NodeZeroGenesisPubkeys {
  signPub: Uint8Array; // ed25519 32  (also epoch-0 ed signing pubkey)
  encPub: Uint8Array; // x25519 32
  kemPub: Uint8Array; // ml-kem-1024 1568
  sigPub: Uint8Array; // ml-dsa-87 2592  (also epoch-0 dsa signing pubkey)
}

export interface RecognizeResult {
  accepted: boolean;
  /** the high-water-mark AFTER this decision (unchanged on reject; = version_counter on accept). */
  newHwm: number;
  reason?: string;
}

/**
 * recognize(publisher_fp, ReleaseObject, version_counter) — the Node Zero instantiation of the shared
 * recognition core generalized from PR#139 (verifyMailboxPointer / selectLatestValidPointer). Same four
 * moves, param'd: (a) anchor-binding, (b) substitution-reject, (c) two-leg verify, (d) anti-rollback.
 *
 * `epochSigningKeys` are the pubkeys obtained by following the pinned lineage to `release.epoch` (for the
 * genesis/epoch-0 case they are the genesis signPub/sigPub). `presentedGenesis`, when supplied, is
 * checked to hash to the pinned anchor (substitution-reject) before its keys are trusted.
 * Never throws — an attacker-input surface.
 */
export function recognizeRelease(args: {
  release: ReleaseObject;
  releasePublisherFp: Uint8Array; // the publisher_fp bound inside THIS release's preimage (32B)
  pinnedPublisherFp: string; // the client's first-install pin (64-hex) = the lineage anchor
  hwm: number; // current high-water-mark
  epochSigningKeys: { edPub: Uint8Array; dsaPub: Uint8Array }; // derived by following the pinned lineage to release.epoch
  presentedGenesis?: NodeZeroGenesisPubkeys; // if present: prove fp == SHA256(pubkeys)
}): RecognizeResult {
  const pinned = normalizeFingerprintHex(args.pinnedPublisherFp);
  const hwm = args.hwm;
  const reject = (reason: string): RecognizeResult => ({ accepted: false, newHwm: hwm, reason });

  // (a) anchor-binding / cross-lineage-replay reject: the release must claim the pinned lineage.
  if (bytesToHex(args.releasePublisherFp) !== pinned) return reject('publisher_fp != pinned anchor');

  // (b) substitution-reject: presented genesis pubkeys must hash to the pin before we trust them.
  if (args.presentedGenesis) {
    const g = args.presentedGenesis;
    let derived: string;
    try {
      derived = deriveCanonicalFingerprintHex(g.signPub, g.encPub, g.kemPub, g.sigPub);
    } catch {
      return reject('genesis pubkeys malformed');
    }
    if (derived !== pinned) return reject('fp != SHA256(pubkeys)');
  }

  // (c) two-leg verify over the EXACT frozen preimage (re-encoded here — never trust a caller-supplied blob).
  const signingInput = encodeReleaseSigningInput({
    publisherFp: args.releasePublisherFp,
    bundleHash: args.release.bundleHash,
    versionCounter: args.release.versionCounter,
    epoch: args.release.epoch,
  });
  if (!verifyReleaseSig(signingInput, args.release.sig, args.epochSigningKeys.edPub, args.epochSigningKeys.dsaPub)) {
    return reject('signature invalid');
  }

  // (d) anti-rollback: strictly greater than the high-water-mark. Never equal, never lower — even a
  //     validly-signed older release is refused (the verifier never goes backwards).
  if (!(args.release.versionCounter > hwm)) {
    return reject(`rollback: version_counter ${args.release.versionCounter} <= HWM ${hwm}`);
  }

  return { accepted: true, newHwm: args.release.versionCounter };
}
