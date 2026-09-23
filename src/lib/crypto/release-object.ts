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
 * FROZEN SIGNING PREIMAGE (Flint pin #141747; grammar_version added per Peter ruling #142110 + Flint's
 * 4 refinements #142106 — KAT these exact bytes, this order):
 *
 *   payload = lpStr("svrnty:release:v1")     // domain tag  (C1: distinct from mailbox-ptr/beacon/reg/rotation)
 *           ‖ u64be(grammar_version)         // BARE — release-object FORMAT version (§29-to-itself). Read from the
 *                                            //   wire object BEFORE verification to DISPATCH grammar (see recognizeRelease);
 *                                            //   BOUND here so a tampered wire version fails verify (dispatch==signed).
 *           ‖ lpStr(SUITE_HYBRID)            // "ed25519+ml-dsa-87" — the EXACT sign-envelope.ts constant (anti-downgrade, matches buildSignedBytes suite-binding)
 *           ‖ lpBin(publisher_fp[32])        // binds THIS Node Zero lineage (belt-and-suspenders vs cross-lineage replay + wrong-pubkey selection; a bound field can be ignored, an unbound one can't be added later without a flag day)
 *           ‖ lpBin(bundle_hash[32])         // SHA256 over the served-asset manifest
 *           ‖ u64be(version_counter)         // BARE fixed-width (self-delimiting — NO LP wrapper). DISTINCT from grammar_version: this is the anti-rollback RELEASE counter (§3), grammar_version is the FORMAT version.
 *           ‖ u64be(epoch)                   // BARE fixed-width — Node Zero key-epoch that signed this release
 *
 * WHY grammar_version (pre-mint-or-never): a wire-readable format version lets a client that is BEHIND
 * recognize a future-grammar release as "update required" (a benign, distinct state) instead of a
 * verification failure indistinguishable from a forgery. Because adding a signed-preimage field AFTER
 * mint is itself the flag-day we're avoiding, the field must exist from v1. (Peter #142110; Flint #142106.)
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
import { SUITE_HYBRID } from './sign-envelope-framing';
// Reuse the canonical fp preimage (P4 = identical to the user fingerprint) — never reimplement it.
import { deriveCanonicalFingerprintHex, normalizeFingerprintHex } from '../identity/fingerprint-canonical';

export const RELEASE_DOMAIN = 'svrnty:release:v1';

/**
 * The release-object grammar-FORMAT version THIS client understands (Peter #142110). It is read from
 * the wire object BEFORE verification to DISPATCH which grammar to verify under, and is BOUND in the
 * signed preimage. A release whose grammar_version EXCEEDS this is a benign "update required" state,
 * NOT a reject/forgery. DISTINCT from ReleaseObject.versionCounter (the anti-rollback release counter).
 * Bump ONLY when the release-object wire format itself changes (and retain older grammars for backward
 * verification when you do, keeping the anti-rollback counter check on every verify branch).
 *
 * ORTHOGONAL VERSION AXES (Flint #142163) — do NOT conflate: the domain-tag ":v1" is the PROTOCOL-
 * GENERATION separator (cross-protocol domain separation; a nuclear/hard break, essentially NEVER
 * bumped), while grammar_version is the read-first FORMAT version — the forward-compat dispatch axis
 * that actually evolves. Which to bump for a future release-object format change? grammar_version.
 * The domain ":vN" essentially never (only a total protocol re-generation). Both are bound in the
 * preimage; they are different axes, not redundant.
 */
export const RELEASE_GRAMMAR_VERSION = 1;

const FP_LEN = 32; // publisher_fp = SHA256(sign32 ‖ enc32 ‖ kem1568 ‖ sig2592) — 32B
const BUNDLE_HASH_LEN = 32; // SHA256 over the served-asset manifest
const ED_SIG_LEN = 64; // Ed25519 signature

/** The immutable, signed fields of a release (sig is over the encoded preimage of the other five). */
export interface ReleaseObject {
  grammarVersion: number; // uint64, release-object FORMAT version (read-first-dispatch, bound). NOT versionCounter.
  bundleHash: Uint8Array; // 32
  versionCounter: number; // uint64, strictly monotonic per-lineage, starts at 1 (anti-rollback)
  epoch: number; // uint64, Node Zero key-epoch that signed this release
  sig: Uint8Array; // ed25519(64B) ‖ ML-DSA-87 sig
}

/**
 * Encode the FROZEN signing preimage (Flint pin #141747 + grammar_version #142110). publisher_fp and
 * bundle_hash are raw 32B. grammar_version / version_counter / epoch are BARE u64be (fixed width,
 * self-delimiting — no LP wrapper). This is OUR encoder over our own release object; it throws on
 * malformed input (not an attacker-input surface — verification parses attacker input elsewhere).
 */
export function encodeReleaseSigningInput(args: {
  grammarVersion: number; // release-object FORMAT version (bound; read-first-dispatch)
  publisherFp: Uint8Array; // 32 raw (the pinned Node Zero lineage anchor)
  bundleHash: Uint8Array; // 32 raw
  versionCounter: number;
  epoch: number;
}): Uint8Array {
  if (!Number.isSafeInteger(args.grammarVersion) || args.grammarVersion < 1) throw new Error(`grammar_version must be a safe integer >= 1, got ${args.grammarVersion}`);
  if (args.publisherFp.length !== FP_LEN) throw new Error(`publisher_fp must be ${FP_LEN}B, got ${args.publisherFp.length}`);
  if (args.bundleHash.length !== BUNDLE_HASH_LEN) throw new Error(`bundle_hash must be ${BUNDLE_HASH_LEN}B, got ${args.bundleHash.length}`);
  // version_counter starts at 1 (§3); both counters must be exactly representable (u64be tolerates <2^53).
  if (!Number.isSafeInteger(args.versionCounter) || args.versionCounter < 1) throw new Error(`version_counter must be a safe integer >= 1, got ${args.versionCounter}`);
  if (!Number.isSafeInteger(args.epoch) || args.epoch < 0) throw new Error(`epoch must be a non-negative safe integer, got ${args.epoch}`);
  return concatBytes(
    lpStr(RELEASE_DOMAIN),
    u64be(args.grammarVersion), // FORMAT version — BARE; bound so a tampered dispatch-version fails verify
    lpStr(SUITE_HYBRID),
    lpBin(args.publisherFp),
    lpBin(args.bundleHash),
    u64be(args.versionCounter), // BARE — anti-rollback release counter (NOT the format version)
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

/**
 * Structured outcome KIND for the §3 WARN-ceremony to switch on (Flint #142163 — NEVER reason-strings;
 * string-matching in a security ceremony is brittle). Only 'attack' fires the scary tampering WARN
 * (+ markDiverged); the rest are benign so the scary warning keeps its credibility for real attacks:
 *   • 'accept'          — verified & adopted.
 *   • 'update-required' — grammar_version ahead of this client → calm UPDATE-REQUIRED (Peter #142110).
 *   • 'attack'          — anchor-mismatch / fp-substitution / signature-invalid → scary WARN + markDiverged.
 *   • 'malformed'       — invalid/unsupported grammar_version or malformed genesis pubkeys → benign ignore/retry
 *                         (corrupt ≠ attack; a truncated fetch / CDN hiccup must not cry wolf).
 *   • 'stale'           — anti-rollback (counter ≤ HWM) → benign keep-current (client already protected).
 */
export type RecognizeKind = 'accept' | 'update-required' | 'attack' | 'malformed' | 'stale';

export interface RecognizeResult {
  accepted: boolean;
  /** structured outcome — SWITCH ON THIS in the WARN-ceremony, never the reason string (Flint #142163). */
  kind: RecognizeKind;
  /** the high-water-mark AFTER this decision (unchanged on reject; = version_counter on accept). */
  newHwm: number;
  /**
   * Convenience alias for kind === 'update-required' (Peter #142110 addendum term). Always consistent
   * with `kind`. TRUE iff this release's grammar_version is AHEAD of what this client understands — a
   * benign "client update required" state the UI MUST render as UPDATE-REQUIRED, never the under-attack
   * warning ("different truths must look different"; else cry-wolf erodes the real warning).
   */
  updateRequired?: boolean;
  reason?: string;
}

/**
 * recognize(publisher_fp, ReleaseObject, version_counter) — the Node Zero instantiation of the shared
 * recognition core generalized from PR#139 (verifyMailboxPointer / selectLatestValidPointer). Same four
 * moves, param'd: (a) anchor-binding, (b) substitution-reject, (c) two-leg verify, (d) anti-rollback —
 * preceded by (0) a FAIL-SAFE pre-verify grammar dispatch.
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
  const reject = (kind: RecognizeKind, reason: string): RecognizeResult => ({ accepted: false, kind, newHwm: hwm, reason });

  // (0) PRE-VERIFY GRAMMAR DISPATCH (Flint #142106 refinements 1+3; Peter #142110). grammar_version is
  //     read from UNVERIFIED wire bytes ONLY to choose which grammar to verify under. Every branch is
  //     fail-safe and NO branch accepts/serves anything unverified:
  //       • ahead of us  → DISTINCT benign updateRequired (render as UPDATE-REQUIRED, NOT a forgery warning)
  //       • older/unknown → reject 'malformed' (this v1 build retains only RELEASE_GRAMMAR_VERSION)
  //       • ==ours       → verify under this grammar below (version re-encoded → tamper fails verify)
  const gv = args.release.grammarVersion;
  if (!Number.isSafeInteger(gv) || gv < 1) return reject('malformed', `invalid grammar_version ${gv}`);
  if (gv > RELEASE_GRAMMAR_VERSION) {
    return { accepted: false, kind: 'update-required', newHwm: hwm, updateRequired: true, reason: `grammar_version ${gv} ahead of client ${RELEASE_GRAMMAR_VERSION} — client update required` };
  }
  if (gv !== RELEASE_GRAMMAR_VERSION) {
    // gv < RELEASE_GRAMMAR_VERSION: an OLDER grammar. A future multi-version client would retain the
    // older grammar and verify under it WITH the same anti-rollback counter check (Flint refinement 4).
    // This v1 build understands exactly RELEASE_GRAMMAR_VERSION → older/unknown is refused (client is
    // ahead, not behind → NOT updateRequired). MALFORMED (unsupported), not attack. Unreachable while
    // RELEASE_GRAMMAR_VERSION === 1.
    return reject('malformed', `unsupported grammar_version ${gv}`);
  }

  // (a) anchor-binding / cross-lineage-replay reject: the release must claim the pinned lineage. ATTACK.
  if (bytesToHex(args.releasePublisherFp) !== pinned) return reject('attack', 'publisher_fp != pinned anchor');

  // (b) substitution-reject: presented genesis pubkeys must hash to the pin before we trust them.
  if (args.presentedGenesis) {
    const g = args.presentedGenesis;
    let derived: string;
    try {
      derived = deriveCanonicalFingerprintHex(g.signPub, g.encPub, g.kemPub, g.sigPub);
    } catch {
      return reject('malformed', 'genesis pubkeys malformed'); // corrupt input, not tampering evidence
    }
    if (derived !== pinned) return reject('attack', 'fp != SHA256(pubkeys)'); // key-substitution = ATTACK
  }

  // (c) two-leg verify over the EXACT frozen preimage (re-encoded here — never trust a caller-supplied
  //     blob). grammar_version is BOUND here (dispatch==signed): a wire grammar_version != the signed
  //     one changes the preimage → verify fails → prevents mis-dispatch spoofing (Flint refinement 2).
  const signingInput = encodeReleaseSigningInput({
    grammarVersion: gv,
    publisherFp: args.releasePublisherFp,
    bundleHash: args.release.bundleHash,
    versionCounter: args.release.versionCounter,
    epoch: args.release.epoch,
  });
  if (!verifyReleaseSig(signingInput, args.release.sig, args.epochSigningKeys.edPub, args.epochSigningKeys.dsaPub)) {
    return reject('attack', 'signature invalid'); // known-version + bad sig = tampering evidence = ATTACK
  }

  // (d) anti-rollback: strictly greater than the high-water-mark. Never equal, never lower — even a
  //     validly-signed older release is refused (the verifier never goes backwards). This ADOPT branch
  //     runs the counter check on every accepted release regardless of grammar_version (refinement 4).
  //     A valid-but-older release is STALE (replay / stale-cache), NOT an attack — benign keep-current.
  if (!(args.release.versionCounter > hwm)) {
    return reject('stale', `rollback: version_counter ${args.release.versionCounter} <= HWM ${hwm}`);
  }

  return { accepted: true, kind: 'accept', newHwm: args.release.versionCounter };
}
