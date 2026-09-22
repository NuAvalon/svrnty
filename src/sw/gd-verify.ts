// src/sw/gd-verify.ts
// Node Zero G-D — release verification core (EPOCH-0 launch), reusing the pinned release-object grammar.
//
// This wraps release-object.ts `recognizeRelease` (Flint pin #141747, svrnty:release:v1, KAT 6/6 green) for
// the launch/epoch-0 case: the founding cohort pins Node Zero's genesis at first install; genesis signPub/sigPub
// ARE the epoch-0 signing keys, so there is NO rotation-epoch-walk at launch (cross-epoch ADOPT-UPDATE is a
// post-launch fast-follow — Apollo's epoch-walk spec, out of scope here).
//
// SCOPE: this verifies the RELEASE OBJECT (two-leg sig + anchor-binding + anti-rollback). It does NOT here
// check that the SERVED BUNDLE hashes to release.bundleHash — that is the manifest step (§4, coordinated with
// Apollo) done in the verify-flow. Kept separate so this crypto core is small + auditable (verdict §6 / Q8:
// the verify module is TCB and self-included in the signed bundle).
//
// Never throws — the release object is served by a possibly-compromised origin (attacker-input surface).

import {
  recognizeRelease,
  type ReleaseObject,
  type NodeZeroGenesisPubkeys,
  type RecognizeResult,
} from '../lib/crypto/release-object.js';

/**
 * The client's pinned Node Zero lineage, captured at first install (§5 pin format) and persisted next to the
 * pin. Epoch-0 launch: `genesis.signPub`/`genesis.sigPub` double as the epoch-0 signing pubkeys.
 */
export interface PinnedLineage {
  publisherFpHex: string; // 64-hex = SHA256(sign32 ‖ enc32 ‖ kem1568 ‖ sig2592) — the lineage anchor
  genesis: NodeZeroGenesisPubkeys; // signPub(32) / encPub(32) / kemPub(1568) / sigPub(2592)
  hwm: number; // high-water-mark (starts at 0; = last accepted version_counter)
  followedEpoch: 0; // launch is epoch-0 only
}

/**
 * Verify a served release object against the pinned lineage, EPOCH-0 only.
 *
 * Returns the RecognizeResult ({accepted, newHwm, reason}). On accept, `newHwm` is the release's
 * version_counter (the caller persists it only after the SERVED BUNDLE also matches the manifest).
 *
 * A release claiming epoch != 0 is rejected here (fail-CLOSED, never a silent accept): deriving a later
 * epoch's signing keys needs the rotation-walk, which is the post-launch epoch-walk. `presentedGenesis` is
 * intentionally NOT passed — at steady state the pinned genesis is already trusted (its fp == the pin by
 * construction); substitution-reject belongs at bootstrap capture, not here.
 */
export function verifyReleaseEpoch0(
  release: ReleaseObject,
  releasePublisherFp: Uint8Array, // the publisher_fp bound inside the served release's preimage (32B)
  pinned: PinnedLineage,
): RecognizeResult {
  if (release.epoch !== 0) {
    // epoch > 0 is a release for a ROTATED epoch a launch (epoch-0-only) client cannot follow yet — the
    // epoch-walk is a post-launch fast-follow (Apollo's spec). This is OBSOLESCENCE, not tampering: a
    // legitimate future release WILL carry epoch > 0, so it must NOT fire the scary "under attack" WARN
    // (cry-wolf erodes the real warning). It maps to the calm UPDATE-REQUIRED state (this client is too old
    // to follow rotation), same family as a grammar_version ahead. Fail-CLOSED regardless — never a silent
    // accept. (kind flagged for Flint's §3 ceremony co-verify: update-required vs a distinct benign kind is a
    // 1-line ceremony call; the load-bearing property — no adopt, no cry-wolf — holds either way.)
    return {
      accepted: false,
      kind: 'update-required',
      newHwm: pinned.hwm,
      updateRequired: true,
      reason: `epoch ${release.epoch} != 0 — epoch-walk is a post-launch fast-follow`,
    };
  }
  return recognizeRelease({
    release,
    releasePublisherFp,
    pinnedPublisherFp: pinned.publisherFpHex,
    hwm: pinned.hwm,
    // epoch-0: the pinned genesis signing keys ARE this epoch's signing keys.
    epochSigningKeys: { edPub: pinned.genesis.signPub, dsaPub: pinned.genesis.sigPub },
  });
}
