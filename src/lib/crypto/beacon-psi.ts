// src/lib/crypto/beacon-psi.ts
// #588 Mutual-Trust Beacon — DH-PSI bond layer (v2 spec PIN3 SIGNAL-2 = the mutual BOND).
//
// Full spec: /app/shared/outbox/apollo/apollo_588_construction_v2.md
//
// The mutual BOND token  M = a·b·H_G(s‖epoch)  where:
//   s = X25519-DH(A,B) pair-secret (deriveSharedSecret; satellite cannot compute it),
//   a,b = each party's own identity scalar (from their ed25519 secret),
//   H_G = ristretto255 hash-to-point (PRIME-ORDER group — chosen deliberately to avoid the
//         ed25519 cofactor-8 pitfalls that would break a naive DL product).
//
// Properties (proven by beacon-psi.test.ts):
//   • Both parties derive the SAME M iff BOTH contribute their identity-bound share
//     (D_A = a·H, D_B = b·H):  M = b·D_A = a·D_B.  A lone share yields nothing → counterpart-blind bond.
//   • M binds BOTH identity secrets → a party holding only s (or only one secret) CANNOT forge the
//     bond (PO-2 unforgeability). This is why the shared s alone is not enough to fake a mutual.
//   • Fresh H per epoch (s‖epoch) → the bond rotates and is cross-epoch unlinkable (R2).
//
// This is SIGNAL-2 (the bond). SIGNAL-1 (the match-event / probe-resistance) and server-side
// distinctness live in the LRS + oblivious-matcher layers (separate modules).

import { ristretto255, ristretto255_hasher, ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes, bytesToHex } from '@noble/hashes/utils.js';
import { deriveSharedSecret, currentEpochWeek } from './mutual-trust';

type RPoint = ReturnType<typeof ristretto255.Point.BASE.multiply>;

const BOND_DOMAIN = 'svrnty-beacon-bond-v2';

/**
 * H_G for this pair+epoch: a ristretto255 point hashed from (domain ‖ pair-secret ‖ epoch).
 * Both parties derive the SAME H (they share s). Fresh per epoch ⇒ cross-epoch unlinkable.
 */
export function bondBase(sharedSecret: Uint8Array, epochWeek?: number): RPoint {
  const epoch = epochWeek ?? currentEpochWeek();
  const msg = utf8ToBytes(`${BOND_DOMAIN}|${bytesToHex(sharedSecret)}|${epoch}`);
  return ristretto255_hasher.hashToCurve(msg) as unknown as RPoint;
}

/** Extract this identity's ristretto255-compatible scalar (clamped, mod L) from its ed25519 secret key. */
export function identityScalar(ed25519Secret: Uint8Array): bigint {
  return ed25519.utils.getExtendedPublicKey(ed25519Secret).scalar;
}

/** My deposit share D = myScalar·H_G. Deposited at the slot; ALONE it reveals no bond (D ≠ M). */
export function depositShare(H: RPoint, myScalar: bigint): RPoint {
  return H.multiply(myScalar);
}

/**
 * The mutual bond token M = myScalar·peerShare = a·b·H.
 * Computable ONLY with the peer's deposited share (+ my own secret) — never from a lone deposit.
 */
export function bondToken(peerShare: RPoint, myScalar: bigint): RPoint {
  return peerShare.multiply(myScalar);
}

/**
 * The consistent-M bond gate (v2 PIN3): "mutual" lights ONLY when both parties' bond tokens agree.
 * A garbage/probe deposit yields a mismatching M ⇒ NOT mutual (no false bond fabricated).
 */
export function bondsMatch(mine: RPoint, theirs: RPoint): boolean {
  return mine.equals(theirs);
}

/** Serialize a bond token / share for transport or comparison. */
export function pointHex(p: RPoint): string {
  return p.toHex();
}

// --- Mandatory bond-confirmation exchange (Flint hammer FINDING-1) ---
//
// The consistent-M check is NOT safe as "I computed a valid-looking M" — a garbage-probe lets the
// prober compute the REAL M from the counterpart's genuine share and unilaterally "light mutual".
// So the bond is confirmed ONLY via a MANDATORY two-sided exchange: each party publishes a
// commitment H(M) and lights "mutual" iff the PEER's commitment equals H(my M). Genuine ⇒ equal
// (both light); any garbage/mismatched deposit ⇒ unequal ⇒ NEITHER side lights. No party can light
// the bond without the peer's verified agreement.

const CONFIRM_DOMAIN = 'svrnty-beacon-bond-confirm-v2';

/** A party's bond commitment: H(domain ‖ M). Reveals nothing about M; enables only equality-check. */
export function bondConfirm(M: RPoint): string {
  return bytesToHex(sha256(utf8ToBytes(`${CONFIRM_DOMAIN}|${M.toHex()}`)));
}

/**
 * Light "mutual" IFF the peer's confirmation matches MY bond token — i.e. we derived the SAME M.
 * This is the mandatory gate: never light mutual on own-M alone.
 */
export function mutualConfirmed(myM: RPoint, peerConfirm: string): boolean {
  return bondConfirm(myM) === peerConfirm;
}

export { deriveSharedSecret };
