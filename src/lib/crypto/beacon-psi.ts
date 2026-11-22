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

// --- Mandatory bond-confirmation exchange (Flint hammer FINDING-1 + reflection re-verify #174198) ---
//
// The consistent-M check is NOT safe as "I computed a valid-looking M" — a garbage-probe lets the
// prober compute the REAL M from the counterpart's genuine share. So the bond is confirmed ONLY via
// a MANDATORY two-sided exchange of a commitment to M.
//
// ★ The commitment MUST be SENDER-TAG-BOUND: bondConfirm(M, senderTag) = H(domain ‖ M ‖ senderTag).
// A symmetric H(domain‖M) is reflectable — a prober reads the victim's confirm and mirrors it back,
// and the victim's own-M check passes (false bond). Binding the sender's tag defeats reflection: the
// verifier accepts only a confirm bound to the PEER's tag, so a reflected confirm (bound to the
// victim's own tag) fails. Forging a peer-tag-bound confirm needs the peer's M — i.e. the peer's
// secret — which a reflector lacks. Genuine still passes: both derive the same M, and each checks
// the other's confirm against (its own M ‖ the other's tag).

const CONFIRM_DOMAIN = 'svrnty-beacon-bond-confirm-v2';

/** A sender's bond commitment, BOUND to the sender's tag: H(domain ‖ M ‖ senderTag). */
export function bondConfirm(M: RPoint, senderTag: string): string {
  return bytesToHex(sha256(utf8ToBytes(`${CONFIRM_DOMAIN}|${M.toHex()}|${senderTag}`)));
}

/**
 * Light "mutual" IFF the PEER's confirmation equals H(domain ‖ my M ‖ peerTag) — i.e. we derived the
 * same M AND the confirm is bound to the peer's own tag (not reflected from mine). Mandatory gate:
 * never light mutual on own-M alone, and never on a confirm not bound to the peer's tag.
 */
export function mutualConfirmed(myM: RPoint, peerConfirm: string, peerTag: string): boolean {
  return bondConfirm(myM, peerTag) === peerConfirm;
}

export { deriveSharedSecret };
