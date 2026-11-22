// src/lib/crypto/beacon-lrs.ts
// #588 Mutual-Trust Beacon — Linkable Ring Signature layer (v2 spec PIN4 / SIGNAL-1).
//
// Full spec: /app/shared/outbox/apollo/apollo_588_construction_v2.md
//
// A Liu–Wei–Wong (LSAG, ACISP'04, eprint 2004/027) linkable ring signature over the ENROLLED
// DIRECTORY, slot-domain-separated. On ristretto255 (prime-order, no cofactor):
//   • ring  = {P_i = x_i·G}  (every enrolled member's beacon pubkey; G = ristretto255 BASE)
//   • signer π proves knowledge of some x_i WITHOUT revealing which  → anonymity within the directory.
//     This is what KILLS OP-5: the anonymity set is the whole directory, not the 2-member pair, so a
//     counterpart B cannot de-anonymize A's deposit by elimination.
//   • slot tag  T = x_π·H_p(slot)   (slot = the beacon slot H_e). SAME signer + SAME slot ⇒ SAME T
//     (server catches a double-deposit / enforces "two DISTINCT members"); DIFFERENT slot ⇒ different
//     H_p(slot) ⇒ different T ⇒ cross-epoch UNLINKABLE (R2).
//   • x_π = the identity scalar (same scalar as beacon-psi) ⇒ a deposit = LRS(this slot) + DH-PSI share,
//     both bound to the one identity secret.
//
// The satellite verifies ring-membership + tag-distinctness WITHOUT learning any identity (PO-1/R1).
// Tested by beacon-lrs.test.ts: completeness, tamper-rejection, non-member soundness, linkability
// (same signer+slot → same T), cross-slot unlinkability, anonymity (sig independent of signer index).

import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToNumberLE, concatBytes, randomBytes } from '@noble/curves/utils.js';

const P = ristretto255.Point;
const Fn = P.Fn;
const G = P.BASE;
const L = Fn.ORDER;

type RPoint = ReturnType<typeof P.BASE.multiply>;

export interface RingSignature {
  /** The seed challenge c_0 that the verifier re-derives the ring from. */
  c0: bigint;
  /** One response scalar per ring member. */
  s: bigint[];
  /** Linkable tag T = x_π·H_p(slot) — hex. Same signer+slot ⇒ equal; distinct members ⇒ distinct. */
  tag: string;
}

// --- helpers ---

/** Uniform scalar mod L from 64 random bytes. */
function randScalar(): bigint {
  return Fn.create(bytesToNumberLE(randomBytes(64)));
}

function ptBytes(p: RPoint): Uint8Array {
  return p.toBytes();
}

/** Fiat–Shamir challenge: H(ring ‖ slot ‖ msg ‖ T ‖ L_i ‖ R_i) → scalar mod L. */
function hChallenge(
  ringBytes: Uint8Array,
  slot: Uint8Array,
  msg: Uint8Array,
  T: RPoint,
  Li: RPoint,
  Ri: RPoint,
): bigint {
  const digest = sha512(concatBytes(ringBytes, slot, msg, ptBytes(T), ptBytes(Li), ptBytes(Ri)));
  return Fn.create(bytesToNumberLE(digest));
}

/** The slot's tag base H_p(slot) — a ristretto255 point. */
export function slotBase(slot: Uint8Array): RPoint {
  return ristretto255_hasher.hashToCurve(slot) as unknown as RPoint;
}

/** This identity's beacon pubkey P = x·G for the directory ring. */
export function beaconPubkey(x: bigint): RPoint {
  return G.multiply(x);
}

function ringEncoding(ring: RPoint[]): Uint8Array {
  return concatBytes(...ring.map(ptBytes));
}

// --- sign / verify / link ---

/**
 * LSAG sign: prove knowledge of x = secretScalar at ring[secretIndex] (P = x·G), over (slot, msg).
 * Produces a linkable tag T = x·H_p(slot).
 */
export function ringSign(
  ring: RPoint[],
  secretIndex: number,
  secretScalar: bigint,
  slot: Uint8Array,
  msg: Uint8Array,
): RingSignature {
  const n = ring.length;
  const Hs = slotBase(slot);
  const T = Hs.multiply(secretScalar); // linkable tag
  const ringBytes = ringEncoding(ring);

  const c = new Array<bigint>(n);
  const s = new Array<bigint>(n);

  // Start the ring just after the signer: c_{π+1} = H(..., u·G, u·Hs)
  const u = randScalar();
  let i = (secretIndex + 1) % n;
  c[i] = hChallenge(ringBytes, slot, msg, T, G.multiply(u), Hs.multiply(u));

  // Walk π+1 → … → π, forging each non-signer link with a random s_i.
  while (i !== secretIndex) {
    s[i] = randScalar();
    const Li = G.multiply(s[i]).add(ring[i].multiply(c[i]));
    const Ri = Hs.multiply(s[i]).add(T.multiply(c[i]));
    const next = (i + 1) % n;
    c[next] = hChallenge(ringBytes, slot, msg, T, Li, Ri);
    i = next;
  }

  // Close the ring at the signer: s_π = u − c_π·x  (mod L).
  s[secretIndex] = Fn.sub(u, Fn.mul(c[secretIndex], secretScalar));

  return { c0: c[0], s, tag: T.toHex() };
}

/** LSAG verify: recompute the challenge chain from c_0 and check it closes. */
export function ringVerify(
  ring: RPoint[],
  slot: Uint8Array,
  msg: Uint8Array,
  sig: RingSignature,
): boolean {
  const n = ring.length;
  if (sig.s.length !== n) return false;
  let T: RPoint;
  try {
    T = P.fromHex(sig.tag);
  } catch {
    return false;
  }
  const Hs = slotBase(slot);
  const ringBytes = ringEncoding(ring);

  let c = sig.c0;
  for (let i = 0; i < n; i++) {
    const Li = G.multiply(sig.s[i]).add(ring[i].multiply(c));
    const Ri = Hs.multiply(sig.s[i]).add(T.multiply(c));
    c = hChallenge(ringBytes, slot, msg, T, Li, Ri);
  }
  return c === sig.c0;
}

/** Linkability: two signatures link iff they share a tag (same signer, same slot). */
export function tagsLink(a: RingSignature, b: RingSignature): boolean {
  return a.tag === b.tag;
}
