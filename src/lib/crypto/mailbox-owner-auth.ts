// src/lib/crypto/mailbox-owner-auth.ts
//
// S1 — mailbox OWNER-AUTH (svrnty C-build, Lane C / Apollo). Client half of the blind-router owner-op
// authorization (Flint's definitive call #151432, KB#91061 lineage).
//
// WHY. The blind router removes the central `identities` directory, so the 34 satellite owner-op sites
// (allow-add/remove, revoke-holder, register-admission, rotate-owner) can no longer verify against an
// identity key looked up in a directory. Instead each mailbox registers a per-(mailbox,epoch) OWNER
// signing pubkey; every owner-op is signed with it and the satellite verifies via ONE chokepoint
// (`verify_mailbox_owner`) holding only the pubkey → verify-not-mint, no identity lookup, no mailbox↔DID
// linkage (sovereignty: the relay never learns which DID controls a mailbox).
//
// ── BYTE-EXACT SPEC (Flint #151432) ───────────────────────────────────────────────────────────────────
//   owner-op preimage  = `svrnty-mailbox-op:{mailbox_fp}:{op}:{epoch}:{target_hex}`   (flat delimited string,
//     signed DIRECTLY as UTF-8 with Ed25519 — NO JSON/canonicalize envelope). Domain-separated from
//     `svrnty-cap:` (S2) and `svrnty:did-doc:v1` (T1) by the leading tag.
//     FLAG-1: op ∈ CLOSED ENUM, mailbox_fp = canonical lowercase-hex, epoch = non-negative int,
//     target_hex = canonical lowercase-hex → every field delimiter-free ⇒ the `:`-split is injective.
//   ★ TARGET-BINDING (the catch Flint confirmed REQUIRED): the op's target (the holder_pub being
//     added/removed/revoked, the admit_pubkey being registered, or the new owner_pubkey being rotated-in)
//     is BOUND into the signed preimage. Without it, verify-not-mint holds but op-INTEGRITY does not — a
//     compelled/hostile blind relay could redirect the owner's authorization to an unauthorized target.
//     This is the S1 analog of the capability-token issuer_cert binding holder_pub.
//   anti-replay = per-OP MONOTONIC epoch (satellite rejects epoch ≤ stored; reuses `mailboxes.epoch`,
//     matches the T1 DID-Doc seq guard). Multi-device owners coordinate the epoch via the synced book
//     (CRDT last-writer-wins-by-epoch; a lost op re-signs at the new epoch).
//
// ── OWNER-KEY LIFECYCLE (three signer paths — Flint #151432) ───────────────────────────────────────────
//   The signing PRIMITIVE below (signOwnerOp) is uniform; the three paths differ only by WHICH key signs
//   and (for recovery) an added pre-rotation reveal:
//     1. routine owner-op        → signed by the mailbox OWNER Ed25519 key (verify vs registered owner pub).
//     2. genesis owner-key boot  → the initial owner-key install, self-asserted by the OPERATIONAL Ed25519
//                                   key (one-time, like the genesis DID-Doc self-sign; a contact already
//                                   trusts it via card-exchange).
//     3. recovery owner-key re-reg → per-mailbox owner-key PRE-ROTATION: at reg, commit H(next_owner_key)
//                                   (seed-derived); on recovery, REVEAL next_owner_key + it self-signs the
//                                   rotate-owner op; the satellite checks H(reveal)==commitment + the
//                                   self-sign. The lost device's key is NOT needed — the pre-commitment IS
//                                   the authorization. ZERO DID reference at the relay → unlinkable. Reuses
//                                   the T1 applyRotation `H(reveal)==commitment` primitive (not net-new).
//   NB (pending Flint co-verify): whether the owner-key install/rotate uses THIS owner-op preimage with
//   op=`rotate-owner` (target=new_owner_pubkey) or a distinct `svrnty-mailbox-ownerkey:` preimage
//   (Athena #151353) is the one detail in the truncated tail of #151432 — the primitives here support
//   either; the exact composition is pinned at co-verify.

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

// ── FLAG-1: op_type is a CLOSED ENUM (never free-form) ─────────────────────────────────────────────────
export const OWNER_OP_TYPES = ['allow-add', 'allow-remove', 'revoke-holder', 'register-admission', 'rotate-owner'] as const;
export type OwnerOpType = (typeof OWNER_OP_TYPES)[number];

const HEX_RE = /^[0-9a-f]+$/; // canonical lowercase-hex
const PUBKEY_HEX_LEN = 64; // 32-byte Ed25519 pubkey → 64 hex chars (holder_pub / admit_pubkey / new_owner_pubkey)

/**
 * The owner-op preimage, byte-exact. Fail-closed on any FLAG-1 violation — a field that could contain ':'
 * or a non-enum op would break the injectivity the satellite relies on when it re-derives + cross-checks.
 * `targetHex` is the op's bound target (holder_pub / admit_pubkey / new_owner_pubkey), all 64-hex Ed25519 pubs.
 */
export function ownerOpScope(mailboxFp: string, op: OwnerOpType, epoch: number, targetHex: string): string {
  if (!HEX_RE.test(mailboxFp)) throw new Error(`ownerOpScope: mailbox_fp must be canonical lowercase-hex, got ${JSON.stringify(mailboxFp)}`);
  if (!OWNER_OP_TYPES.includes(op)) throw new Error(`ownerOpScope: op not in enum {${OWNER_OP_TYPES.join(', ')}}, got ${JSON.stringify(op)}`);
  if (!Number.isInteger(epoch) || epoch < 0) throw new Error(`ownerOpScope: epoch must be a non-negative integer, got ${epoch}`);
  if (!HEX_RE.test(targetHex) || targetHex.length !== PUBKEY_HEX_LEN)
    throw new Error(`ownerOpScope: target must be ${PUBKEY_HEX_LEN}-char lowercase-hex, got ${JSON.stringify(targetHex)}`);
  return `svrnty-mailbox-op:${mailboxFp}:${op}:${epoch}:${targetHex}`;
}

/** Sign an owner-op. `signerSk` = the mailbox owner key (routine), the operational key (genesis boot), or the
 *  revealed next owner-key (recovery self-sign). The signing primitive is identical across the three paths. */
export function signOwnerOp(
  signerSk: Uint8Array,
  mailboxFp: string,
  op: OwnerOpType,
  epoch: number,
  targetHex: string,
): Uint8Array {
  return ed25519.sign(utf8ToBytes(ownerOpScope(mailboxFp, op, epoch, targetHex)), signerSk);
}

export interface OwnerOpVerifyInput {
  ownerPub: Uint8Array; // the mailbox's registered per-(mailbox,epoch) owner pubkey (satellite holds pubkey only)
  sig: Uint8Array;
  mailboxFp: string;
  op: OwnerOpType;
  epoch: number;
  targetHex: string;
  lastEpoch?: number; // the satellite's stored monotonic epoch — reject epoch ≤ lastEpoch (per-op replay guard)
}
export interface OwnerOpVerifyResult {
  ok: boolean;
  reason?: string;
}

/** Mirror of the satellite's authoritative verify_mailbox_owner — for self-test + the co-verify vector.
 *  The satellite is authoritative (it owns the (mailbox,epoch)→owner-pubkey store + the monotonic clock). */
export function verifyOwnerOp(inp: OwnerOpVerifyInput): OwnerOpVerifyResult {
  if (inp.lastEpoch !== undefined && !(inp.epoch > inp.lastEpoch)) return { ok: false, reason: 'epoch-not-monotonic' };
  let scope: string;
  try {
    scope = ownerOpScope(inp.mailboxFp, inp.op, inp.epoch, inp.targetHex);
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : 'bad-scope-fields' };
  }
  if (inp.ownerPub.length !== 32) return { ok: false, reason: 'bad-owner-pub-length' };
  if (!ed25519.verify(inp.sig, utf8ToBytes(scope), inp.ownerPub)) return { ok: false, reason: 'owner-sig-invalid' };
  return { ok: true };
}

// ── owner-key PRE-ROTATION primitive (recovery path 3; reuses the T1 H(reveal)==commitment pattern) ─────
/** The pre-commitment stored at owner-key registration: SHA256(next_owner_pubkey) as lowercase hex.
 *  next_owner_key is seed-derived so it survives device loss; only its HASH is registered (nothing to steal). */
export function commitNextOwnerKey(nextOwnerPub: Uint8Array): string {
  if (nextOwnerPub.length !== 32) throw new Error(`commitNextOwnerKey: owner pubkey must be 32 bytes`);
  return bytesToHex(sha256(nextOwnerPub));
}

/** Recovery check (satellite mirror): the revealed next owner-key must hash to the pre-committed value.
 *  On success the caller then verifies the revealed key SELF-SIGNS the rotate-owner op (via verifyOwnerOp
 *  with op='rotate-owner', target=hex(revealed), ownerPub=revealed) — the pre-commitment IS the authority,
 *  so the lost device's key is never needed. Fail-closed on any length/hash mismatch. */
export function verifyRecoveryReveal(revealedNextOwnerPub: Uint8Array, storedCommitmentHex: string): boolean {
  try {
    if (revealedNextOwnerPub.length !== 32) return false;
    return commitNextOwnerKey(revealedNextOwnerPub) === storedCommitmentHex.toLowerCase();
  } catch {
    return false;
  }
}
