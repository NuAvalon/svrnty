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
//                                   (seed-derived); on recovery, REVEAL next_owner_key + it self-signs its
//                                   owner-key registration (svrnty-mailbox-ownerkey preimage); the satellite checks H(reveal)==commitment + the
//                                   self-sign. The lost device's key is NOT needed — the pre-commitment IS
//                                   the authorization. ZERO DID reference at the relay → unlinkable. Reuses
//                                   the T1 applyRotation `H(reveal)==commitment` primitive (not net-new).
//   RESOLVED (Flint #151507 / KB#91073): the owner-key install/rotate/recovery uses a DISTINCT preimage
//   `svrnty-mailbox-ownerkey:{mailbox_fp}:{owner_pub_hex}:{epoch}` (NOT the rotate-owner op — dropped). The
//   NEW owner-key SELF-signs its own registration (genesis = TOFU, relay stores durable_id-BLIND on
//   client-auth; rotate/recovery = pre-rotation reveal H(reveal)==stored commitment_n). The owner-key CHAIN
//   is per-mailbox + DID-blind: owner_key_n = HKDF(seed, info=utf8("svrnty-mailbox-ownerkey-chain:v1:{mailbox_fp}:{n}"))
//   (KB#91096 HKDF-encoding nod) — mailbox-scoped so the relay can never link mailbox↔DID (§0). NO
//   current-key-sig and NO DID-authority sig on the rotate/recovery path (survives current-key theft; unlinkable).
//   ⚠ The owner-key-reg `epoch` is the ROTATION INDEX n (0 at genesis, +1 per rotation) — DISTINCT from the
//   routine-op anti-replay epoch above; the satellite stores them separately. Flagged for Flint/Athena at co-verify.

import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';

// ── FLAG-1: op_type is a CLOSED ENUM (never free-form) ─────────────────────────────────────────────────
// `rotate-owner` was REMOVED (Flint #151507 / KB#91073): an owner-KEY install/rotate/recovery changes the
// mailbox ROOT authority — a different security class + verify mechanism than ops-signed-UNDER-that-authority.
// It gets its OWN domain-separated preimage (`svrnty-mailbox-ownerkey:`, below) so a routine-op signature can
// never replay as a key-install (separation law). The routine enum is these four only.
export const OWNER_OP_TYPES = ['allow-add', 'allow-remove', 'revoke-holder', 'register-admission'] as const;
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
 *  On success the caller then verifies the revealed key SELF-SIGNS its owner-key registration (via
 *  signOwnerKeyReg / verifyOwnerKeyReg over ownerKeyRegScope — NOT a routine owner-op; `rotate-owner` was
 *  dropped from OWNER_OP_TYPES, #151507) — the pre-commitment IS the authority,
 *  so the lost device's key is never needed. Fail-closed on any length/hash mismatch. */
export function verifyRecoveryReveal(revealedNextOwnerPub: Uint8Array, storedCommitmentHex: string): boolean {
  try {
    if (revealedNextOwnerPub.length !== 32) return false;
    return commitNextOwnerKey(revealedNextOwnerPub) === storedCommitmentHex.toLowerCase();
  } catch {
    return false;
  }
}

// ══ OWNER-KEY LIFECYCLE (install / rotate / recovery) — Flint #151507 / KB#91073+91096 ═══════════════════
// The owner-KEY registration is DISTINCT from a routine owner-op (separation law): different domain preimage,
// self-signed by the NEW owner key. Genesis = TOFU (relay durable_id-blind); rotate/recovery = pre-rotation
// reveal (H(reveal)==stored commitment_n). The owner-key chain is seed-derived, per-mailbox, and DID-BLIND.

const HEX64_RE = /^[0-9a-f]{64}$/; // SHA-256 commitment / 32B pubkey as lowercase hex

/**
 * The owner-KEY registration preimage, byte-exact and domain-separated from `svrnty-mailbox-op:`:
 *   `svrnty-mailbox-ownerkey:{mailbox_fp}:{owner_pub_hex}:{epoch}`
 * Flat delimited, signed DIRECTLY as UTF-8 with Ed25519 (no envelope). The owner_pub is BOUND into the
 * preimage (it self-signs) so a relay can't swap the registered key. `epoch` here is the owner-key ROTATION
 * INDEX n (0 = genesis), monotonic — DISTINCT from the routine-op anti-replay epoch.
 */
export function ownerKeyRegScope(mailboxFp: string, ownerPubHex: string, epoch: number): string {
  if (!HEX_RE.test(mailboxFp)) throw new Error(`ownerKeyRegScope: mailbox_fp must be canonical lowercase-hex, got ${JSON.stringify(mailboxFp)}`);
  if (!HEX_RE.test(ownerPubHex) || ownerPubHex.length !== PUBKEY_HEX_LEN)
    throw new Error(`ownerKeyRegScope: owner_pub must be ${PUBKEY_HEX_LEN}-char lowercase-hex, got ${JSON.stringify(ownerPubHex)}`);
  if (!Number.isInteger(epoch) || epoch < 0) throw new Error(`ownerKeyRegScope: epoch must be a non-negative integer, got ${epoch}`);
  return `svrnty-mailbox-ownerkey:${mailboxFp}:${ownerPubHex}:${epoch}`;
}

/**
 * Derive the owner key at rotation index `n` from the owner's cold seed — per-mailbox + DID-blind (KB#91096):
 *   owner_key_n = HKDF-SHA256(seed, info=utf8("svrnty-mailbox-ownerkey-chain:v1:{mailbox_fp}:{n}"), 32B)
 * mailbox_fp is in the info (mailbox-scoped) but the DID is NOT → the relay can never link mailbox↔DID (§0).
 * Returns the 32B ed25519 seed + its pubkey. The seed survives device loss (re-derivable from the cold seed),
 * so recovery reveals the pre-committed next key without ever needing the lost device.
 */
export function deriveOwnerKey(seed: Uint8Array, mailboxFp: string, n: number): { seed: Uint8Array; pub: Uint8Array } {
  if (!HEX_RE.test(mailboxFp)) throw new Error(`deriveOwnerKey: mailbox_fp must be canonical lowercase-hex`);
  if (!Number.isInteger(n) || n < 0) throw new Error(`deriveOwnerKey: n must be a non-negative integer, got ${n}`);
  const info = utf8ToBytes(`svrnty-mailbox-ownerkey-chain:v1:${mailboxFp}:${n}`);
  const keySeed = hkdf(sha256, seed, undefined, info, 32);
  return { seed: keySeed, pub: ed25519.getPublicKey(keySeed) };
}

/**
 * SELF-sign an owner-key registration: the owner key signs the preimage that names its OWN pubkey. Derives
 * the pubkey from the seed (fail-closed self-consistency — you cannot register a key you do not hold).
 */
export function signOwnerKeyReg(ownerKeySeed: Uint8Array, mailboxFp: string, epoch: number): { ownerPubHex: string; sig: Uint8Array } {
  const ownerPubHex = bytesToHex(ed25519.getPublicKey(ownerKeySeed));
  const sig = ed25519.sign(utf8ToBytes(ownerKeyRegScope(mailboxFp, ownerPubHex, epoch)), ownerKeySeed);
  return { ownerPubHex, sig };
}

/** A completed owner-key registration record — what the client hands the relay (genesis or rotate/recovery). */
export interface OwnerKeyRegistration {
  mailboxFp: string;
  epoch: number; // rotation index n (0 = genesis)
  ownerPubHex: string; // the owner key being registered (self-signs)
  sig: Uint8Array; // self-sign over ownerKeyRegScope
  nextCommitmentHex: string; // H(owner_key_{n+1}) — the pre-rotation commitment this reg SETS for the next rotation
}

/** Build the GENESIS owner-key registration (epoch 0): owner_key_0 self-signs, commits H(owner_key_1). */
export function buildOwnerKeyGenesis(seed: Uint8Array, mailboxFp: string): OwnerKeyRegistration {
  const k0 = deriveOwnerKey(seed, mailboxFp, 0);
  const k1 = deriveOwnerKey(seed, mailboxFp, 1);
  const { ownerPubHex, sig } = signOwnerKeyReg(k0.seed, mailboxFp, 0);
  return { mailboxFp, epoch: 0, ownerPubHex, sig, nextCommitmentHex: commitNextOwnerKey(k1.pub) };
}

/**
 * Build a ROTATION/RECOVERY owner-key registration INTO rotation index `epoch` (≥ 1): reveal owner_key_epoch
 * (which the relay checks hashes to the stored commitment_{epoch-1}), self-sign, and commit H(owner_key_{epoch+1}).
 * Rotate and recovery are the SAME path — recovery just re-derives the chain from the cold seed after device loss.
 */
export function buildOwnerKeyRotation(seed: Uint8Array, mailboxFp: string, epoch: number): OwnerKeyRegistration {
  if (!Number.isInteger(epoch) || epoch < 1) throw new Error('buildOwnerKeyRotation: epoch must be ≥ 1 (genesis is epoch 0)');
  const kn = deriveOwnerKey(seed, mailboxFp, epoch);
  const kNext = deriveOwnerKey(seed, mailboxFp, epoch + 1);
  const { ownerPubHex, sig } = signOwnerKeyReg(kn.seed, mailboxFp, epoch);
  return { mailboxFp, epoch, ownerPubHex, sig, nextCommitmentHex: commitNextOwnerKey(kNext.pub) };
}

export interface OwnerKeyRegVerifyInput {
  ownerPub: Uint8Array; // the owner key being registered (verifies its own self-sign)
  sig: Uint8Array;
  mailboxFp: string;
  epoch: number; // rotation index n
  nextCommitmentHex: string; // the commitment this reg sets (stored on accept) — format-checked here
  priorCommitmentHex?: string; // PRESENT ⇒ rotate/recovery (reveal must hash to it); ABSENT ⇒ genesis (TOFU)
  lastEpoch?: number; // satellite's stored rotation index — reject epoch ≤ lastEpoch (rotate/recovery only)
}

/**
 * Mirror of the satellite's owner-key registration verify (satellite is authoritative — it owns the
 * (mailbox)→{owner_pub, rotation-index, commitment} store). Two modes:
 *   • genesis (priorCommitmentHex absent): TOFU — epoch must be 0, the owner key self-signs. Relay stores
 *     the record on client-auth WITHOUT any durable_id lookup (§0 unlinkable).
 *   • rotate/recovery (priorCommitmentHex present): the revealed owner key must hash to the stored
 *     commitment_{n-1} (pre-rotation), self-sign valid, and the rotation index strictly advances.
 * NO current-key signature and NO DID-authority is ever required — the pre-commitment IS the authorization.
 */
export function verifyOwnerKeyReg(inp: OwnerKeyRegVerifyInput): OwnerOpVerifyResult {
  if (inp.ownerPub.length !== 32) return { ok: false, reason: 'bad-owner-pub-length' };
  if (!HEX64_RE.test((inp.nextCommitmentHex || '').toLowerCase())) return { ok: false, reason: 'bad-next-commitment' };
  let scope: string;
  try {
    scope = ownerKeyRegScope(inp.mailboxFp, bytesToHex(inp.ownerPub), inp.epoch);
  } catch (e) {
    return { ok: false, reason: e instanceof Error ? e.message : 'bad-ownerkey-scope-fields' };
  }
  if (!ed25519.verify(inp.sig, utf8ToBytes(scope), inp.ownerPub)) return { ok: false, reason: 'ownerkey-self-sign-invalid' };
  if (inp.priorCommitmentHex === undefined) {
    // genesis (TOFU) — no prior commitment to check; the relay is trusting-on-first-use.
    if (inp.epoch !== 0) return { ok: false, reason: 'genesis-must-be-epoch-0' };
    return { ok: true };
  }
  // rotate / recovery
  if (inp.epoch < 1) return { ok: false, reason: 'rotation-must-advance-epoch' };
  if (inp.lastEpoch !== undefined && !(inp.epoch > inp.lastEpoch)) return { ok: false, reason: 'epoch-not-monotonic' };
  if (!verifyRecoveryReveal(inp.ownerPub, inp.priorCommitmentHex)) return { ok: false, reason: 'reveal-does-not-match-commitment' };
  return { ok: true };
}
