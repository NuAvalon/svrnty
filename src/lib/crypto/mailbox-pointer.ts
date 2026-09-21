// src/lib/crypto/mailbox-pointer.ts
/**
 * Mailbox pointer — the sovereign "here is my mailbox" capsule (KB#90104 item 4, Flint grammar-pin).
 *
 * A pointer conveys a publisher's CURRENT mailbox (its public keys + epoch) to a specific peer, sealed
 * and deposited at the pair's blind rendezvous R_e (trust-rendezvous.ts). It is the ONE genuinely-new
 * byte-grammar in the mailbox lifecycle — everything else reuses pinned primitives. This module defines
 * ONLY what goes INSIDE the sealed beacon blob; the seal/deposit transport is trust-rendezvous.ts.
 *
 * ptr_plaintext =
 *     LP("svrnty:mailbox-ptr:v1")     // domain tag (C1: distinct from trust-beacon / mailbox-env / reg)
 *   ‖ LP(mailbox_fp_raw[32])          // 32 RAW bytes (NOT hex) — SHA256(x25519_pub ‖ mlkem1024_ek)
 *   ‖ u64be(epoch)
 *   ‖ LP(x25519_pub[32])
 *   ‖ LP(mlkem1024_ek[1568])
 *
 * signed_pointer = ptr_plaintext ‖ sig[64]     // Ed25519(publisher_identity_seed, ptr_plaintext)
 *   The signature is INSIDE the seal (relay-blind): presence at R_e proves nothing (both peers can
 *   deposit there), only the publisher's identity signature proves WHO published this mailbox.
 *
 * ANTI-SUBSTITUTION (Flint MUST, hard reject not comment): a resolver recomputes
 * SHA256(x25519_pub ‖ mlkem1024_ek) == mailbox_fp_raw and REJECTS on mismatch BEFORE using the keys.
 * Because the pubkeys are inline, a peer seals with ZERO GET round-trip and self-verifies locally — a
 * lying relay cannot substitute attacker pubkeys. verifyMailboxPointer enforces this + the identity sig.
 *
 * SWAP/rotation (S1/S2): a new random keypair → new fp → re-publish a pointer at the CURRENT R_e with a
 * HIGHER epoch (multiple blobs may collide at one R_e). A resolver takes the highest-epoch valid-sig
 * pointer — see selectLatestValidPointer. Monotonic, no relay-visible migration record.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { sha256 as sha256hash } from '@noble/hashes/sha2.js';
import { lpBin, lpStr, u64be } from './lp-tlv.js';

export const MAILBOX_PTR_DOMAIN = 'svrnty:mailbox-ptr:v1';
const X25519_LEN = 32;
const KEM_PUB_LEN = 1568; // ML-KEM-1024 encapsulation key
const FP_RAW_LEN = 32; // SHA256 output
const SIG_LEN = 64; // Ed25519

/** The verified contents of a mailbox pointer. */
export interface MailboxPointer {
  /** mailbox_fp as 64 lowercase hex — VERIFIED == SHA256(x25519Pub ‖ mlkem1024Ek). */
  mailboxFp: string;
  epoch: number;
  x25519Pub: Uint8Array; // 32
  mlkem1024Ek: Uint8Array; // 1568
}

/**
 * Encode ptr_plaintext for the given mailbox keys + epoch. mailbox_fp_raw is derived from the pubkeys
 * (never accepted as an independent parameter) so fp == SHA256(pubkeys) holds BY CONSTRUCTION.
 * Throws on malformed input (this is OUR encoder over our own keys — not an attacker-input surface).
 */
export function encodeMailboxPointerPlaintext(epoch: number, x25519Pub: Uint8Array, mlkem1024Ek: Uint8Array): Uint8Array {
  if (x25519Pub.length !== X25519_LEN) throw new Error(`x25519 pub must be ${X25519_LEN}B, got ${x25519Pub.length}`);
  if (mlkem1024Ek.length !== KEM_PUB_LEN) throw new Error(`ml-kem ek must be ${KEM_PUB_LEN}B, got ${mlkem1024Ek.length}`);
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new Error(`epoch must be a non-negative safe integer, got ${epoch}`);
  const fpRaw = sha256hash(concatBytes(x25519Pub, mlkem1024Ek)); // 32B, matches deriveMailboxFp preimage
  return concatBytes(
    lpStr(MAILBOX_PTR_DOMAIN),
    lpBin(fpRaw),
    u64be(epoch),
    lpBin(x25519Pub),
    lpBin(mlkem1024Ek),
  );
}

/**
 * Build a SIGNED mailbox pointer (ptr_plaintext ‖ sig). `identitySeed` is the publisher's raw 32B Ed25519
 * identity seed (from extractRawSign — in-memory only). The returned blob is what gets beacon-sealed.
 */
export function buildSignedMailboxPointer(
  epoch: number,
  x25519Pub: Uint8Array,
  mlkem1024Ek: Uint8Array,
  identitySeed: Uint8Array,
): Uint8Array {
  const plaintext = encodeMailboxPointerPlaintext(epoch, x25519Pub, mlkem1024Ek);
  const sig = ed25519.sign(plaintext, identitySeed); // 64B
  return concatBytes(plaintext, sig);
}

// ── Bounds-checked reader (never throws on attacker input; returns null on any malformation) ──

function u32beAt(buf: Uint8Array, off: number): number {
  // high byte via multiply (not <<24) to avoid the sign bit
  return buf[off] * 0x1000000 + (buf[off + 1] << 16) + (buf[off + 2] << 8) + buf[off + 3];
}

function u64beAt(buf: Uint8Array, off: number): number {
  let v = 0;
  for (let i = 0; i < 8; i++) v = v * 256 + buf[off + i]; // exact for epochs (< 2^53)
  return v;
}

interface RawPointer {
  plaintext: Uint8Array; // the exact bytes the signature covers
  fpRaw: Uint8Array; // 32
  epoch: number;
  x25519Pub: Uint8Array; // 32
  mlkem1024Ek: Uint8Array; // 1568
  sig: Uint8Array; // 64
}

/**
 * Parse a signed pointer blob into its fields WITHOUT verifying the sig or the fp binding. Returns null
 * on ANY structural malformation (short buffer, wrong domain, wrong field length, trailing bytes). Never
 * throws. Verification (sig + anti-substitution) is verifyMailboxPointer.
 */
export function parseSignedMailboxPointer(blob: Uint8Array): RawPointer | null {
  let off = 0;
  const readLP = (): Uint8Array | null => {
    if (off + 4 > blob.length) return null;
    const len = u32beAt(blob, off);
    const start = off + 4;
    const end = start + len;
    if (len < 0 || end > blob.length) return null;
    off = end;
    return blob.slice(start, end);
  };

  const domain = readLP();
  if (!domain || bytesToHex(domain) !== bytesToHex(utf8ToBytes(MAILBOX_PTR_DOMAIN))) return null;

  const fpRaw = readLP();
  if (!fpRaw || fpRaw.length !== FP_RAW_LEN) return null;

  if (off + 8 > blob.length) return null;
  const epoch = u64beAt(blob, off);
  off += 8;

  const x25519Pub = readLP();
  if (!x25519Pub || x25519Pub.length !== X25519_LEN) return null;

  const mlkem1024Ek = readLP();
  if (!mlkem1024Ek || mlkem1024Ek.length !== KEM_PUB_LEN) return null;

  const plaintext = blob.slice(0, off); // everything read so far == ptr_plaintext
  if (off + SIG_LEN !== blob.length) return null; // exactly one 64B sig, no trailing bytes
  const sig = blob.slice(off, off + SIG_LEN);

  return { plaintext, fpRaw, epoch, x25519Pub, mlkem1024Ek, sig };
}

/**
 * Verify a signed pointer against the expected publisher's Ed25519 identity pubkey. Returns the VERIFIED
 * MailboxPointer, or null on any rejection (malformed, bad signature, or fp != SHA256(pubkeys)). Never
 * throws on attacker-controlled input. This is the one gate every pointer consumer MUST pass through.
 */
export function verifyMailboxPointer(blob: Uint8Array, publisherEdPub: Uint8Array): MailboxPointer | null {
  const p = parseSignedMailboxPointer(blob);
  if (!p) return null;

  // 1. identity signature over the exact plaintext (authenticates WHO published)
  let sigOk: boolean;
  try {
    sigOk = ed25519.verify(p.sig, p.plaintext, publisherEdPub);
  } catch {
    return null;
  }
  if (!sigOk) return null;

  // 2. ANTI-SUBSTITUTION MUST (Flint): fp_raw == SHA256(x25519_pub ‖ mlkem1024_ek) — hard reject
  const recomputed = sha256hash(concatBytes(p.x25519Pub, p.mlkem1024Ek));
  if (bytesToHex(recomputed) !== bytesToHex(p.fpRaw)) return null;

  return {
    mailboxFp: bytesToHex(p.fpRaw),
    epoch: p.epoch,
    x25519Pub: p.x25519Pub,
    mlkem1024Ek: p.mlkem1024Ek,
  };
}

/**
 * From a set of candidate pointer blobs all claiming to be from `publisherEdPub` (e.g. multiple blobs
 * colliding at one R_e after a rotation), return the VERIFIED pointer with the HIGHEST epoch, or null if
 * none verify. Monotonic rotation selection (KB#90104 item 4 SWAP): a stale/forged lower-epoch pointer
 * can never override a higher-epoch valid one, and an unsigned/tampered blob is dropped.
 */
export function selectLatestValidPointer(blobs: Uint8Array[], publisherEdPub: Uint8Array): MailboxPointer | null {
  let best: MailboxPointer | null = null;
  for (const blob of blobs) {
    const p = verifyMailboxPointer(blob, publisherEdPub);
    if (p && (!best || p.epoch > best.epoch)) best = p;
  }
  return best;
}
