// src/lib/trust/psi-epoch-note.ts
/**
 * The PSI epoch note: how a contact hands a friend the two per-epoch secrets (psi-epoch-element.ts). Library only:
 * nothing calls it, the sealing/deposit path and the receiver's acceptance rule ("MAC verifies AND e strictly greater
 * than the current e for that sender") are NOT here.
 *
 * Plaintext, fixed width, identical in shape for every recipient (real and decoy fields alike):
 *
 *   header(2) || u64be(e) || E_know(32) || E_trust(32) || tag(32)          = 106 bytes
 *
 * There is no layer label, no signature and no key on the wire. A recipient who is not in the sender's trust set (or
 * not in the know set at all) gets a fresh random 32-byte decoy in that field, drawn per recipient, per roll, per
 * field; the recipient cannot tell a decoy from a real field.
 *
 * MAC, not a signature (so the content is not transferable proof):
 *   K_mac = HKDF-SHA256(S_pair, salt = 'svrnty-psi-epoch-auth-v1', info = 'psi-epoch-mac' || LP(fp_sender) || LP(fp_receiver), 32)
 *   tag   = HMAC-SHA256(K_mac, header || fp_sender(32 raw) || fp_receiver(32 raw) || u64be(e)
 *                              || 'know' || E_know || 'trust' || E_trust)
 * Every preimage field is fixed width and the two layer labels are constants at fixed positions, so no two different
 * field splits give the same bytes. The sender comes first in both places: a reflected note, or one replayed in the
 * other direction, fails. LP is the shared lp-tlv.ts framing (uint32 big-endian byte length).
 *
 * S_pair is an INPUT (the caller derives it from the identity keys); it is never stored here. A note from ourselves
 * (fp_sender == fp_receiver) is refused when building and when opening.
 * Known answers: psi-epoch-note.test.ts, from scripts/psi-epoch-note-kat.py (standard library only, no shared code).
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { lpStr, u64be } from '../crypto/lp-tlv';
import { EPOCH_SECRET_LEN } from './psi-epoch-element';

/** Wire type 0x45 ('E') and version 1. The numbering of the type in the sealed-note dispatcher is decided where it is wired. */
export const EPOCH_NOTE_HEADER = Uint8Array.of(0x45, 0x01);
export const EPOCH_NOTE_TAG_LEN = 32;
export const EPOCH_NOTE_LEN = 2 + 8 + EPOCH_SECRET_LEN + EPOCH_SECRET_LEN + EPOCH_NOTE_TAG_LEN; // 106

const MAC_SALT = 'svrnty-psi-epoch-auth-v1';
const MAC_INFO = 'psi-epoch-mac';
const LABEL_KNOW = utf8ToBytes('know');
const LABEL_TRUST = utf8ToBytes('trust');
const CANONICAL_FP = /^[0-9a-f]{64}$/;
const PAIR_SECRET_LEN = 32;

export type EpochNoteErrorCode =
  | 'bad-fingerprint'
  | 'self-note'
  | 'bad-epoch'
  | 'bad-secret'
  | 'bad-pairwise-secret'
  | 'trust-without-know'
  | 'secrets-not-independent';

export class EpochNoteError extends Error {
  constructor(readonly code: EpochNoteErrorCode, detail: string) {
    super(`psi-epoch-note: ${code}: ${detail}`);
    this.name = 'EpochNoteError';
  }
}

export interface EpochNoteContext {
  /** The 32-byte pairwise secret between sender and receiver (the caller derives it; it is not kept here). */
  sPair: Uint8Array;
  /** Canonical lowercase 64-hex fingerprints. */
  fpSender: string;
  fpReceiver: string;
}

function checkContext(ctx: EpochNoteContext): void {
  for (const fp of [ctx.fpSender, ctx.fpReceiver]) {
    if (typeof fp !== 'string' || !CANONICAL_FP.test(fp)) throw new EpochNoteError('bad-fingerprint', 'not canonical (lowercase 64-hex)');
  }
  if (!(ctx.sPair instanceof Uint8Array) || ctx.sPair.length !== PAIR_SECRET_LEN) {
    throw new EpochNoteError('bad-pairwise-secret', `must be exactly ${PAIR_SECRET_LEN} bytes`);
  }
}

function checkEpoch(epoch: number): void {
  if (!Number.isSafeInteger(epoch) || epoch < 0) throw new EpochNoteError('bad-epoch', 'must be a non-negative safe integer');
}

function checkField(f: unknown): Uint8Array {
  if (!(f instanceof Uint8Array) || f.length !== EPOCH_SECRET_LEN) {
    throw new EpochNoteError('bad-secret', `must be exactly ${EPOCH_SECRET_LEN} bytes`);
  }
  return f;
}

/** Constant time over equal-length inputs; a length mismatch is rejected up front (lengths are public). */
function ctEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return ctEqual(a, b);
}

/** K_mac for one direction (sender first). Derived per use; the caller must not keep it. */
export function deriveEpochMacKey(ctx: EpochNoteContext): Uint8Array {
  checkContext(ctx);
  const info = concatBytes(utf8ToBytes(MAC_INFO), lpStr(ctx.fpSender), lpStr(ctx.fpReceiver));
  return hkdf(sha256, ctx.sPair, utf8ToBytes(MAC_SALT), info, 32);
}

function macPreimage(ctx: EpochNoteContext, epoch: number, know: Uint8Array, trust: Uint8Array): Uint8Array {
  return concatBytes(
    EPOCH_NOTE_HEADER,
    hexToBytes(ctx.fpSender),
    hexToBytes(ctx.fpReceiver),
    u64be(epoch),
    LABEL_KNOW,
    know,
    LABEL_TRUST,
    trust,
  );
}

function tagOf(ctx: EpochNoteContext, epoch: number, know: Uint8Array, trust: Uint8Array): Uint8Array {
  return hmac(sha256, deriveEpochMacKey(ctx), macPreimage(ctx, epoch, know, trust));
}

export interface BuildEpochNoteArgs extends EpochNoteContext {
  epoch: number;
  /** The real know-layer secret, or null for a recipient who is not in the sender's know set (a fresh decoy is drawn). */
  know: Uint8Array | null;
  /** The real trust-layer secret, or null for a recipient not in the trust set (a fresh decoy is drawn). */
  trust: Uint8Array | null;
  rand?: (n: number) => Uint8Array;
}

/**
 * The 106-byte plaintext for one recipient. The result carries no marker of which fields are real: a friend in both
 * sets, a know-only friend, and a recipient outside both sets all get the same length and shape.
 */
export function buildEpochNote(args: BuildEpochNoteArgs): Uint8Array {
  checkContext(args);
  if (args.fpSender === args.fpReceiver) throw new EpochNoteError('self-note', 'sender and receiver are the same fingerprint');
  checkEpoch(args.epoch);
  if (args.trust !== null && args.know === null) {
    throw new EpochNoteError('trust-without-know', 'the trust set is a subset of the know set');
  }
  const rand = args.rand ?? randomBytes;
  const know = args.know !== null ? checkField(args.know) : checkField(rand(EPOCH_SECRET_LEN));
  const trust = args.trust !== null ? checkField(args.trust) : checkField(rand(EPOCH_SECRET_LEN));
  if (sameBytes(know, trust)) throw new EpochNoteError('secrets-not-independent', 'the two fields came out identical');
  const tag = tagOf(args, args.epoch, know, trust);
  return concatBytes(EPOCH_NOTE_HEADER, u64be(args.epoch), know, trust, tag);
}

export type EpochNoteRejection = 'malformed' | 'self' | 'epoch-range' | 'bad-mac';

export type OpenedEpochNote =
  | { ok: true; epoch: number; know: Uint8Array; trust: Uint8Array }
  | { ok: false; reason: EpochNoteRejection };

/**
 * Parse and authenticate a received plaintext. Strict: exact length, exact header, nothing extra. The reason is for a
 * local counter only; nothing derived from it may leave the device. Acceptance ("e strictly greater than the current
 * e for this sender") is the caller's, after this returns ok.
 */
export function openEpochNote(wire: Uint8Array, ctx: EpochNoteContext): OpenedEpochNote {
  checkContext(ctx);
  if (!(wire instanceof Uint8Array) || wire.length !== EPOCH_NOTE_LEN) return { ok: false, reason: 'malformed' };
  for (let i = 0; i < EPOCH_NOTE_HEADER.length; i++) if (wire[i] !== EPOCH_NOTE_HEADER[i]) return { ok: false, reason: 'malformed' };
  if (ctx.fpSender === ctx.fpReceiver) return { ok: false, reason: 'self' };
  const epochBig = new DataView(wire.buffer, wire.byteOffset + 2, 8).getBigUint64(0, false);
  if (epochBig > BigInt(Number.MAX_SAFE_INTEGER)) return { ok: false, reason: 'epoch-range' };
  const epoch = Number(epochBig);
  const know = wire.slice(10, 10 + EPOCH_SECRET_LEN);
  const trust = wire.slice(10 + EPOCH_SECRET_LEN, 10 + 2 * EPOCH_SECRET_LEN);
  const got = wire.slice(10 + 2 * EPOCH_SECRET_LEN);
  if (!ctEqual(tagOf(ctx, epoch, know, trust), got)) return { ok: false, reason: 'bad-mac' };
  return { ok: true, epoch, know, trust };
}
