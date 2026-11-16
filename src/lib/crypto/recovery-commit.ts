// src/lib/crypto/recovery-commit.ts
// A commitment to each recovery piece: c_i = sha256(COMMIT_DOMAIN || set_id(32 bytes) || index(1 byte) || piece bytes).
// Shamir gives no integrity: a bad, short or foreign piece recombines to wrong bytes with no error, and a piece's index/threshold/identity labels are never read
// (recovery-shards.test.ts). The commitment binds the LABEL to the PIECE under one set id, so the owner can say which of the pieces it was handed to trust, and
// a holder can check the one piece it received. The owner keeps the list; each holder keeps only its own c_i.
// A leaf on purpose: it sees pieces, never the secret, and imports no store, network, Shamir or vault code.
// Fixed-width fields (32 + 1 bytes before the piece) mean no two different inputs share an encoding. The domain tag keeps this hash from being valid as anything else.
// Run: npx tsx --test src/lib/crypto/recovery-commit.test.ts
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { ctEqual } from './ct-equal';

export const COMMIT_DOMAIN = 'svrnty/recovery-piece/commit/v1\0';
export const SET_ID_BYTES = 32;
export const SET_ID_HEX_LENGTH = SET_ID_BYTES * 2;
const HEX64 = /^[0-9a-f]{64}$/;

/** A piece as it travels: its label and its base64 data (the shape of recovery.ts Shard, narrowed to what is committed). */
export interface CommittablePiece { index: number; data: string }

/** What the owner stores: a version, the set id, and one commitment per index (the index is the decimal string "1".."255"). */
export interface PieceCommitments { v: 1; set_id: string; commitments: Record<string, string> }

export type BadPieceReason = 'mismatch' | 'unknown-index' | 'duplicate' | 'malformed';
export interface BadPiece { at: number; index: unknown; reason: BadPieceReason }

function fromB64(s: unknown): Uint8Array | null {
  if (typeof s !== 'string' || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return null; // the regex needs at least one character
  let bin: string;
  try { bin = atob(s); } catch { return null; }
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  // One piece, one spelling: only the string a writer produces is accepted (atob also takes extra low bits in the last character).
  let again = '';
  for (let i = 0; i < b.length; i++) again += String.fromCharCode(b[i]);
  return b.length > 0 && btoa(again) === s ? b : null;
}
const validIndex = (i: unknown): i is number => typeof i === 'number' && Number.isInteger(i) && i >= 1 && i <= 255;
function setIdBytes(setId: unknown): Uint8Array {
  if (typeof setId !== 'string' || !/^[0-9a-fA-F]{64}$/.test(setId)) throw new Error('set id must be 64 hex characters');
  return hexToBytes(setId.toLowerCase());
}
function hashPiece(setId: Uint8Array, index: number, piece: Uint8Array): Uint8Array {
  const domain = new TextEncoder().encode(COMMIT_DOMAIN);
  const buf = new Uint8Array(domain.length + SET_ID_BYTES + 1 + piece.length);
  buf.set(domain, 0);
  buf.set(setId, domain.length);
  buf[domain.length + SET_ID_BYTES] = index;
  buf.set(piece, domain.length + SET_ID_BYTES + 1);
  return sha256(buf);
}

/** A fresh random set id (64 hex characters). One per split: pieces of different splits never share one. */
export function newSetId(): string {
  const c = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  if (!c || typeof c.getRandomValues !== 'function') throw new Error('no CSPRNG available');
  return bytesToHex(c.getRandomValues(new Uint8Array(SET_ID_BYTES)));
}

/** The commitment (64 hex) to one piece under a set id and a label. Throws on an input that is not a set id, a label 1..255, or a non-empty base64 piece. */
export function commitPiece(setId: string, index: number, pieceB64: string): string {
  const s = setIdBytes(setId);
  if (!validIndex(index)) throw new Error('index must be an integer from 1 to 255');
  const piece = fromB64(pieceB64);
  if (!piece) throw new Error('piece must be non-empty base64');
  return bytesToHex(hashPiece(s, index, piece));
}

/** The owner's list for a split: one commitment per piece. Refuses an empty set and two pieces with one label. */
export function commitSet(setId: string, pieces: readonly CommittablePiece[]): PieceCommitments {
  if (pieces.length === 0) throw new Error('no pieces to commit');
  const commitments: Record<string, string> = {};
  for (const p of pieces) {
    const key = String(p.index);
    if (Object.prototype.hasOwnProperty.call(commitments, key)) throw new Error('duplicate index: each piece needs a unique label');
    commitments[key] = commitPiece(setId, p.index, p.data);
  }
  return { v: 1, set_id: setId.toLowerCase(), commitments };
}

/** The holder's check of the one piece it was sent, against the one commitment it keeps. False (never a throw) for anything that does not match. */
export function verifyOwnPiece(setId: string, index: number, pieceB64: string, commitment: string): boolean {
  try {
    if (typeof commitment !== 'string' || !HEX64.test(commitment)) return false;
    return ctEqual(hexToBytes(commitPiece(setId, index, pieceB64)), hexToBytes(commitment));
  } catch { return false; }
}

/**
 * The owner's check before combining: the pieces that match the list, and each one that does not, with where it was and why.
 * A piece is good when its label is in the list and its commitment matches; a second copy of a good piece is a duplicate; a forgery that
 * arrives BEFORE the genuine piece with its label does not hide it. The caller decides whether enough good pieces remain.
 */
export function sortPieces<T extends CommittablePiece>(list: PieceCommitments, handed: readonly T[]): { good: T[]; bad: BadPiece[] } {
  const good: T[] = [];
  const bad: BadPiece[] = [];
  const seen = new Set<number>();
  const set = setIdBytes(list.set_id);
  handed.forEach((p, at) => {
    const piece = fromB64(p?.data);
    if (!piece || !validIndex(p?.index)) { bad.push({ at, index: p?.index, reason: 'malformed' }); return; }
    const key = String(p.index);
    if (!Object.prototype.hasOwnProperty.call(list.commitments, key)) { bad.push({ at, index: p.index, reason: 'unknown-index' }); return; }
    if (!ctEqual(hashPiece(set, p.index, piece), hexToBytes(list.commitments[key]))) { bad.push({ at, index: p.index, reason: 'mismatch' }); return; }
    if (seen.has(p.index)) { bad.push({ at, index: p.index, reason: 'duplicate' }); return; }
    seen.add(p.index);
    good.push(p);
  });
  return { good, bad };
}

/** Read a stored list back: the exact shape or null. Nothing partly valid is returned. A set id or commitment in upper case is read as lower case. */
export function parseCommitments(raw: unknown): PieceCommitments | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  if (Object.keys(o).sort().join(',') !== 'commitments,set_id,v') return null;
  if (o.v !== 1 || typeof o.set_id !== 'string' || !HEX64.test(o.set_id.toLowerCase())) return null;
  const c = o.commitments;
  if (typeof c !== 'object' || c === null || Array.isArray(c)) return null;
  const out: Record<string, string> = {};
  const seenValues = new Set<string>();
  for (const [k, v] of Object.entries(c as Record<string, unknown>)) {
    if (!/^[1-9][0-9]{0,2}$/.test(k) || !validIndex(Number(k))) return null;
    if (typeof v !== 'string' || !HEX64.test(v.toLowerCase())) return null;
    const lower = v.toLowerCase();
    if (seenValues.has(lower)) return null;
    seenValues.add(lower);
    out[k] = lower;
  }
  if (Object.keys(out).length === 0) return null;
  return { v: 1, set_id: o.set_id.toLowerCase(), commitments: out };
}
