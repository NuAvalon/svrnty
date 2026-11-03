// src/lib/trust/psi-epoch-book.ts
/**
 * What this device holds for ONE friend's per-epoch secrets, and the rule for taking a new one in. Library only and
 * PURE: no storage, no clock, no randomness, nothing calls it. Persisting the record (and making that write safe
 * against a concurrent write to the same contact) is the next slice; the record is a plain JSON-able value so that
 * slice can store it wherever it is decided to live.
 *
 *   record = { v: 1, cur: { e, know, trust }, prev: { e, know, trust } | null, adoptedTick }
 *
 * The friend's two layers roll TOGETHER under ONE epoch number `e`, so there is one acceptance rule per friend, not
 * one per layer. A note is taken in only if its `e` is STRICTLY greater than the current one:
 *   - greater   -> adopted: the old `cur` becomes `prev` (the one before that is forgotten), the new fields become `cur`;
 *                  a friend who was offline across rolls simply adopts e+2.
 *   - equal and the same bytes  -> 'duplicate' (a benign redelivery; the record is returned untouched).
 *   - equal and DIFFERENT bytes -> 'conflict' (dropped; an equal epoch never replaces what is held, in either direction).
 *   - lower                     -> 'stale' (dropped; no rollback, no replay).
 *   - anything malformed        -> 'invalid' (dropped).
 * A note is taken whole or not at all. A decoy field and a real one are stored identically, so the record does not
 * show which layers this device was actually let into.
 *
 * `prev` is kept for a short window counted in the holder's OWN ticks (PSI_PREV_TICKS), supplied by the caller as an
 * integer; this module never reads a clock. A tick that went BACKWARDS (a restored counter) drops `prev`: losing a
 * match for a while is the safe direction, keeping it longer is not.
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { psiElement, EPOCH_SECRET_LEN, type PsiLayer } from './psi-epoch-element';

export const PSI_EPOCH_RECORD_V = 1;
/** How many of the holder's own ticks `prev` is kept after a new epoch is adopted. */
export const PSI_PREV_TICKS = 12;

const HEX_SECRET = /^[0-9a-f]{64}$/;

/** The epoch carries the sender's clock in minutes above this many low bits: e = (minutes * 2^20) + sequence. */
const EPOCH_SEQ_BITS = 20;
const EPOCH_SEQ_RANGE = 2 ** EPOCH_SEQ_BITS;
/**
 * How far ahead of the holder's own clock a note's epoch may be and still be taken in: 24 hours. It is SHARED between the sender's clock lead and
 * the holder's clock lag (an honest note is taken in when the sender's lead plus the holder's lag is at most this), not added to it.
 */
export const PSI_EPOCH_SKEW_MINUTES = 24 * 60;

export interface EpochSlot {
  e: number;
  /** lowercase hex, 32 bytes */
  know: string;
  trust: string;
}

export interface PsiEpochRecord {
  v: typeof PSI_EPOCH_RECORD_V;
  cur: EpochSlot;
  prev: EpochSlot | null;
  /** the holder's tick at which `cur` was adopted */
  adoptedTick: number;
}

/**
 * The highest epoch a holder whose clock reads `nowMinutes` (whole minutes since the Unix epoch) takes in: the last slot of the minute
 * `skewMinutes` ahead. Built with multiplication, NOT `<<`: a minute count of this size shifted by 20 overflows a 32-bit shift.
 */
export function maxEpochFor(nowMinutes: number, skewMinutes: number = PSI_EPOCH_SKEW_MINUTES): number {
  if (!isSafeNonNeg(nowMinutes) || !isSafeNonNeg(skewMinutes)) throw new TypeError('psi-epoch-book: minutes must be non-negative safe integers');
  const max = (nowMinutes + skewMinutes) * EPOCH_SEQ_RANGE + (EPOCH_SEQ_RANGE - 1);
  if (!Number.isSafeInteger(max)) throw new TypeError('psi-epoch-book: the bound does not fit a safe integer');
  return max;
}

export type ApplyOutcome = 'adopted' | 'duplicate' | 'conflict' | 'stale' | 'invalid';

export interface OpenedNote {
  epoch: number;
  know: Uint8Array;
  trust: Uint8Array;
}

const isSafeNonNeg = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;

function checkTick(tick: unknown): number {
  if (!isSafeNonNeg(tick)) throw new TypeError('psi-epoch-book: tick must be a non-negative safe integer');
  return tick;
}

function slotFromNote(n: OpenedNote): EpochSlot | null {
  if (!isSafeNonNeg(n.epoch)) return null;
  for (const f of [n.know, n.trust]) if (!(f instanceof Uint8Array) || f.length !== EPOCH_SECRET_LEN) return null;
  const know = bytesToHex(n.know);
  const trust = bytesToHex(n.trust);
  if (know === trust) return null; // one secret for both layers is never a legitimate note
  return { e: n.epoch, know, trust };
}

/**
 * Take a note's epoch in, or say why not. Never mutates its arguments. `record` is null when nothing is held yet for
 * this friend (any epoch >= 0 is then adopted).
 *
 * `maxEpoch` (optional) is the highest epoch the caller will take in, computed by the caller from the holder's clock (see maxEpochFor); this
 * module reads no clock. A note above it is `invalid`: dropped, the record and the adoption tick unchanged. Omitted, there is no upper bound.
 * It is a number the caller computed, so a value that is not a non-negative safe integer is a programming error, never "no bound".
 */
export function applyEpochNote(
  record: PsiEpochRecord | null,
  note: OpenedNote,
  tick: number,
  maxEpoch?: number,
): { outcome: ApplyOutcome; record: PsiEpochRecord | null } {
  const t = checkTick(tick);
  if (maxEpoch !== undefined && !isSafeNonNeg(maxEpoch)) throw new TypeError('psi-epoch-book: maxEpoch must be a non-negative safe integer');
  const slot = slotFromNote(note);
  if (slot === null) return { outcome: 'invalid', record };
  if (maxEpoch !== undefined && slot.e > maxEpoch) return { outcome: 'invalid', record };
  if (record === null) return { outcome: 'adopted', record: { v: PSI_EPOCH_RECORD_V, cur: slot, prev: null, adoptedTick: t } };
  if (slot.e < record.cur.e) return { outcome: 'stale', record };
  if (slot.e === record.cur.e) {
    const same = slot.know === record.cur.know && slot.trust === record.cur.trust;
    return { outcome: same ? 'duplicate' : 'conflict', record };
  }
  return { outcome: 'adopted', record: { v: PSI_EPOCH_RECORD_V, cur: slot, prev: { ...record.cur }, adoptedTick: t } };
}

/** Drop `prev` once PSI_PREV_TICKS of the holder's own ticks have passed since `cur` was adopted (or the tick went backwards). */
export function expirePrev(record: PsiEpochRecord, tick: number): PsiEpochRecord {
  const t = checkTick(tick);
  if (record.prev === null) return record;
  if (t < record.adoptedTick || t - record.adoptedTick >= PSI_PREV_TICKS) return { ...record, prev: null };
  return record;
}

/**
 * The (epoch, element) pairs this device can form for the friend `fp` at `layer`: `cur`, then `prev` if still held.
 * These are what PSI would match on in place of the friend's bare fingerprint.
 */
export function epochElementsFor(
  record: PsiEpochRecord,
  fp: string,
  layer: PsiLayer,
): Array<{ epoch: number; role: 'cur' | 'prev'; element: Uint8Array }> {
  const out: Array<{ epoch: number; role: 'cur' | 'prev'; element: Uint8Array }> = [
    { epoch: record.cur.e, role: 'cur', element: psiElement(fp, layer, record.cur.e, hexToBytes(record.cur[layer])) },
  ];
  if (record.prev !== null) {
    out.push({ epoch: record.prev.e, role: 'prev', element: psiElement(fp, layer, record.prev.e, hexToBytes(record.prev[layer])) });
  }
  return out;
}

// ── persistence shape ───────────────────────────────────────────────────────────────────────────────────────────

/** A fixed-order JSON string, so the stored form does not drift. */
export function serializeEpochRecord(r: PsiEpochRecord): string {
  const slot = (s: EpochSlot) => ({ e: s.e, know: s.know, trust: s.trust });
  return JSON.stringify({ v: r.v, cur: slot(r.cur), prev: r.prev === null ? null : slot(r.prev), adoptedTick: r.adoptedTick });
}

function restoreSlot(x: unknown): EpochSlot | null {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) return null;
  const o = x as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== 3 || !keys.includes('e') || !keys.includes('know') || !keys.includes('trust')) return null;
  if (!isSafeNonNeg(o.e)) return null;
  if (typeof o.know !== 'string' || typeof o.trust !== 'string') return null;
  if (!HEX_SECRET.test(o.know) || !HEX_SECRET.test(o.trust)) return null;
  if (o.know === o.trust) return null; // applyEpochNote never produces this, so a stored record that has it is not one of ours
  return { e: o.e, know: o.know, trust: o.trust };
}

/** Restore a stored record, or null on ANY malformation: not a string, not JSON, wrong version, a missing or extra key, a bad width or digit, an inconsistent epoch order. Fail closed. */
export function restoreEpochRecord(raw: unknown): PsiEpochRecord | null {
  if (typeof raw !== 'string' || raw.length === 0) return null;
  let o: unknown;
  try {
    o = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof o !== 'object' || o === null || Array.isArray(o)) return null;
  const rec = o as Record<string, unknown>;
  const keys = Object.keys(rec);
  if (keys.length !== 4 || !['v', 'cur', 'prev', 'adoptedTick'].every((k) => keys.includes(k))) return null;
  if (rec.v !== PSI_EPOCH_RECORD_V) return null;
  if (!isSafeNonNeg(rec.adoptedTick)) return null;
  const cur = restoreSlot(rec.cur);
  if (cur === null) return null;
  let prev: EpochSlot | null = null;
  if (rec.prev !== null) {
    prev = restoreSlot(rec.prev);
    if (prev === null || prev.e >= cur.e) return null;
  }
  return { v: PSI_EPOCH_RECORD_V, cur, prev, adoptedTick: rec.adoptedTick };
}
