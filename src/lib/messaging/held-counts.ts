// src/lib/messaging/held-counts.ts: how many HELD notes each frozen sender has, kept as ONE sealed row so the per-arrival cap check does not decrypt the whole store.
// PURE: no storage, no crypto, no clock. The store (store.ts) reads and writes the row; this file says what the row means and when it can be trusted.
//
// Why it exists: the cap check ran countHeldFrom on every new held note from a frozen sender, and that decrypts every thread and every note in the store (measured: 0.4 - 1.3 s
// unthrottled, 1.1 - 4.5 s at 4x CPU throttle, with 500 held + 5000 ordinary notes). A sender chooses how often it arrives, so the cost was a lever they held. The count is a CACHE of the
// held rows, not the truth:
//   - EVERY write that changes a held row also changes this row, in the same transaction (store.ts: one compare-and-set over the note row and this row);
//   - a row that is absent, unreadable or marked "dirty" is NEVER read as 0 (0 would bypass the cap) and never as "full" (that would refuse notes early, the worse error for a person
//     keeping evidence): the caller falls back to the full scan for that decision, which is slow but right;
//   - the full scan also runs OFF the receive path (on unlock) and rewrites the row from the notes themselves, so a row that drifted heals.
// The row's length must not say how many senders are frozen, so it is padded to a fixed size bucket before it is sealed.
import { isHeldNote } from './held-note';
import type { NoteRecord } from './types';

/** The ONE key the row lives under in the notes DB's settings store. Constant, and written for everyone at the first reconcile, so a key listing does not say whether anyone is frozen. */
export const HELD_COUNTS_KEY = 'held_counts:v1';
export const HELD_COUNTS_VERSION = 1;
/** Plaintext bytes of the padded payload are always a whole number of these: the sealed row's size shows the bucket, not the sender count. */
export const HELD_COUNTS_BUCKET = 4096;
/** A count above this is not believed (the per-sender cap is far below it): the row is read as unreadable. */
const MAX_COUNT = 1_000_000;
const MAX_SENDERS = 5_000;
const KEY_CHARS = /^[A-Za-z0-9:._-]+$/;

export type HeldCounts = ReadonlyMap<string, number>;
/** What a stored row says: usable counts, "dirty" (a held row changed while the counts were not usable: unknown until the next reconcile), or not understood at all (null). */
export type HeldCountsRead = { state: 'ok'; counts: HeldCounts } | { state: 'dirty' } | null;
/** Why the cap check did not use the row (a reason code for the log): there was none, it was dirty, or it could not be read. */
export type CountFallback = 'absent' | 'dirty' | 'unreadable';

/** THE rule for "this note counts as held for this sender", used by the cap scan, the write path and the reconcile, so they cannot disagree. The sender is compared case-insensitively. */
export function heldInboundSender(note: NoteRecord): string | null {
  return isHeldNote(note) && note.direction === 'inbound' ? note.from_fingerprint.toLowerCase() : null;
}

/** The counts after one row went from counting for `before` to counting for `after` (either may be null = not a held inbound row). A fresh map; nothing is ever below 1 or kept at 0. */
export function applyChange(counts: HeldCounts, before: string | null, after: string | null): Map<string, number> {
  const next = new Map(counts);
  if (before === after) return next;
  if (before !== null) {
    const n = (next.get(before) ?? 0) - 1;
    if (n > 0) next.set(before, n);
    else next.delete(before);
  }
  if (after !== null) next.set(after, (next.get(after) ?? 0) + 1);
  return next;
}

/** The counts the notes themselves say: what the full scan and the reconcile compute. */
export function countsFromNotes(notes: Iterable<NoteRecord>): Map<string, number> {
  const out = new Map<string, number>();
  for (const n of notes) {
    const who = heldInboundSender(n);
    if (who !== null) out.set(who, (out.get(who) ?? 0) + 1);
  }
  return out;
}

/** What goes into the sealed row, padded with filler up to the next bucket. Pairs, sorted, so no sender key can ever be read as an object property. */
export function sealedShape(read: HeldCountsRead): { v: number; s: 'ok' | 'dirty'; c: Array<[string, number]>; pad: string } {
  const c: Array<[string, number]> = read && read.state === 'ok' ? [...read.counts.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)) : [];
  const base = { v: HELD_COUNTS_VERSION, s: read && read.state === 'ok' ? ('ok' as const) : ('dirty' as const), c, pad: '' };
  const len = JSON.stringify(base).length;
  const target = Math.max(HELD_COUNTS_BUCKET, Math.ceil(len / HELD_COUNTS_BUCKET) * HELD_COUNTS_BUCKET);
  return { ...base, pad: 'x'.repeat(target - len) };
}

/** Read a stored payload strictly. Anything that is not exactly what sealedShape writes is "not understood" (null): the caller falls back to the scan, it never guesses. */
export function parseHeldCounts(raw: unknown): HeldCountsRead {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  if (r.v !== HELD_COUNTS_VERSION || typeof r.pad !== 'string' || !Array.isArray(r.c)) return null;
  if (Object.keys(r).some((k) => k !== 'v' && k !== 's' && k !== 'c' && k !== 'pad')) return null;
  if (r.s === 'dirty') return r.c.length === 0 ? { state: 'dirty' } : null;
  if (r.s !== 'ok' || r.c.length > MAX_SENDERS) return null;
  const counts = new Map<string, number>();
  for (const pair of r.c) {
    if (!Array.isArray(pair) || pair.length !== 2) return null;
    const [who, n] = pair as [unknown, unknown];
    if (typeof who !== 'string' || who.length === 0 || who.length > 200 || !KEY_CHARS.test(who) || who !== who.toLowerCase()) return null;
    if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < 1 || n > MAX_COUNT || counts.has(who)) return null;
    counts.set(who, n);
  }
  return { state: 'ok', counts };
}

/** What the cap check does with a read: the count for one sender, or the reason it could not use the row. A sender that is not in a usable row has 0 held (the row is the whole truth when ok). */
export function countFrom(read: HeldCountsRead | 'absent', sender: string): { count: number } | { fallback: CountFallback } {
  if (read === 'absent') return { fallback: 'absent' };
  if (read === null) return { fallback: 'unreadable' };
  if (read.state === 'dirty') return { fallback: 'dirty' };
  return { count: read.counts.get(sender.toLowerCase()) ?? 0 };
}
