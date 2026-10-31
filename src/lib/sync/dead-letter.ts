// src/lib/sync/dead-letter.ts
// #720 reliable receive: the PURE half of the dead-letter record (contract v2 R1/R2/R9, Flint F1-F6). No I/O, no React.
//
// A mailbox blob this device could not turn into a stored message must never vanish silently. Before the relay is told to delete it
// (ack), a small METADATA-ONLY row is committed by the caller (the store lives elsewhere). This module decides what that row may contain and
// which held envelopes have outlived the keep bounds. It never sees, stores or returns any text from the blob (F2/F4).

import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { asMailboxEnvelopePackage } from './hybrid-dual-read';

/** Why a blob did not become a message (F6: "can't open" and "failed to verify" are different classes). */
export const DEAD_LETTER_REASONS = ['unknown-format', 'decrypt-failed', 'missing-key', 'verify-failed', 'unverified-frame', 'not-in-book', 'ratchet-unopenable', 'ratchet-local', 'ratchet-desync', 'session-reset', 'expired'] as const;
export type DeadLetterReason =
  | 'unknown-format' // not a shape this build can open
  | 'decrypt-failed' // right shape, would not open
  | 'missing-key' // a hybrid package sealed to a key this device does not have (held, then bounded)
  | 'verify-failed' // opened, but the sender could not be authenticated
  | 'unverified-frame' // a NON-MESSAGE frame (contact-update, joiner, receipt) from a sender we could not authenticate; never counted as a message (Flint ruling a)
  | 'not-in-book' // opened and authenticated, sender is not in the Gate (R9)
  | 'ratchet-unopenable' // opened and authenticated, a known contact's ratchet body would not open: the FRAME's fault (a verdict)
  | 'ratchet-local' // same frame, but something on THIS DEVICE stopped it (own key missing, session row unreadable, unknown cause): HELD, then recorded past the bound
  | 'ratchet-desync' // same frame, the sessions no longer agree (a receive failure on an authenticated contact's frame): HELD with backoff, then recorded (T2)
  | 'session-reset' // a held ratchet frame released because the USER reset the session with that contact: our own deliberate act (T3, Flint reset semantics R2)
  | 'expired'; // arrived after its time limit

/**
 * Only these reasons come AFTER the sender was authenticated, so only they may carry a fingerprint (F3: the sender fields of an
 * unopened or unverified envelope are attacker-controlled and must never be stored or shown).
 */
export const AUTHENTICATED_REASONS: ReadonlySet<DeadLetterReason> = new Set<DeadLetterReason>(['not-in-book', 'ratchet-unopenable', 'ratchet-local', 'ratchet-desync', 'session-reset']);

/**
 * Terminal outcomes that CONSUME a blob without losing a message: the content is already stored, or it was never a message.
 * Listed explicitly so "benign" cannot silently grow; a test pins this exact list. Anything terminal that is not here must write a row.
 */
export const BENIGN_TERMINALS = ['contact-update-stale', 'joiner-already-known', 'receipt-no-match'] as const;
export type BenignTerminal = (typeof BENIGN_TERMINALS)[number];

/**
 * Reasons whose rows are NOT about a message (Flint ruling a, Hypatia #2001): a stranger's contact-update, joiner or receipt frame.
 * A row of one of these may exist, but it must never feed any "N messages ..." count in the UI.
 */
export const NON_MESSAGE_REASONS: ReadonlySet<DeadLetterReason> = new Set<DeadLetterReason>(['unverified-frame']);
export function isMessageReason(reason: DeadLetterReason): boolean {
  return !NON_MESSAGE_REASONS.has(reason);
}

/** What KIND of blob it was, from its shape alone. Never any content (F2). */
export const BLOB_KINDS = ['hybrid-package', 'openpgp-armor', 'json', 'other'] as const;
export type BlobKind = (typeof BLOB_KINDS)[number];

export function classifyBlob(blob: string): BlobKind {
  if (asMailboxEnvelopePackage(blob) != null) return 'hybrid-package';
  if (blob.startsWith('-----BEGIN PGP MESSAGE-----')) return 'openpgp-armor';
  try {
    const v = JSON.parse(blob);
    if (v && typeof v === 'object') return 'json';
  } catch {
    /* not JSON */
  }
  return 'other';
}

export interface DeadLetterRow {
  envelope_id: string;
  first_seen: string; // ISO time of the FIRST poll that saw this envelope (local clock)
  reason: DeadLetterReason;
  blob_kind: BlobKind;
  /** Present only for AUTHENTICATED_REASONS and only when well-formed. */
  fp?: string;
}

// The relay lets a depositor choose the envelope id (retry-dedup), so it is attacker-controlled until proven otherwise (F4):
// a short, plain charset only. A real id (a UUID) always passes; anything else is refused and gets no row.
const SAFE_ID = /^[A-Za-z0-9._:-]{1,100}$/;
const FP_HEX = /^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/;

export function safeEnvelopeId(id: unknown): string | null {
  return typeof id === 'string' && SAFE_ID.test(id) ? id : null;
}

/**
 * The key a record is stored under (E1, Flint #2029). A safe relay id is its own key. An id outside the plain charset (the depositor chose
 * it, so it is attacker text) is NEVER stored or shown: it is keyed by 'x:' + the first 32 hex of sha256(its UTF-8 bytes), a safe string of
 * 34 characters. The caller still acks the ORIGINAL id, so a hostile id can neither get a free ride (it is recorded) nor sit on the relay
 * until its TTL filling the mailbox. Not a string at all: null (nothing can be recorded or acked for it).
 */
export function recordKeyFor(id: unknown): string | null {
  if (typeof id !== 'string') return null;
  return safeEnvelopeId(id) ?? `x:${bytesToHex(sha256(utf8ToBytes(id))).slice(0, 32)}`;
}

/**
 * Build the row to store, or null when it cannot be built SAFELY (unsafe id, unreadable time). The blob is read for its KIND only;
 * the returned row has exactly the keys above and nothing from the blob's content.
 */
export function makeDeadLetterRow(a: {
  envelopeId: unknown;
  firstSeen: string;
  reason: DeadLetterReason;
  blob: string;
  fp?: string;
}): DeadLetterRow | null {
  const envelope_id = safeEnvelopeId(a.envelopeId);
  if (!envelope_id) return null;
  if (!Number.isFinite(Date.parse(a.firstSeen))) return null;
  const row: DeadLetterRow = { envelope_id, first_seen: a.firstSeen, reason: a.reason, blob_kind: classifyBlob(a.blob) };
  if (AUTHENTICATED_REASONS.has(a.reason) && typeof a.fp === 'string' && FP_HEX.test(a.fp)) row.fp = a.fp.toLowerCase();
  return row;
}

export const KEEP_MAX_COUNT = 50; // F1: held envelopes kept per mailbox
export const KEEP_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // F1: and for at most this long after first seen

export interface BoundPlan {
  keep: string[];
  /** Past a bound: write the dead-letter row FIRST, then ack. */
  release: Array<{ envelope_id: string; cause: 'age' | 'count' }>;
}

/**
 * Which held envelopes stay on the relay, which have outlived the bounds. Oldest first (F1): an envelope is released when it is more
 * than KEEP_MAX_AGE_MS past first_seen (a row whose time cannot be read counts as expired), then, if more than KEEP_MAX_COUNT remain,
 * the OLDEST extras. Real mail keeps flowing: this only ever touches envelopes already classed as held.
 */
export function planBound(
  held: ReadonlyArray<{ envelope_id: string; first_seen: string }>,
  nowMs: number,
  opts: { maxCount?: number; maxAgeMs?: number } = {},
): BoundPlan {
  const maxCount = opts.maxCount ?? KEEP_MAX_COUNT;
  const maxAgeMs = opts.maxAgeMs ?? KEEP_MAX_AGE_MS;
  const ordered = held
    .map((h) => ({ id: h.envelope_id, t: Date.parse(h.first_seen) }))
    .sort((a, b) => (Number.isNaN(a.t) ? -Infinity : a.t) - (Number.isNaN(b.t) ? -Infinity : b.t) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const release: BoundPlan['release'] = [];
  const alive: string[] = [];
  for (const h of ordered) {
    if (Number.isNaN(h.t) || nowMs - h.t > maxAgeMs) release.push({ envelope_id: h.id, cause: 'age' });
    else alive.push(h.id);
  }
  const over = alive.length - maxCount;
  if (over > 0) for (const id of alive.splice(0, over)) release.push({ envelope_id: id, cause: 'count' });
  return { keep: alive, release };
}

/**
 * Validate a row read back from storage (or about to be written). Exact key set, closed value sets, safe id, readable time, and a
 * fingerprint only for authenticated reasons: anything else is refused (null), so a corrupt or tampered row can never reach the UI.
 */
export function parseDeadLetterRow(raw: unknown): DeadLetterRow | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  for (const k of Object.keys(o)) if (!['envelope_id', 'first_seen', 'reason', 'blob_kind', 'fp'].includes(k)) return null;
  const envelope_id = safeEnvelopeId(o.envelope_id);
  if (!envelope_id) return null;
  if (typeof o.first_seen !== 'string' || !Number.isFinite(Date.parse(o.first_seen))) return null;
  if (!(DEAD_LETTER_REASONS as readonly unknown[]).includes(o.reason)) return null;
  if (!(BLOB_KINDS as readonly unknown[]).includes(o.blob_kind)) return null;
  const row: DeadLetterRow = { envelope_id, first_seen: o.first_seen, reason: o.reason as DeadLetterReason, blob_kind: o.blob_kind as BlobKind };
  if (o.fp !== undefined) {
    if (!AUTHENTICATED_REASONS.has(row.reason) || typeof o.fp !== 'string' || !FP_HEX.test(o.fp)) return null;
    row.fp = o.fp.toLowerCase();
  }
  return row;
}

// Row retention. The contract does not specify one; without it, junk that is acked-with-a-row would grow storage without limit. Archie accepted
// 200 rows / 30 days (#1993). Flint's B1 (#2026, #2029): deposits are unauthenticated, so ONE shared budget let an outsider evict the record of a
// REAL contact's failed message (~200 junk blobs inside the relay's per-IP limit). And "authenticated by signature" is not "admitted": a fresh
// identity signs a not-in-book note for free, so that class can also be filled by an outsider. THREE budgets, never sharing:
//   junk              every unauthenticated reason, and any row with no reason ............ ROW_MAX_COUNT (200) together
//   not-in-book       authenticated by signature, sender NOT in the Gate (free to mint) ... ROW_MAX_NOT_IN_BOOK (200) together
//   ratchet-unopenable / ratchet-local an ADMITTED contact's body that would not open (either class) ..... ROW_MAX_PER_CONTACT (50) PER fp (Archie #2030)
// and every group also drops rows older than ROW_MAX_AGE_MS. Eviction is oldest-first inside a group only.
export const ROW_MAX_COUNT = 200;
export const ROW_MAX_NOT_IN_BOOK = 200;
export const ROW_MAX_PER_CONTACT = 50;
export const ROW_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

function pruneGroup(rows: ReadonlyArray<{ envelope_id: string; first_seen: string }>, nowMs: number, maxRows: number, maxAgeMs: number): string[] {
  const ordered = rows
    .map((r) => ({ id: r.envelope_id, t: Date.parse(r.first_seen) }))
    .sort((a, b) => (Number.isNaN(a.t) ? -Infinity : a.t) - (Number.isNaN(b.t) ? -Infinity : b.t) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const drop: string[] = [];
  const keep: string[] = [];
  for (const r of ordered) (Number.isNaN(r.t) || nowMs - r.t > maxAgeMs ? drop : keep).push(r.id);
  const over = keep.length - maxRows;
  if (over > 0) drop.push(...keep.splice(0, over));
  return drop;
}

/**
 * Which stored rows to delete. Each budget above is pruned on its own: older than ROW_MAX_AGE_MS goes (an unreadable time counts as old), then
 * the oldest beyond that budget's cap. A row with NO reason (or an unknown one) is junk: it can never claim a protected budget. A
 * ratchet-unopenable row with no readable fp lands in its own '' bucket, still apart from junk and from every real contact.
 */
export function planPrune(
  rows: ReadonlyArray<{ envelope_id: string; first_seen: string; reason?: string; fp?: string }>,
  nowMs: number,
  opts: { maxRows?: number; maxNotInBook?: number; maxPerContact?: number; maxAgeMs?: number } = {},
): string[] {
  const maxAgeMs = opts.maxAgeMs ?? ROW_MAX_AGE_MS;
  const junk: typeof rows[number][] = [];
  const notInBook: typeof rows[number][] = [];
  const byContact = new Map<string, typeof rows[number][]>();
  for (const r of rows) {
    if (r.reason === 'not-in-book') notInBook.push(r);
    else if (r.reason === 'ratchet-unopenable' || r.reason === 'ratchet-local' || r.reason === 'ratchet-desync' || r.reason === 'session-reset') {
      const k = typeof r.fp === 'string' && FP_HEX.test(r.fp) ? r.fp.toLowerCase() : '';
      const g = byContact.get(k);
      if (g) g.push(r);
      else byContact.set(k, [r]);
    } else junk.push(r);
  }
  const drop = [...pruneGroup(junk, nowMs, opts.maxRows ?? ROW_MAX_COUNT, maxAgeMs), ...pruneGroup(notInBook, nowMs, opts.maxNotInBook ?? ROW_MAX_NOT_IN_BOOK, maxAgeMs)];
  for (const g of byContact.values()) drop.push(...pruneGroup(g, nowMs, opts.maxPerContact ?? ROW_MAX_PER_CONTACT, maxAgeMs));
  return drop;
}
