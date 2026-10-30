// src/lib/sync/dead-letter.ts
// #720 reliable receive: the PURE half of the dead-letter record (contract v2 R1/R2/R9, Flint F1-F6). No I/O, no React.
//
// A mailbox blob this device could not turn into a stored message must never vanish silently. Before the relay is told to delete it
// (ack), a small METADATA-ONLY row is committed by the caller (the store lives elsewhere). This module decides what that row may contain and
// which held envelopes have outlived the keep bounds. It never sees, stores or returns any text from the blob (F2/F4).

import { asMailboxEnvelopePackage } from './hybrid-dual-read';

/** Why a blob did not become a message (F6: "can't open" and "failed to verify" are different classes). */
export type DeadLetterReason =
  | 'unknown-format' // not a shape this build can open
  | 'decrypt-failed' // right shape, would not open
  | 'missing-key' // a hybrid package sealed to a key this device does not have (held, then bounded)
  | 'verify-failed' // opened, but the sender could not be authenticated
  | 'not-in-book' // opened and authenticated, sender is not in the Gate (R9)
  | 'ratchet-unopenable' // opened and authenticated, a known contact's ratchet body would not open
  | 'expired'; // arrived after its time limit

/**
 * Only these reasons come AFTER the sender was authenticated, so only they may carry a fingerprint (F3: the sender fields of an
 * unopened or unverified envelope are attacker-controlled and must never be stored or shown).
 */
export const AUTHENTICATED_REASONS: ReadonlySet<DeadLetterReason> = new Set<DeadLetterReason>(['not-in-book', 'ratchet-unopenable']);

/**
 * Terminal outcomes that CONSUME a blob without losing a message: the content is already stored, or it was never a message.
 * Listed explicitly so "benign" cannot silently grow; a test pins this exact list. Anything terminal that is not here must write a row.
 */
export const BENIGN_TERMINALS = ['contact-update-stale', 'joiner-already-known', 'receipt-no-match'] as const;
export type BenignTerminal = (typeof BENIGN_TERMINALS)[number];

/** What KIND of blob it was, from its shape alone. Never any content (F2). */
export type BlobKind = 'hybrid-package' | 'openpgp-armor' | 'json' | 'other';

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
