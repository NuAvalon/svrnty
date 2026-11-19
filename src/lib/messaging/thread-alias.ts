// src/lib/messaging/thread-alias.ts: the local alias that keeps ONE conversation in ONE thread when a sender names a thread they are not a participant of.
// acceptInboundNote never lets a note join a thread its sender is not in (the sender chooses the thread_id on the wire). Such a note goes to a fresh LOCAL thread; this alias
// remembers (sender, claimed id) -> that fresh id so the sender's next notes under the same claimed id join it instead of each making a new thread. It is local metadata only:
// never sent, never synced, never exported, and it never reveals the original thread. Pure here: the key, the strict row, and the bounded update. The row is an encrypted row in
// the notes DB's 'settings' store (adopt-floor.ts pattern), one per sender, so a lookup is one read.
//   - Keyed by the sender's canonical fingerprint; entries keyed by the EXACT claimed id.
//   - Bounded: the newest MAX_THREAD_ALIASES entries per sender. An evicted entry only means the next note makes another fresh thread: it can never fall back to joining the original.
import { normalizeResetFp } from './reset-flag';

export const THREAD_ALIAS_PREFIX = 'thread_alias:';
export const MAX_THREAD_ALIASES = 64;
/** A claimed id longer than this is not aliased (each such note simply gets its own fresh thread): the row stays small and bounded. */
export const MAX_CLAIMED_ID_LENGTH = 200;

export interface ThreadAliasEntry {
  /** The thread id the sender claimed on the wire. */
  c: string;
  /** The local thread id the sender's notes were filed under instead. */
  l: string;
}
export interface ThreadAliasRow {
  /** The sender's canonical fingerprint (lowercase hex). */
  fp: string;
  /** Newest first. */
  entries: ThreadAliasEntry[];
}

/** What acceptInboundNote needs: both calls THROW while the notes store is locked, so a locked store makes the accept retryable and never falls back to joining a thread. */
export interface ThreadAliasPort {
  resolve(senderFingerprint: string, claimedThreadId: string): Promise<string | null>;
  remember(senderFingerprint: string, claimedThreadId: string, localThreadId: string): Promise<void>;
}

/** Whether `fingerprint` is one of the thread's participants (lowercase comparison: a fingerprint is hex, and case must never decide membership). The ONE membership rule, shared by the browser accept path and the headless store. */
export function threadHasParticipant(thread: { participants?: ReadonlyArray<{ fingerprint: unknown }> }, fingerprint: string): boolean {
  const fp = String(fingerprint).toLowerCase();
  return (thread.participants ?? []).some((p) => String(p.fingerprint).toLowerCase() === fp);
}

/**
 * The local thread id for a note whose sender is NOT a participant of the thread they named (the ONE rule, shared): the alias if there is one; else, for a redelivery of a note
 * already stored under a fresh thread, that thread (so a lost alias never splits a redelivery); else a fresh id. It is never the claimed id.
 */
export function freshThreadIdFor(a: { mapped: string | null; priorThreadId: string | null; claimed: string; mint: () => string }): string {
  return a.mapped ?? (a.priorThreadId !== null && a.priorThreadId !== a.claimed ? a.priorThreadId : a.mint());
}

export function threadAliasKey(senderFp: unknown): string | null {
  const fp = normalizeResetFp(senderFp);
  return fp ? `${THREAD_ALIAS_PREFIX}${fp}` : null;
}

const ROW_KEYS = ['entries', 'fp'];
const ENTRY_KEYS = ['c', 'l'];

/** Strict: exactly {fp, entries}, fp canonical lowercase, entries a bounded list of exactly {c, l} strings. Anything else is absent, never repaired. */
export function parseThreadAliasRow(v: unknown): ThreadAliasRow | null {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  if (Object.keys(o).sort().join() !== ROW_KEYS.join()) return null;
  if (typeof o.fp !== 'string' || o.fp !== o.fp.toLowerCase() || normalizeResetFp(o.fp) !== o.fp) return null;
  if (!Array.isArray(o.entries) || o.entries.length > MAX_THREAD_ALIASES) return null;
  const entries: ThreadAliasEntry[] = [];
  for (const e of o.entries) {
    if (!e || typeof e !== 'object' || Array.isArray(e)) return null;
    const r = e as Record<string, unknown>;
    if (Object.keys(r).sort().join() !== ENTRY_KEYS.join()) return null;
    if (typeof r.c !== 'string' || typeof r.l !== 'string' || r.c.length === 0 || r.c.length > MAX_CLAIMED_ID_LENGTH || r.l.length === 0 || r.l.length > MAX_CLAIMED_ID_LENGTH) return null;
    entries.push({ c: r.c, l: r.l });
  }
  return { fp: o.fp, entries };
}

/** The local thread id this sender's notes under `claimed` were filed under, or null. */
export function aliasFor(row: ThreadAliasRow | null, claimed: string): string | null {
  return row?.entries.find((e) => e.c === claimed)?.l ?? null;
}

/** The row after remembering claimed -> local: newest first, one entry per claimed id, bounded. Returns null when the claimed id is too long to alias (nothing to store). */
export function withAlias(row: ThreadAliasRow | null, fp: string, claimed: string, local: string): ThreadAliasRow | null {
  if (claimed.length === 0 || claimed.length > MAX_CLAIMED_ID_LENGTH || local.length === 0 || local.length > MAX_CLAIMED_ID_LENGTH) return null;
  const rest = (row?.entries ?? []).filter((e) => e.c !== claimed);
  return { fp, entries: [{ c: claimed, l: local }, ...rest].slice(0, MAX_THREAD_ALIASES) };
}
