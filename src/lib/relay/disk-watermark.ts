// src/lib/relay/disk-watermark.ts
// Launch plan v2 L4 (Archie lane:svrnty #2202): refuse NEW deposits once the relay's data filesystem is above a watermark, so a deposit
// flood (any id lazily creates a mailbox; ~6.4 GB/sender/week at today's limits) can't fill the box. Owner polls and acks are never
// refused: draining is how the disk frees up.
// The refusal is a 429 (Hypatia #2204): the app shows a definite 4xx as "Not sent. Saved on this device." (true), while a 5xx/507 reads
// as UNCONFIRMED and would discourage the resend. Global, never about a particular mailbox, so it adds no per-mailbox oracle (I-4).
// statfs is re-read at most every CHECK_MS. If it can't be read, deposits are ALLOWED (fail-open, warned once): a broken statfs must not
// stop all mail; the rate limit and the per-mailbox cap still hold.

import { statfsSync } from 'node:fs';
import { dirname } from 'node:path';
import { mailboxConfig } from './mailbox-config';

const CHECK_MS = 30_000;

export interface StatfsLike {
  blocks: number | bigint;
  bavail: number | bigint;
  bsize: number | bigint;
}
type Statfs = (path: string) => StatfsLike;

let cache: { path: string; at: number; full: boolean } | null = null;
let warnedUnreadable = false;

/** Fraction of the filesystem holding `path` that is in use (non-root view: 1 - bavail/blocks), or null if it can't be read. */
export function usedFraction(path: string, statfs: Statfs = statfsSync): number | null {
  try {
    const s = statfs(dirname(path));
    const blocks = Number(s.blocks);
    const avail = Number(s.bavail);
    if (!(blocks > 0) || !(avail >= 0)) return null;
    return 1 - avail / blocks;
  } catch {
    return null;
  }
}

/** True when new deposits must be refused. `path` = the relay's SQLite file. */
export function relayDiskFull(path: string, now: number, statfs: Statfs = statfsSync): boolean {
  if (path === ':memory:') return false;
  if (cache && cache.path === path && now - cache.at < CHECK_MS) return cache.full;
  const used = usedFraction(path, statfs);
  let full = false;
  if (used === null) {
    if (!warnedUnreadable) console.warn('[relay] disk watermark: data filesystem unreadable; deposits allowed');
    warnedUnreadable = true;
  } else {
    full = used * 100 >= mailboxConfig().diskWatermarkPct;
  }
  if (full !== (cache?.full ?? false)) {
    // The alert: one line per transition, no ids, no IPs.
    if (full) console.error(`[relay] DISK WATERMARK: data filesystem ${(used! * 100).toFixed(1)}% used; refusing new deposits`);
    else console.warn('[relay] disk watermark cleared; accepting deposits');
  }
  cache = { path, at: now, full };
  return full;
}

/** Tests only. */
export function resetDiskWatermarkCache(): void {
  cache = null;
  warnedUnreadable = false;
}
