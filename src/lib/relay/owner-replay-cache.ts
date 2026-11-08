// src/lib/relay/owner-replay-cache.ts
// One-time use of a signed v1 owner request (poll / ack / claim). v2 is NOT wired to this cache: v2 owner requests are refused by
// the routes until RELAY_OWNER_V2_ENABLED is set, and turning that on needs this protection added to the v2 verifier first. Freshness alone let a captured or self-made request be
// re-sent for the whole window, each copy costing the relay a full signature verify. Every owner bundle carries a random nonce;
// this remembers (mailbox_id, nonce) until the request's freshness window closes, so a second copy is refused like a non-owner.
//
// Only a request whose signature already checked out is recorded (after the full v1 check), so a
// stranger cannot fill the cache with nonces of mailboxes they don't own. Bounded: at replayCacheMax live entries a sweep runs; if it
// is still full, the one-time check is SKIPPED for that request (fail OPEN, counted and logged), never an eviction (that would re-open
// a recorded replay) and never a refusal (anyone can mint an identity and sign validly, so failing closed would hand any requester a
// cheap global outage). Skipping is never worse than before this cache: a replay costs CPU, and polls are read-only.
//
// Environment-neutral (plain Map on globalThis): mailbox-auth.ts is also loaded by the browser, which never calls this.

import { mailboxConfig } from './mailbox-config';
import { logDeposit429 } from './deposit-429-log';

const MAX_NONCE_LEN = 128;
const SWEEP_EVERY_MS = 1_000; // at most one O(n) sweep per second, however many verified requests arrive while the cache is full

declare global {
  var __ownerReplayCache: Map<string, number> | undefined; // key -> expiresAt (ms)
  var __ownerReplaySweptAt: number | undefined;
}

function cache(): Map<string, number> {
  if (!globalThis.__ownerReplayCache) globalThis.__ownerReplayCache = new Map();
  return globalThis.__ownerReplayCache;
}

const keyOf = (mailboxId: string, nonce: string) => `${mailboxId}\n${nonce}`;

function sweep(c: Map<string, number>, now: number): void {
  for (const [k, exp] of c) if (now >= exp) c.delete(k);
}

/** Drop a few of the oldest entries if expired (bounded work per call, so the map tracks its live size in steady state). */
function trimOldest(c: Map<string, number>, now: number): void {
  let n = 0;
  for (const [k, exp] of c) {
    if (n++ >= 4) break;
    if (now >= exp) c.delete(k);
  }
}

/** True if this (mailbox_id, nonce) was already used and its window has not closed. A malformed nonce reads as used. */
export function isOwnerNonceSeen(mailboxId: string, nonce: string, now: number): boolean {
  if (typeof nonce !== 'string' || nonce.length === 0 || nonce.length > MAX_NONCE_LEN) return true;
  const exp = cache().get(keyOf(mailboxId, nonce));
  return exp !== undefined && now < exp;
}

/**
 * Record a verified request's nonce until `expiresAt` (its ts + the freshness window). True = proceed (first use, or the cache is full
 * and the check is skipped: fail open, logged). False = a replay or a malformed nonce. Synchronous, so check-and-insert is atomic.
 */
export function claimOwnerNonce(mailboxId: string, nonce: string, expiresAt: number, now: number): boolean {
  if (isOwnerNonceSeen(mailboxId, nonce, now)) return false;
  const c = cache();
  trimOldest(c, now);
  if (c.size >= mailboxConfig().replayCacheMax) {
    if (now - (globalThis.__ownerReplaySweptAt ?? 0) >= SWEEP_EVERY_MS) {
      sweep(c, now);
      globalThis.__ownerReplaySweptAt = now;
    }
    if (c.size >= mailboxConfig().replayCacheMax) {
      logDeposit429('replay_cache_full', now);
      return true;
    }
  }
  c.set(keyOf(mailboxId, nonce), expiresAt);
  return true;
}

/** Live entries after a sweep (test + metrics seam). */
export function ownerReplayCacheSize(now: number): number {
  const c = cache();
  sweep(c, now);
  return c.size;
}

/** Test seam: forget every nonce. */
export function resetOwnerReplayCache(): void {
  globalThis.__ownerReplayCache = new Map();
  globalThis.__ownerReplaySweptAt = undefined;
}
