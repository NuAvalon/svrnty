// src/lib/relay/owner-replay-cache.ts
// One-time use of a signed owner request (poll / ack / claim, v1 and v2). Freshness alone let a captured or self-made request be
// re-sent for the whole window, each copy costing the relay a full signature verify. Every owner bundle carries a random nonce;
// this remembers (mailbox_id, nonce) until the request's freshness window closes, so a second copy is refused like a non-owner.
//
// Only a VERIFIED request is recorded (v2: after Ed25519, before ML-DSA; v1: after the full check), so a stranger cannot fill the
// cache with nonces of mailboxes they don't own. Bounded: at replayCacheMax live entries a sweep runs; if still full the request
// fails CLOSED. Evicting a live entry would re-open its replay. Filling the cache needs that many VALID fresh signatures through
// the per-IP limiter inside one window.
//
// Environment-neutral (plain Map on globalThis): mailbox-auth-v2.ts is also loaded by the browser, which never calls this.

import { mailboxConfig } from './mailbox-config';

const MAX_NONCE_LEN = 128;

declare global {
  var __ownerReplayCache: Map<string, number> | undefined; // key -> expiresAt (ms)
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
 * Record a verified request's nonce until `expiresAt` (its ts + the freshness window). True = first use, proceed. False = a replay,
 * a malformed nonce, or the cache is full of live entries (fail closed). Synchronous, so check-and-insert is atomic.
 */
export function claimOwnerNonce(mailboxId: string, nonce: string, expiresAt: number, now: number): boolean {
  if (isOwnerNonceSeen(mailboxId, nonce, now)) return false;
  const c = cache();
  trimOldest(c, now);
  if (c.size >= mailboxConfig().replayCacheMax) {
    sweep(c, now);
    if (c.size >= mailboxConfig().replayCacheMax) return false;
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
}
