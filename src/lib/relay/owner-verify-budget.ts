// src/lib/relay/owner-verify-budget.ts
// A GLOBAL budget for the expensive step of owner auth, on the event loop that also serves the website.
//
// Measured (warm, distinct keys, one core): a v1 owner verify is ~2.3 ms on the main thread (fingerprint-to-key binding ~1.4 ms +
// OpenPGP verify ~1.0 ms). A v2 owner verify is ~1.8 ms of Ed25519 on the main thread, then ~4 ms of ML-DSA-87 in the worker pool
// (4 workers ≈ 790 verifies/s). So the limit is the MAIN THREAD, not the pool, and one bucket covers both paths. The default 120/s
// × ~2.4 ms ≈ 29% of a core, however the load splits between v1 and v2.
//
// A fresh request costs the requester almost nothing to make, so the per-IP budget and the replay cache are not enough on their own.
//
// Two rules decide who gets a token:
// 1. HARD CAP: every verify, in any share, spends one token from the global bucket. Nothing bypasses it, so the bound on main-thread
//    work holds even if a client address is a lie. It is the last-resort shed that keeps the site up.
// 2. FAIR SHARE, as priority: each address (its /64 for IPv6) has a small refilling share (default 1/s, burst 4; an active tab polls
//    ≈ 0.67/s). A request within its share may take the bucket down to empty. A request beyond its share may only take tokens above
//    a reserve (half the burst). So a few flooding addresses spend the top of the bucket and cannot starve everyone else.
//
// Past either limit a request gets a uniform 503 BEFORE the expensive step; a client treats it like any refused poll ("Could not
// check right now.") and its next tick signs fresh. Honest bound: addresses are not free but they are not scarce. Enough of them,
// each within its share, can still use up the budget (at launch-scale traffic of ~60 verifies/s, about 60 attacking addresses
// start to shed legitimate polls). Only edge rate limiting, in front of the box, closes that.
//
// Order inside a verifier: cheap checks → replay check → THIS → expensive verify. A replay never spends budget.

import { mailboxConfig } from './mailbox-config';
import { logDeposit429 } from './deposit-429-log';

/** Thrown by an owner verifier when the global budget is spent; the routes map it to the uniform 503. The ONLY thing they throw. */
export class OwnerVerifyBusyError extends Error {
  constructor() {
    super('owner verify budget spent');
    this.name = 'OwnerVerifyBusyError';
  }
}

interface Bucket { tokens: number; at: number }
interface BudgetState { global: Bucket; shares: Map<string, Bucket>; sweptAt: number }

const OVERFLOW = '\u0000overflow';
const SWEEP_EVERY_MS = 1_000; // at most one O(n) sweep per second, however many new addresses arrive while the map is full

declare global {
  var __ownerVerifyBudget: BudgetState | undefined;
}

function refill(b: Bucket, rate: number, burst: number, now: number): void {
  const elapsed = Math.max(0, now - b.at);
  b.tokens = Math.min(burst, b.tokens + (elapsed * rate) / 1000);
  b.at = now;
}

/** The address's share bucket, refilled. Bounded memory: when full, new addresses share ONE overflow bucket. */
function shareOf(s: BudgetState, clientKey: string, now: number): Bucket {
  const { ownerVerifyFairPerSec: rate, ownerVerifyFairBurst: burst, ownerRateLimitIpCap: cap } = mailboxConfig();
  let key = clientKey;
  if (!s.shares.has(key) && s.shares.size >= cap) {
    if (now - s.sweptAt >= SWEEP_EVERY_MS) {
      s.sweptAt = now;
      // A share that has refilled completely carries no information: dropping it is the same as forgetting a new address.
      for (const [k, v] of s.shares) if (v.tokens + (Math.max(0, now - v.at) * rate) / 1000 >= burst) s.shares.delete(k);
    }
    if (s.shares.size >= cap) key = OVERFLOW;
  }
  let share = s.shares.get(key);
  if (!share) {
    share = { tokens: burst, at: now };
    s.shares.set(key, share);
    return share;
  }
  refill(share, rate, burst, now);
  return share;
}

/**
 * Take one expensive-verify token for this client (`ownerClientKey(request)`), or throw OwnerVerifyBusyError (and count it).
 * A request within the client's fair share may empty the bucket; one beyond it may only spend tokens above the reserve.
 */
export function takeOwnerVerifyToken(now: number, clientKey: string): void {
  const { ownerVerifyPerSec: rate, ownerVerifyBurst: burst } = mailboxConfig();
  const s = (globalThis.__ownerVerifyBudget ??= { global: { tokens: burst, at: now }, shares: new Map(), sweptAt: 0 });
  refill(s.global, rate, burst, now);
  const share = shareOf(s, clientKey, now);
  const inShare = share.tokens >= 1;
  const reserve = inShare ? 0 : Math.floor(burst / 2);
  if (s.global.tokens < 1 + reserve) {
    logDeposit429('owner_verify_busy', now);
    throw new OwnerVerifyBusyError();
  }
  s.global.tokens -= 1;
  if (inShare) share.tokens -= 1;
}

/** The uniform shed response. Says nothing about any mailbox: decided before the expensive step, from process-wide counters. */
export function ownerVerifyBusyResponse(): Response {
  return Response.json({ error: 'Relay busy.' }, { status: 503, headers: { 'retry-after': '1' } });
}

/** Test seam. */
export function resetOwnerVerifyBudget(): void {
  globalThis.__ownerVerifyBudget = undefined;
}
