// src/lib/relay/mailbox-rate-limit.ts
// Per-IP deposit rate limit for the return-channel mailbox. Independent of the single-use relay's
// limiter (different endpoint, different budget). Config-driven (joint §5.1).
//
// NOTE: like the relay store, this is per-process in-memory (single-node). Horizontal scale needs
// shared state (Redis) — deferred, same posture as the mailbox store.

import { mailboxConfig } from './mailbox-config';
import { budgetKeyOf } from './client-ip';

interface Bucket {
  count: number;
  resetAt: number;
}

const OVERFLOW = '\u0000overflow';
const SWEEP_EVERY_MS = 1_000; // at most one O(n) sweep per second, however many new addresses arrive while the map is full

declare global {
  // eslint-disable-next-line no-var
  var __mailboxRateLimits: Map<string, Bucket> | undefined;
  // eslint-disable-next-line no-var
  var __mailboxRateLimitsSweptAt: number | undefined;
}

function buckets(): Map<string, Bucket> {
  if (!globalThis.__mailboxRateLimits) globalThis.__mailboxRateLimits = new Map();
  return globalThis.__mailboxRateLimits;
}

// #707: the client IP comes ONLY from the header Caddy sets (client-ip.ts); kept exported here for the existing import path.
export { getClientIP } from './client-ip';

/** True if the deposit is allowed; false if the IP is over its per-window ceiling. */
export function checkMailboxRateLimit(ip: string, now: number): boolean {
  const cfg = mailboxConfig();
  const b = buckets();
  let key = budgetKeyOf(ip); // an IPv6 address counts by its /64, so a subscriber's whole block is one budget
  if (!b.has(key) && b.size >= cfg.rateLimitIpCap) {
    if (now - (globalThis.__mailboxRateLimitsSweptAt ?? 0) >= SWEEP_EVERY_MS) {
      globalThis.__mailboxRateLimitsSweptAt = now;
      for (const [k, v] of b) if (now > v.resetAt) b.delete(k);
    }
    if (b.size >= cfg.rateLimitIpCap) key = OVERFLOW;
  }
  const entry = b.get(key);
  if (!entry || now > entry.resetAt) {
    b.set(key, { count: 1, resetAt: now + cfg.rateLimitWindowMs });
    return true;
  }
  if (entry.count >= cfg.rateLimitMax) return false;
  entry.count++;
  return true;
}

/** Test seam: how many addresses are tracked. */
export function mailboxLimiterSize(): number {
  return buckets().size;
}
