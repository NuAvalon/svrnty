// src/lib/relay/mailbox-rate-limit.ts
// Per-IP deposit rate limit for the return-channel mailbox. Independent of the single-use relay's
// limiter (different endpoint, different budget). Config-driven (joint §5.1).
//
// NOTE: like the relay store, this is per-process in-memory (single-node). Horizontal scale needs
// shared state (Redis) — deferred, same posture as the mailbox store.

import { mailboxConfig } from './mailbox-config';

interface Bucket {
  count: number;
  resetAt: number;
}

declare global {
  // eslint-disable-next-line no-var
  var __mailboxRateLimits: Map<string, Bucket> | undefined;
}

function buckets(): Map<string, Bucket> {
  if (!globalThis.__mailboxRateLimits) globalThis.__mailboxRateLimits = new Map();
  return globalThis.__mailboxRateLimits;
}

export function getClientIP(request: Request): string {
  const fwd = request.headers.get('x-forwarded-for');
  if (fwd) return fwd.split(',')[0].trim();
  return request.headers.get('x-real-ip') ?? 'unknown';
}

/** True if the deposit is allowed; false if the IP is over its per-window ceiling. */
export function checkMailboxRateLimit(ip: string, now: number): boolean {
  const cfg = mailboxConfig();
  const b = buckets();
  const entry = b.get(ip);
  if (!entry || now > entry.resetAt) {
    b.set(ip, { count: 1, resetAt: now + cfg.rateLimitWindowMs });
    return true;
  }
  if (entry.count >= cfg.rateLimitMax) return false;
  entry.count++;
  return true;
}
