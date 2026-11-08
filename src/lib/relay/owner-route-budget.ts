// src/lib/relay/owner-route-budget.ts
// Per-IP limiter for the OWNER routes (queue / ack / claim). It is the FIRST thing those routes do: before the URL, the body or
// any auth header is parsed, so a refused request costs a Map lookup and never reaches a verifier (the ~22 ms ML-DSA-87 step).
// One budget per IP across all three routes. Its own budget, not the deposit one (mailbox-config.ts: ownerRateLimitMax).
//
// The refusal is about the REQUESTER, never about a mailbox: it is decided before the mailbox id is read, so it cannot depend on
// whether that mailbox exists or holds anything (I-4).
//
// Bounded memory: at ownerRateLimitIpCap tracked IPs, expired buckets are swept; if still full, every new IP shares ONE overflow
// bucket (rate-limited together) instead of growing the map. Per-process, in-memory (single node), like the deposit limiter.

import { mailboxConfig } from './mailbox-config';
import { getClientIP } from './mailbox-rate-limit';

interface Bucket { count: number; resetAt: number }
const OVERFLOW = '\u0000overflow';

declare global {
  var __ownerRouteRateLimits: Map<string, Bucket> | undefined;
}

function buckets(): Map<string, Bucket> {
  if (!globalThis.__ownerRouteRateLimits) globalThis.__ownerRouteRateLimits = new Map();
  return globalThis.__ownerRouteRateLimits;
}

function sweep(b: Map<string, Bucket>, now: number): void {
  for (const [k, v] of b) if (now > v.resetAt) b.delete(k);
}

/** True if this owner-route request may proceed; false if the IP (or the overflow bucket) is over its ceiling for the window. */
export function checkOwnerRouteBudget(ip: string, now: number): boolean {
  const cfg = mailboxConfig();
  const b = buckets();
  let key = ip;
  if (!b.has(key) && b.size >= cfg.ownerRateLimitIpCap) {
    sweep(b, now);
    if (b.size >= cfg.ownerRateLimitIpCap) key = OVERFLOW;
  }
  const entry = b.get(key);
  if (!entry || now > entry.resetAt) {
    b.set(key, { count: 1, resetAt: now + cfg.ownerRateLimitWindowMs });
    return true;
  }
  if (entry.count >= cfg.ownerRateLimitMax) return false;
  entry.count++;
  return true;
}

/** Test seam: forget every bucket. */
export function resetOwnerRouteBudgets(): void {
  globalThis.__ownerRouteRateLimits = new Map();
}

/**
 * The owner routes' first line: `const gated = ownerRouteGate(request); if (gated) return gated;`. Reads only the client-IP header,
 * so it runs before the URL, the body or any auth header is parsed. Returns the uniform 429, or null to proceed. The 429 body is the
 * deposit route's ('Rate limit exceeded.'), so one client-side handling covers both.
 */
export function ownerRouteGate(request: Request, now: number = Date.now()): Response | null {
  if (checkOwnerRouteBudget(getClientIP(request), now)) return null;
  return Response.json({ error: 'Rate limit exceeded.' }, { status: 429 });
}
