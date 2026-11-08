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
import { logDeposit429 } from './deposit-429-log';

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

/**
 * The budget key for an address: an IPv4 address as is; an IPv6 address by its /64 (one host or subscriber usually owns a whole /64,
 * so per-address keying would give it unlimited budget and let it fill the map); an IPv4-mapped IPv6 address as its IPv4. Anything
 * that doesn't parse is keyed as given.
 */
export function budgetKeyOf(ip: string): string {
  let s = ip.trim().toLowerCase();
  if (s.startsWith('[') && s.includes(']')) s = s.slice(1, s.indexOf(']'));
  if (!s.includes(':')) return s;
  s = s.split('%')[0]; // drop a zone id
  const mapped = /^(?:::|(?:0{1,4}:){5})(?:0{1,4}:)?ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (mapped) return mapped[1];
  const halves = s.split('::');
  if (halves.length > 2) return s;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const width = (parts: string[]) => parts.reduce((w, p) => w + (p.includes('.') ? 2 : 1), 0);
  const fill = halves.length === 2 ? 8 - width(head) - width(tail) : 0;
  if (fill < 0 || (halves.length === 1 && width(head) !== 8)) return s;
  const first4 = [...head, ...Array<string>(fill).fill('0'), ...tail].slice(0, 4);
  if (first4.length < 4 || !first4.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return s;
  return first4.map((g) => parseInt(g, 16).toString(16)).join(':') + '::/64';
}

/** True if this owner-route request may proceed; false if the address (its /64 for IPv6) or the overflow bucket is over its ceiling. */
export function checkOwnerRouteBudget(ip: string, now: number): boolean {
  const cfg = mailboxConfig();
  const b = buckets();
  let key = budgetKeyOf(ip);
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
  logDeposit429('owner_rate_limit', now); // at most one line per reason per 60 s, reason + counts only (no IP, no mailbox)
  return Response.json({ error: 'Rate limit exceeded.' }, { status: 429 });
}
