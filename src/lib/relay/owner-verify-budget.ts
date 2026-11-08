// src/lib/relay/owner-verify-budget.ts
// A GLOBAL budget for the expensive step of owner auth: the ML-DSA-87 verify (v2) and the key parse + signature verify (v1), each
// ~22 ms of CPU on the event loop that also serves the website. A fresh request costs the requester almost nothing to make: a valid
// Ed25519 signature over their own key plus a garbage pq_sig still forces a full ML-DSA verify. So the per-IP budget and the replay
// cache are not enough: N addresses at the per-IP ceiling can pin the core.
//
// This token bucket caps expensive verifies per second for the whole process: a LAST-RESORT shed sized from capacity (default
// 120/s, burst 240 ≈ 4 pool workers × ~40/s minus headroom), not a per-user quota: every owner verify spends it, legit ones too.
// The isolation that keeps svrnty.is responsive is the ML-DSA worker pool (mldsa-verify-pool.server.ts), which moves the ~20 ms
// verify off the event loop and sheds when its bounded queue is full. Past either limit a request gets a uniform 503 BEFORE the
// expensive step; a client treats it like any refused poll ("Could not check right now.") and its next tick signs fresh. Honest
// bound: enough addresses, each under its per-IP budget, can still use up total verify capacity; only edge rate limiting (in
// front of the box) closes that.
//
// Order inside a verifier: cheap checks → replay check → THIS → (v2: record nonce) → expensive verify. A replay never spends budget.

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

declare global {
  var __ownerVerifyBudget: Bucket | undefined;
}

/** Take one expensive-verify token, or throw OwnerVerifyBusyError (and count it). */
export function takeOwnerVerifyToken(now: number): void {
  const { ownerVerifyPerSec: rate, ownerVerifyBurst: burst } = mailboxConfig();
  const b = (globalThis.__ownerVerifyBudget ??= { tokens: burst, at: now });
  const elapsed = Math.max(0, now - b.at);
  b.tokens = Math.min(burst, b.tokens + (elapsed * rate) / 1000);
  b.at = now;
  if (b.tokens < 1) {
    logDeposit429('owner_verify_busy', now);
    throw new OwnerVerifyBusyError();
  }
  b.tokens -= 1;
}

/** The uniform shed response. Says nothing about any mailbox: decided before the expensive step, from a process-wide counter. */
export function ownerVerifyBusyResponse(): Response {
  return Response.json({ error: 'Relay busy.' }, { status: 503, headers: { 'retry-after': '1' } });
}

/** Test seam. */
export function resetOwnerVerifyBudget(): void {
  globalThis.__ownerVerifyBudget = undefined;
}
