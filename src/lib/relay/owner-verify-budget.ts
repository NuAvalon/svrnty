// src/lib/relay/owner-verify-budget.ts
// A GLOBAL budget for the expensive step of owner auth: the ML-DSA-87 verify (v2) and the key parse + signature verify (v1), each
// ~22 ms of CPU on the event loop that also serves the website. A fresh request costs the requester almost nothing to make: a valid
// Ed25519 signature over their own key plus a garbage pq_sig still forces a full ML-DSA verify. So the per-IP budget and the replay
// cache are not enough: N addresses at the per-IP ceiling can pin the core.
//
// This token bucket caps expensive verifies per second for the whole process. With the defaults (10/s sustained, burst 20) relay
// verification can use at most ~22% of the event loop, so svrnty.is stays responsive however hard the relay is hit. Past the cap a
// request is shed with a uniform 503 BEFORE the expensive step; a client treats it like any refused poll ("Could not check right
// now.") and its next tick signs fresh. Under a sustained flood the RELAY degrades, the site does not. Moving verification to a
// worker pool (more throughput, same isolation) is a follow-up.
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
