// src/lib/relay/mailbox-store.ts
// Return-channel mailbox: a persistent, recipient-keyed DELTA on the single-use dead-drop relay.
// The relay gains a mailbox + poll + ack WITHOUT becoming smart about the social graph
// (joint design §1/§5, Peter-acked #116192). It stores ONLY opaque blobs + relay-assigned ids —
// NO sender field, no edge-list (custody I-1). Sender identity + sender_signature live INSIDE the
// E2E-encrypted blob and are verified by the RECIPIENT on consume, never by the relay (§4).
//
// In-memory, per-process (single-node), same posture as the existing relay store (Redis later).

import { mailboxConfig } from './mailbox-config';

export interface Envelope {
  /** Relay-assigned unique id — the handle for ack-delete + client-side dedup. */
  envelope_id: string;
  /** Opaque payload (≤ maxPayloadBytes). The relay never reads or interprets this. */
  blob: string;
  deposited_at: number;
  expires_at: number;
}

declare global {
  // eslint-disable-next-line no-var
  var __mailboxStore: Map<string, Envelope[]> | undefined;
}

export function getMailboxStore(): Map<string, Envelope[]> {
  if (!globalThis.__mailboxStore) globalThis.__mailboxStore = new Map();
  return globalThis.__mailboxStore;
}

/** Backstop TTL GC (ack-delete is primary): drop expired envelopes. Swept lazily on every access. */
function sweepExpired(list: Envelope[], now: number): Envelope[] {
  return list.filter((e) => e.expires_at > now);
}

export type DepositResult = { ok: true } | { ok: false; status: 400 | 413 | 429 };

/**
 * Deposit one opaque envelope into a mailbox (lazy-create).
 *
 * The OUTCOME is uniform w.r.t. the recipient's mailbox state (I-4 deposit-side, §4): a depositor
 * cannot probe whether R's mailbox exists / is empty / has mail. The ONLY mailbox-state-dependent
 * signal is the at-cap 429 — a Peter-RATIFIED bounded I-4 residual (#116282): it leaks only the
 * coarse "at-capacity" fact, never who/read-state, and probing it requires filling a stranger's
 * mailbox to cap (itself rate-limited + costly). Named closure = edge-scoped deposit-tokens (Tier-2).
 *
 * (400/413 are request-shape errors — about the deposit itself, NOT R's mailbox state.)
 */
export function depositEnvelope(mailboxId: string, blob: string, now: number): DepositResult {
  const cfg = mailboxConfig();
  if (!mailboxId || typeof mailboxId !== 'string') return { ok: false, status: 400 };
  if (!blob || typeof blob !== 'string') return { ok: false, status: 400 };
  if (blob.length > cfg.maxPayloadBytes) return { ok: false, status: 413 };

  // §5.1 LAUNCH seam (config-driven, NOT built for 9/10): under the svrnty.is nursery profile
  // (cfg.inviteRequired), mailbox CREATION is gated behind an explicit owner-claim carrying an
  // invite_token+chain. A deposit to an as-yet-UNCLAIMED mailbox is still ACCEPTED UNIFORMLY —
  // buffered + TTL'd + unreadable until claimed — and is NEVER rejected (Archie #116327): rejecting
  // would reintroduce exactly the occupancy-oracle / silent-drop that the uniform-ack design closes.
  // That claim registry lands with the invite machinery (Archie #116271); the demo/family profile
  // (inviteRequired=false, default) lazy-creates on first deposit below. Referenced here so the
  // policy branch reads config, not a literal — the image never forks (Invariant 8).
  void cfg.inviteRequired;

  const store = getMailboxStore();
  const list = sweepExpired(store.get(mailboxId) ?? [], now); // lazy GC on write
  if (list.length >= cfg.cap) {
    store.set(mailboxId, list); // persist the GC even on reject
    return { ok: false, status: 429 };
  }

  const envelope: Envelope = {
    envelope_id: crypto.randomUUID(),
    blob,
    deposited_at: now,
    expires_at: now + cfg.envelopeTtlMs,
  };
  list.push(envelope);
  store.set(mailboxId, list); // lazy-create
  return { ok: true };
}

/**
 * Non-destructive poll (owner-only — the route enforces owner-auth BEFORE calling this).
 * Returns the pending envelopes as `{envelope_id, blob}`. A never-used mailbox reads as empty (`[]`),
 * indistinguishable to the owner from a drained one — and never reachable by a non-owner at all.
 */
export function pollMailbox(mailboxId: string, now: number): Array<{ envelope_id: string; blob: string }> {
  const store = getMailboxStore();
  const list = sweepExpired(store.get(mailboxId) ?? [], now);
  store.set(mailboxId, list); // persist GC
  return list.map((e) => ({ envelope_id: e.envelope_id, blob: e.blob }));
}

/** Ack-delete (owner-only). Removes the listed ids from the mailbox. Returns the count removed. */
export function ackDelete(mailboxId: string, envelopeIds: string[], now: number): number {
  const store = getMailboxStore();
  const list = sweepExpired(store.get(mailboxId) ?? [], now);
  const drop = new Set(envelopeIds);
  const kept = list.filter((e) => !drop.has(e.envelope_id));
  store.set(mailboxId, kept);
  return list.length - kept.length;
}
