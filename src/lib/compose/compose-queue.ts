// src/lib/compose/compose-queue.ts
// The queue of pending sign cards. Pure and immutable (every function returns a NEW state; nothing is mutated), so it is testable without a DOM.
// Rules (Flint/Archie lane:portal #994 Q6, spec v0.7): ONE card in front of Peter at a time; queue cap 5; expired requests are dropped; NEVER sign
// late (current() never returns an expired item, and the signer re-validates at approval with a fresh clock); a repeated nonce never makes a second card.
//
// WHAT BECOMES A CARD: a request the validator accepts ('sign'), and a request refused for HIDDEN CHARACTERS ('refusal', Hypatia §3: "Can't sign this
// message..." with Close only, never a way to sign). Every other refusal is DROPPED with its reason code returned to the caller for a counter: no copy
// exists for those, so nothing is shown (open item for Hypatia), and nothing is ever rendered from the request's own text.

import { validateComposeRequest, type Refusal, type ValidRequest } from './compose-request';

export const QUEUE_CAP = 5;
/** How many resolved/queued nonces we remember to stop a replay from making a second card. Bounded so a flood cannot grow state. */
export const SEEN_CAP = 64;
/** A refusal card has no expiry of its own; it is removed this long after it arrived if Peter never closed it. */
export const REFUSAL_TTL_MS = 10 * 60 * 1000;

export type QueueItem =
  | { kind: 'sign'; nonce: string; request: ValidRequest; raw: unknown; expiresAtMs: number; receivedAtMs: number }
  | { kind: 'refusal'; nonce: string | null; refusal: Refusal; receivedAtMs: number;
      /** The text of the ONE field the refusal names (<= the note cap), so the card can show it with [U+XXXX] markers; absent if the field is not a string. */
      shownText?: string };

export interface QueueState {
  readonly pending: readonly QueueItem[];
  /** Nonces already seen (queued OR resolved), newest last. */
  readonly seen: readonly string[];
}

export type EnqueueOutcome =
  | { outcome: 'queued'; kind: 'sign' | 'refusal' }
  | { outcome: 'duplicate' }
  | { outcome: 'full' }
  /** Refused for a reason that has no card: the code is for a counter/log, NEVER for display. */
  | { outcome: 'dropped'; code: Refusal['code'] };

export function emptyQueue(): QueueState {
  return { pending: [], seen: [] };
}

const NONCE = /^[0-9a-f]{32}$/;
const nonceOf = (raw: unknown): string | null => {
  if (typeof raw !== 'object' || raw === null) return null;
  const n = (raw as Record<string, unknown>).nonce;
  return typeof n === 'string' && NONCE.test(n) ? n : null;
};

function remember(seen: readonly string[], nonce: string | null): readonly string[] {
  if (nonce === null || seen.includes(nonce)) return seen;
  const next = [...seen, nonce];
  return next.length > SEEN_CAP ? next.slice(next.length - SEEN_CAP) : next;
}

/** Remove everything that has expired: sign items past their expires_at, refusal items older than the TTL. Pure. */
export function prune(state: QueueState, now: Date): QueueState {
  const t = now.getTime();
  const pending = state.pending.filter((it) => (it.kind === 'sign' ? it.expiresAtMs > t : t - it.receivedAtMs < REFUSAL_TTL_MS));
  return pending.length === state.pending.length ? state : { pending, seen: state.seen };
}

/**
 * Offer a request that already passed the PINNED-SENDER gate (compose-inbound + decideSender). Validates it with the caller's clock.
 * Returns the new state and what happened. A duplicate nonce, a full queue and an expired request never add a card.
 */
export function enqueue(state: QueueState, raw: unknown, now: Date): { state: QueueState; result: EnqueueOutcome } {
  const base = prune(state, now);
  const nonce = nonceOf(raw);
  if (nonce !== null && base.seen.includes(nonce)) return { state: base, result: { outcome: 'duplicate' } };

  const v = validateComposeRequest(raw, now);
  if (!v.ok) {
    if (v.refusal.code !== 'refused-characters') return { state: base, result: { outcome: 'dropped', code: v.refusal.code } };
    if (base.pending.length >= QUEUE_CAP) return { state: base, result: { outcome: 'full' } };
    const f = v.refusal.field;
    const t = f !== undefined && typeof raw === 'object' && raw !== null ? (raw as Record<string, unknown>)[f] : undefined;
    const item: QueueItem = { kind: 'refusal', nonce, refusal: v.refusal, receivedAtMs: now.getTime(), ...(typeof t === 'string' ? { shownText: t } : {}) };
    return { state: { pending: [...base.pending, item], seen: remember(base.seen, nonce) }, result: { outcome: 'queued', kind: 'refusal' } };
  }
  if (base.pending.length >= QUEUE_CAP) return { state: base, result: { outcome: 'full' } };
  const expiresAtMs = Date.parse(v.request.object.expires_at);
  const item: QueueItem = { kind: 'sign', nonce: v.request.object.nonce, request: v.request, raw, expiresAtMs, receivedAtMs: now.getTime() };
  return { state: { pending: [...base.pending, item], seen: remember(base.seen, item.nonce) }, result: { outcome: 'queued', kind: 'sign' } };
}

/** The ONE card to show now (oldest first), or null. Never returns an expired item. */
export function current(state: QueueState, now: Date): QueueItem | null {
  return prune(state, now).pending[0] ?? null;
}

/**
 * Peter finished with a card (signed it, declined it, or closed a refusal). Removes it. Its nonce is ALREADY in `seen` (enqueue remembers on the way in),
 * so a replay cannot re-raise it; resolve deliberately does not re-add it (a mutation check showed that re-adding was dead code: a pending item cannot be
 * evicted from the bounded seen-set, since FIFO + cap 5 means 64 newer items cannot pass an older one before it expires or is resolved).
 */
export function resolve(state: QueueState, item: QueueItem): QueueState {
  const idx = state.pending.indexOf(item);
  if (idx < 0) return state;
  return { pending: [...state.pending.slice(0, idx), ...state.pending.slice(idx + 1)], seen: state.seen };
}
