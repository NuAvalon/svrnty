// src/lib/sync/relay-tiers.ts
// Failover T2 phase 2a (Archie #2633, Flint's failover design v0.2): a sender or poller may know more than one relay. PURE helpers, no I/O.
//
// SEND rule: a note is sealed ONCE and the SAME blob is re-POSTed to the next relay. A re-seal would take another ratchet step (the ratchet frame
// lives inside the signed wire) and burn an index, so failover is a re-POST, never a re-send. We move on only when the relay itself, not the blob,
// is the problem: 5xx, 429 (at-cap), 408, or a network failure/timeout. Any other refusal (400 malformed, 413 too big, 401/403) would be the same
// on the next relay, so it ends the walk. An UNCONFIRMED outcome (5xx/timeout: the relay may have stored it) followed by a success elsewhere can
// store the note twice by design; receivers dedupe on note_id (the #720 r2 redelivery branch).

import type { ConsumeSummary } from '@/lib/sync/consume-mailbox';

/** Most relays one agent will talk to: a typo must not become a fan-out. */
export const MAX_RELAYS = 4;

/**
 * Is this URL hostname on a private network? Loopback (127/8, ::1, localhost), RFC1918 (10/8, 172.16/12, 192.168/16), link-local (169.254/16,
 * fe80::/10), IPv6 unique-local (fc00::/7), `*.local`, or a SINGLE-LABEL name (no dot: resolved by the local resolver, e.g. a docker service
 * name; it cannot be a public DNS name). Anything else, including every dotted public name, is public. `new URL` has already normalised
 * decimal/hex/octal IPv4 spellings to dotted form, so those cannot slip past.
 */
export function isPrivateHost(hostname: string): boolean {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
  }
  if (h.includes(':')) return h === '::1' || /^fe[89ab][0-9a-f]:/.test(h) || /^f[cd][0-9a-f]{2}:/.test(h);
  return !h.includes('.') && h.length > 0;
}

/**
 * The ordered, de-duplicated relay bases. `SVRNTY_RELAYS` (comma list) wins; `SVRNTY_RELAY` (one) is the old form and stays valid.
 * THROWS on an entry that is not an http(s) URL or on more than MAX_RELAYS: a misconfigured failover must be loud, not silently single-relay.
 */
export function parseRelayList(env: { SVRNTY_RELAYS?: string; SVRNTY_RELAY?: string }, fallback: string): string[] {
  const raw = (env.SVRNTY_RELAYS ?? '').trim() ? env.SVRNTY_RELAYS! : env.SVRNTY_RELAY ?? fallback;
  const out: string[] = [];
  for (const part of raw.split(',')) {
    const s = part.trim().replace(/\/+$/, '');
    if (!s) continue;
    let u: URL;
    try {
      u = new URL(s);
    } catch {
      throw new Error(`relay list: not a URL: ${JSON.stringify(s.slice(0, 60))}`);
    }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error(`relay list: only http(s) relays: ${JSON.stringify(s.slice(0, 60))}`);
    // Plain http carries the signed owner-auth header and the poll in the clear: allowed only on a private network (Flint #2650 (a)).
    if (u.protocol === 'http:' && !isPrivateHost(u.hostname)) throw new Error(`relay list: plain http is only for a private host (loopback, 10/8, 172.16/12, 192.168/16, link-local, *.local, a single-label name); use https: ${JSON.stringify(s.slice(0, 60))}`);
    if (!out.includes(s)) out.push(s);
  }
  if (out.length === 0) throw new Error('relay list: no relay configured');
  if (out.length > MAX_RELAYS) throw new Error(`relay list: at most ${MAX_RELAYS} relays`);
  return out;
}

/** Should the next relay be tried after this status? (The relay is the problem, not the blob.) */
export function failoverWorthy(status: number): boolean {
  return status >= 500 || status === 429 || status === 408;
}

export interface DepositOutcome {
  deposited: boolean;
  /** Index (in the list given) of the relay that stored it; null if none did. */
  tier: number | null;
  /** How many relays were contacted. */
  tried: number;
  /** True if any attempt ended UNCONFIRMED (5xx/timeout/network): that relay may still hold the note, so never say "not sent". */
  unconfirmed: boolean;
}

/**
 * Walk the relays in order with one sealed blob. `post(relayBase)` does the POST and resolves with the HTTP response (or throws).
 * Resolves with the outcome. If EVERY relay threw, rethrows the first error (same as a single-relay send did).
 */
export async function depositWithFailover(
  relays: readonly string[],
  post: (relayBase: string) => Promise<{ ok: boolean; status: number }>,
): Promise<DepositOutcome> {
  let tried = 0;
  let unconfirmed = false;
  let threw = 0;
  let firstError: unknown;
  for (let i = 0; i < relays.length; i++) {
    tried++;
    let res: { ok: boolean; status: number };
    try {
      res = await post(relays[i]);
    } catch (err) {
      threw++;
      unconfirmed = true;
      if (firstError === undefined) firstError = err;
      continue;
    }
    if (res.ok) return { deposited: true, tier: i, tried, unconfirmed };
    if (res.status >= 500) unconfirmed = true;
    if (!failoverWorthy(res.status)) return { deposited: false, tier: null, tried, unconfirmed };
  }
  if (threw === tried && firstError !== undefined) throw firstError;
  return { deposited: false, tier: null, tried, unconfirmed };
}

/** What one relay's poll came to: its summary, or that it failed outright (threw). Counts and status only: never a URL, never an id. */
export type RelayPoll = { summary: ConsumeSummary } | { failed: true };

/**
 * One summary for a multi-relay poll. Counters are summed; `lost` maps are summed key by key; `rejected` keeps the FIRST refusal status so a
 * refused relay is never hidden by a healthy one (a rejected poll is not an empty mailbox). `relaysFailed` / `relaysRejected` say how many relays
 * did not give a clean answer; the "Caught up" logic must treat any non-zero as not caught up.
 */
export function mergeRelaySummaries(polls: readonly RelayPoll[]): ConsumeSummary & { relays: number; relaysFailed: number; relaysRejected: number } {
  const out: ConsumeSummary & { relays: number; relaysFailed: number; relaysRejected: number } = {
    polled: 0, applied: 0, ignited: 0, notes: 0, delivered: 0, dropped: 0, held: 0, deadLettered: 0, unrecorded: 0,
    lost: {}, opened_hybrid: 0, opened_classical: 0, released: 0, acked: 0,
    relays: polls.length, relaysFailed: 0, relaysRejected: 0,
  };
  for (const p of polls) {
    if ('failed' in p) {
      out.relaysFailed++;
      continue;
    }
    const x = p.summary;
    for (const k of ['polled', 'applied', 'ignited', 'notes', 'delivered', 'dropped', 'held', 'deadLettered', 'unrecorded', 'opened_hybrid', 'opened_classical', 'released', 'acked'] as const) {
      out[k] += x[k] ?? 0;
    }
    for (const [reason, n] of Object.entries(x.lost ?? {})) {
      const r = reason as keyof ConsumeSummary['lost'];
      out.lost[r] = (out.lost[r] ?? 0) + (n ?? 0);
    }
    if (x.rejected !== undefined) {
      out.relaysRejected++;
      if (out.rejected === undefined) out.rejected = x.rejected;
    }
  }
  return out;
}
