// src/lib/sync/allowed-sync.ts
// Client half of the satellite allowed_senders mutual-connection wiring (AND-gate b, flip-blocker #572).
//
// WHY (grounded): PSI /initiate's mutual-gate reads the satellite allowed_senders table (satellite.py:3557
// "both parties in each other's allowed_senders"). The old connect path (/trust/commit) was ORPHANED by
// the trust_commitments->allowed_senders refactor (table migrated-once-at-boot then DROPped; no live
// handler), so real users had NO path to populate allowed_senders and discovery was unsatisfiable. This
// module POSTs the signed add / DELETEs the signed revoke through the #189 proxy (/api/satellite/allowed).
//
// THE INVARIANT (Archie/Flint): the allowed_senders row exists IFF the client's own consent invariant
// holds — open_visibility ∩ !blocked ∩ !per_contact_private (the KNOWN reveal getKnownPeers surfaces; trusted⊆known v1, mutuality via the bidirectional gate). So:
//   • ADD    on invariant-ENTRY (becomes open_vis ∧ !blocked ∧ !per_contact_private)
//   • DELETE on ANY invariant-EXIT — block, go-private (open_vis→false), per_contact_private, remove
//     (untrust is NO LONGER a known-exit → it exits the TRUSTED layer only, piece-2)
// The DELETE is the #111-satellite-completeness leg: client fix#2 only stops the SURVIVOR's client from
// revealing; without the satellite revoke, a blocked adversary's stale row keeps the mutual-gate open so
// THEIR client still discovers the survivor. One-sided DELETE suffices (Flint: /initiate needs BOTH rows,
// so dropping EITHER breaks discovery both directions). ADD+DELETE must ship together (ADD-alone would
// create the stale-row hole). Signed by the BOUND sig key (self-bind = the identity seed); the satellite
// re-verifies vs the stored bound sig_pubkey + requires a bound identity. Fail-closed on any miss.

import { toBase64 } from '@/lib/crypto/kdf';
import { signAllowedAdd, signAllowedRemove, signPsiAuth } from '@/lib/identity/raw-sign';

/** Same-origin proxy base (#189). POST {base}/{owner} add · DELETE {base}/{owner}/{sender} revoke. */
const ALLOWED_BASE = '/api/satellite/allowed';

/** The client's consent state for one peer — mirrors the getKnownPeers reveal invariant. */
export interface PeerConsent {
  trusted: boolean;
  openVisibility: boolean;
  blocked: boolean;
  /** piece-1: per-contact-private AND-term. true ⇒ excluded from the reveal set (fail-closed). REQUIRED. */
  perContactPrivate: boolean;
}

/** allowed_senders row should exist IFF the full consent invariant holds. */
export function allowedRowShouldExist(c: PeerConsent): boolean {
  // piece-1: KNOWN reveal = open_vis ∩ !blocked ∩ !per_contact_private. DROP trusted (trusted⊆known v1;
  // mutuality enforced by the bidirectional gate, not a FE term). `!c.perContactPrivate` = truthy-exclusion
  // (fail-closed: a malformed truthy pcp EXCLUDES — NOT `!== true`, which would fail-OPEN).
  return c.openVisibility === true && c.blocked !== true && !c.perContactPrivate;
}

interface AllowedOpArgs {
  ownerFp: string;
  senderFp: string;
  /** The owner's bound sig seed (self-bind = identity seed) — in-memory only, never persisted. */
  seed: Uint8Array;
  fetchImpl?: typeof fetch;
  /** Override the proxy base (tests). */
  base?: string;
  /** Override the unix clock (tests). */
  nowUnixSeconds?: number;
}

function nowUnix(args: AllowedOpArgs): number {
  return args.nowUnixSeconds ?? Math.floor(Date.now() / 1000);
}

/** wire format the satellite/proxy expect: `{unix}:{base64(sig)}` (satellite AllowedSenderRequest). */
function wire(sig: Uint8Array, unix: number): string {
  return `${unix}:${toBase64(sig)}`;
}

/**
 * ADD the peer to the owner's satellite allowed_senders (POST /api/satellite/allowed/{owner}).
 * Signed svrnty-allowed-add:{owner}:{sender}:{unix}. Returns true on 2xx; false (fail-closed) on any miss.
 * Idempotent at the satellite (re-add of an existing pair is a no-op 2xx).
 */
export async function addAllowedSender(args: AllowedOpArgs): Promise<boolean> {
  const f = args.fetchImpl ?? fetch;
  const base = args.base ?? ALLOWED_BASE;
  const unix = nowUnix(args);
  try {
    const res = await f(`${base}/${encodeURIComponent(args.ownerFp)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        sender_fingerprint: args.senderFp,
        signature: wire(signAllowedAdd(args.seed, args.ownerFp, args.senderFp, unix), unix),
      }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * DELETE the peer from the owner's satellite allowed_senders (DELETE /api/satellite/allowed/{owner}/{sender}).
 * Signed svrnty-allowed-remove:{owner}:{sender}:{unix} in the X-Signature header. The #111 satellite revoke.
 * Returns true on 2xx; false on any miss. Safe to call when no row exists (satellite no-op).
 */
export async function removeAllowedSender(args: AllowedOpArgs): Promise<boolean> {
  const f = args.fetchImpl ?? fetch;
  const base = args.base ?? ALLOWED_BASE;
  const unix = nowUnix(args);
  try {
    const res = await f(
      `${base}/${encodeURIComponent(args.ownerFp)}/${encodeURIComponent(args.senderFp)}`,
      {
        method: 'DELETE',
        headers: {
          'X-Signature': wire(signAllowedRemove(args.seed, args.ownerFp, args.senderFp, unix), unix),
        },
      },
    );
    return res.ok;
  } catch {
    return false;
  }
}

/** What one consent change asks of the satellite's list: put the peer on it, take the peer off it, or nothing at all. */
export type AllowedRowDecision = 'add' | 'delete' | 'none';

/**
 * THE ONE RULE (#959). A DELETE is sent only for a peer that HAS a row at the satellite (`rowAtRelay`: the relay's own list names it, see listAllowedSenders) and whose
 * consent no longer allows one. A peer that never had a row sends NOTHING: a DELETE for it tells the satellite's operator that fingerprint and revokes nothing. The answer comes
 * from the RELAY'S STATE, not from the consent before the change or any local record, so a DELETE that never went out (the app closed, the request failed) is still owed at the next change
 * or tick, and so is a row for a contact that was removed or blocked long ago.
 * ADD is unchanged: whenever the consent allows a row (idempotent at the satellite).
 */
export function allowedRowDecision(rowAtRelay: boolean, after: PeerConsent): AllowedRowDecision {
  if (allowedRowShouldExist(after)) return 'add';
  if (rowAtRelay) return 'delete';
  return 'none';
}

/** What the relay's own list said: the list, "the relay keeps no list" (410), or nothing usable. */
export type AllowedListResult = { status: 'ok'; fps: string[] } | { status: 'gone' } | { status: 'unknown' };

/** a bound so a hostile or damaged answer cannot make the drain do unbounded work */
export const MAX_LISTED = 50_000;
/** a fingerprint as the satellite and the rest of the app know it: 40 or 64 hex digits (the shape dead-letter.ts already uses), in either case */
const FP_SHAPE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;

/**
 * The satellite's own list of who it allows for this owner (GET /api/satellite/allowed/{owner}; Ed25519 psi-auth tag in X-Signature, the same wire as the DELETE; the relay returns
 * fingerprints only). It is the truth about which rows exist, so what is OWED a DELETE is this list minus the peers whose consent allows a row now.
 *
 * Retire this with #540; the revoke check moves client-side with it.
 *
 * The satellite is NOT trusted, and this list drives SIGNED DELETEs: every entry must be a fingerprint (40 or 64 hex digits), and ONE bad entry makes the WHOLE list 'unknown', never a partial use.
 * A FAILURE IS NEVER AN EMPTY LIST: a 403, a 5xx, a network error, a body that is not a list of fingerprints, all answer 'unknown', which the caller treats as "try again next tick" and
 * which touches no state. 410 is the ONE exception ('gone': once the relay stops keeping the list there is nothing owed). A real empty list is { status: 'ok', fps: [] }.
 */
export async function listAllowedSenders(args: AllowedOpArgs): Promise<AllowedListResult> {
  const f = args.fetchImpl ?? fetch;
  const base = args.base ?? ALLOWED_BASE;
  const unix = nowUnix(args);
  try {
    const res = await f(`${base}/${encodeURIComponent(args.ownerFp)}`, {
      method: 'GET',
      cache: 'no-store',                                   // a failure must not be answered from any cache as a stale 200, whatever a deploy's defaults or headers say
      headers: { 'X-Signature': wire(signPsiAuth(args.seed, args.ownerFp, unix), unix) },
    });
    if (res.status === 410) return { status: 'gone' };
    if (!res.ok) return { status: 'unknown' };
    const body: unknown = await res.json();
    const list = body && typeof body === 'object' ? (body as { allowed?: unknown }).allowed : undefined;
    if (!Array.isArray(list) || list.length > MAX_LISTED || !list.every((x) => typeof x === 'string' && FP_SHAPE.test(x))) return { status: 'unknown' };
    return { status: 'ok', fps: list as string[] };
  } catch (err) {
    // unknown (retry next tick), but NEVER silently: a bug in this request must not look like a quiet relay
    if (typeof console !== 'undefined') console.warn('[psi] allowed list request failed (will retry):', err);
    return { status: 'unknown' };
  }
}

/**
 * Reconcile the satellite allowed_senders row to the client consent invariant, BY CONSTRUCTION, from the consent AFTER the change and whether the peer may have a row (see
 * allowedRowDecision). Call from every handler that can change the invariant (trust-toggle, block-toggle, go-private/open_visibility-toggle, import-merge, contact removal) with
 * the POST-change consent — the row then mirrors the reveal set regardless of WHICH axis moved. This is the ONLY function that reaches removeAllowedSender (pinned by a source
 * test). Returns the action taken + its ok (fail-closed), or { action: 'none' } when nothing was to be sent.
 */
export async function reconcileAllowedForPeer(
  args: AllowedOpArgs & { consent: PeerConsent; rowAtRelay: boolean },
): Promise<{ action: 'add' | 'delete'; ok: boolean } | { action: 'none' }> {
  switch (allowedRowDecision(args.rowAtRelay, args.consent)) {
    case 'add': return { action: 'add', ok: await addAllowedSender(args) };
    case 'delete': return { action: 'delete', ok: await removeAllowedSender(args) };
    default: return { action: 'none' };
  }
}
