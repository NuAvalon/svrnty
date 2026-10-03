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
// holds — trusted ∩ open_visibility ∩ !blocked (the SAME set getKnownPeers reveals). So:
//   • ADD    on invariant-ENTRY (becomes trusted ∧ open_vis ∧ !blocked)
//   • DELETE on ANY invariant-EXIT — untrust, block, AND go-private (open_vis→false)
// The DELETE is the #111-satellite-completeness leg: client fix#2 only stops the SURVIVOR's client from
// revealing; without the satellite revoke, a blocked adversary's stale row keeps the mutual-gate open so
// THEIR client still discovers the survivor. One-sided DELETE suffices (Flint: /initiate needs BOTH rows,
// so dropping EITHER breaks discovery both directions). ADD+DELETE must ship together (ADD-alone would
// create the stale-row hole). Signed by the BOUND sig key (self-bind = the identity seed); the satellite
// re-verifies vs the stored bound sig_pubkey + requires a bound identity. Fail-closed on any miss.

import { toBase64 } from '@/lib/crypto/kdf';
import { signAllowedAdd, signAllowedRemove } from '@/lib/identity/raw-sign';

/** Same-origin proxy base (#189). POST {base}/{owner} add · DELETE {base}/{owner}/{sender} revoke. */
const ALLOWED_BASE = '/api/satellite/allowed';

/** The client's consent state for one peer — mirrors the getKnownPeers reveal invariant. */
export interface PeerConsent {
  trusted: boolean;
  openVisibility: boolean;
  blocked: boolean;
}

/** allowed_senders row should exist IFF the full consent invariant holds. */
export function allowedRowShouldExist(c: PeerConsent): boolean {
  return c.trusted === true && c.openVisibility === true && c.blocked !== true;
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

/**
 * Reconcile the satellite allowed_senders row to the client consent invariant, BY CONSTRUCTION:
 * ADD when (trusted ∧ open_vis ∧ !blocked), DELETE otherwise. Call from every handler that can change
 * the invariant (trust-toggle, block-toggle, go-private/open_visibility-toggle) with the POST-change
 * consent — the row then mirrors the reveal set regardless of WHICH axis moved. Both ops are satellite-
 * idempotent, so a no-op transition is harmless. Returns the action taken + its ok (fail-closed).
 */
export async function reconcileAllowedForPeer(
  args: AllowedOpArgs & { consent: PeerConsent },
): Promise<{ action: 'add' | 'delete'; ok: boolean }> {
  if (allowedRowShouldExist(args.consent)) {
    return { action: 'add', ok: await addAllowedSender(args) };
  }
  return { action: 'delete', ok: await removeAllowedSender(args) };
}
