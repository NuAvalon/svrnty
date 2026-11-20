// src/lib/sync/reconcile-allowed-hook.ts
// FE integration hook (#572 part 2): reconcile the satellite allowed_senders row to the owner's
// POST-change consent invariant whenever a trust / block / open-visibility handler fires.
//
// WHY A SEPARATE HOOK (part 1 = allowed-sync.ts is the signed ADD/DELETE + reconcile-by-invariant
// crypto core): this wrapper adds the three FE concerns that must NOT live inline in the UI handlers —
//   1. GATE    — runs only while isPSIDiscoveryLive() is true (claim-gates.ts; true in this codebase since 2026-10-04, on
//                dev and main; ce8420b). If the gate is ever false again there is no /allowed traffic, by construction.
//   2. SEED    — unlock the owner identity (loadKey -> readPrivateKey -> decryptKey -> extractRawSign)
//                to recover the BOUND Ed25519 sign seed the satellite verifies /allowed against. The
//                seed is in-memory only and is a reference INTO the decrypted key packet — never persist
//                it and never zero it (zeroing would corrupt the cached identity key).
//   3. FAIL-SOFT — a reconcile miss (identity locked, satellite down, network error, decrypt failure)
//                must NEVER break the local-first UX. The whole body is wrapped; this function never
//                throws and never rejects.
//
// The 5 invariant-change handler sites (ContactManagement trust/block/share-settings + app/page.tsx
// TrustMap trust/block) call this fire-and-forget (void) AFTER the local updateContact persists, with
// the POST-change consent — so the satellite row mirrors the FINAL reveal set (trusted ∩ open_vis ∩
// !blocked) regardless of which axis moved. The DELETE leg is the #111-satellite-completeness fix: the
// client-side reveal filter (fix#2) only stops the SURVIVOR's client; without the satellite revoke a
// blocked adversary's stale row keeps the mutual-gate open so THEIR client still discovers the survivor.

import { decryptKey, readPrivateKey } from 'openpgp';
import { loadKey as defaultLoadKey } from '@/lib/identity/client-store';
import { extractRawSign } from '@/lib/identity/raw-sign';
import { isPSIDiscoveryLive } from '@/lib/claim-gates';
import { allowedRowShouldExist, listAllowedSenders, reconcileAllowedForPeer, type PeerConsent } from './allowed-sync';
import { requestDrain, type AllowedRevokeDeps, type AllowedRevokeIo } from './allowed-revoke';
import { realAllowedRevokeDeps } from './allowed-revoke-real';

export interface ReconcileAllowedHookArgs {
  /** Owner's own identity fingerprint (the allowed_senders table owner). */
  ownerFp: string | null | undefined;
  /** The peer/contact fingerprint (the allowed sender). Empty/null → no-op (not a svrnty-network peer). */
  senderFp: string | null | undefined;
  /** The owner's consent toward this peer AFTER the handler's state change. */
  consent: PeerConsent;
  // ── test injectables ──
  loadKeyImpl?: typeof defaultLoadKey;
  fetchImpl?: typeof fetch;
  /** Gate override (default isPSIDiscoveryLive). */
  gate?: () => boolean;
  /** The owner's book and the drain's clock/pacing (default: the real ones). Tests inject an in-memory book so no store is touched. */
  allowedRevoke?: AllowedRevokeDeps;
}

export type ReconcileAllowedResult =
  | { action: 'add' | 'delete'; ok: boolean }
  | { skipped: 'dark' | 'no-peer' | 'locked' | 'error' | 'never-allowed' };

/**
 * The owner's bound Ed25519 sign seed (the one the satellite verifies /allowed against), or null if the identity is locked. In-memory only: it is a reference INTO the decrypted
 * key packet, so never persist it and never zero it (zeroing would corrupt the cached identity key).
 */
async function ownerSeed(ownerFp: string, loadKeyImpl?: typeof defaultLoadKey): Promise<Uint8Array | null> {
  const key = await (loadKeyImpl ?? defaultLoadKey)(ownerFp);
  if (!key?.privateKey || !key.passphrase) return null;
  const locked = await readPrivateKey({ armoredKey: key.privateKey });
  const decrypted = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: key.passphrase });
  return extractRawSign(decrypted).seed;
}

/** The consent of a contact that is gone: nothing is open, so no row should exist. */
const GONE: PeerConsent = { trusted: false, openVisibility: false, blocked: false, perContactPrivate: false };

/** The drain's I/O: the relay's own list, and the signed DELETE through reconcileAllowedForPeer (the ONLY path to removeAllowedSender): true only for a confirmed one. */
function revokeIo(ownerFp: string, seed: Uint8Array, fetchImpl?: typeof fetch): AllowedRevokeIo {
  return {
    list: () => listAllowedSenders({ ownerFp, senderFp: '', seed, fetchImpl }),
    deleteRow: async (senderFp) => {
      const x = await reconcileAllowedForPeer({ ownerFp, senderFp, seed, consent: GONE, rowAtRelay: true, fetchImpl });
      return x.action === 'delete' && x.ok;
    },
  };
}

/**
 * Reconcile the satellite allowed_senders row for one peer to the owner's POST-change consent (#959). A consent that ALLOWS a row is an ADD (idempotent). One that does not asks the
 * RELAY'S OWN LIST whether this peer has a row, and sends a DELETE only if it does: a peer that never had a row sends nothing, and a DELETE that never went out earlier (or any other
 * owed one) is sent now, because every call also pays down everything the relay still lists that is no longer allowed. The consent this call was handed is authoritative for its own peer.
 * GATE -> seed -> reconcile, all fail-soft.
 */
export async function reconcileAllowedOnConsentChange(
  args: ReconcileAllowedHookArgs,
): Promise<ReconcileAllowedResult> {
  const gate = args.gate ?? isPSIDiscoveryLive;
  try {
    if (!gate()) return { skipped: 'dark' };                       // pre-flip: no /allowed traffic
    if (!args.ownerFp || !args.senderFp) return { skipped: 'no-peer' };
    const ownerFp = args.ownerFp, senderFp = args.senderFp;
    const seed = await ownerSeed(ownerFp, args.loadKeyImpl);
    if (!seed) return { skipped: 'locked' };                        // identity locked → best-effort skip
    const deps = args.allowedRevoke ?? realAllowedRevokeDeps();
    const io = revokeIo(ownerFp, seed, args.fetchImpl);
    const own = new Map([[senderFp, args.consent]]);

    if (allowedRowShouldExist(args.consent)) {
      const r = await reconcileAllowedForPeer({ ownerFp, senderFp, seed, consent: args.consent, rowAtRelay: false, fetchImpl: args.fetchImpl });
      try { await requestDrain(ownerFp, io, deps, own); } catch { /* best effort */ }
      return r.action === 'none' ? { skipped: 'never-allowed' } : r;
    }
    // a consent that allows no row: whether THIS peer has one is the relay's to say
    const d = await requestDrain(ownerFp, io, deps, own);
    const o = d.outcomes.get(senderFp.toLowerCase());
    if (o === 'deleted') return { action: 'delete', ok: true };
    if (o === 'failed' || o === 'waiting' || o === 'deferred') return { action: 'delete', ok: false };   // owed: refused just now, inside its retry window, or past this drain's cap
    if (d.listed === 'ok') return { skipped: 'never-allowed' };                       // the relay lists no row for this peer
    return { skipped: 'error' };                                                      // the relay could not be asked (or keeps no list)
  } catch (err) {
    // FAIL-SOFT: the local book is the source of truth; the satellite row is a best-effort mirror that
    // self-heals on the next consent change or know-layer sync tick. Never surface to the handler.
    if (typeof console !== 'undefined') {
      console.warn('[psi] allowed_senders reconcile skipped (non-fatal):', err);
    }
    return { skipped: 'error' };
  }
}

/**
 * The know-layer tick's share of #959 (and app-open's): ask the relay what it still lists and send every DELETE that is owed, so an open session that sits for hours does not leave a
 * blocked person's row open until the next consent change. FAIL-SOFT and QUIET: it never throws, makes no request while the gate is dark, and does nothing while the identity is locked.
 */
export async function runAllowedRevokeTick(
  ownerFp: string,
  args: { allowedRevoke?: AllowedRevokeDeps; loadKeyImpl?: typeof defaultLoadKey; fetchImpl?: typeof fetch; gate?: () => boolean } = {},
): Promise<void> {
  try {
    if (!ownerFp || !(args.gate ?? isPSIDiscoveryLive)()) return;
    const seed = await ownerSeed(ownerFp, args.loadKeyImpl);
    if (!seed) return;
    await requestDrain(ownerFp, revokeIo(ownerFp, seed, args.fetchImpl), args.allowedRevoke ?? realAllowedRevokeDeps());
  } catch { /* best effort: the next tick tries again */ }
}

/**
 * Contact REMOVE: the same rule as every other change, with the all-false "peer gone" consent as the AFTER. A contact the relay does not list sends nothing; one it lists gets exactly one
 * DELETE. Gated, fail-soft, never throws.
 */
export async function reconcileAllowedOnRemove(
  args: Omit<ReconcileAllowedHookArgs, 'consent'>,
): Promise<ReconcileAllowedResult> {
  return reconcileAllowedOnConsentChange({ ...args, consent: GONE });
}
