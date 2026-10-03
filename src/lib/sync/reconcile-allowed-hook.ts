// src/lib/sync/reconcile-allowed-hook.ts
// FE integration hook (#572 part 2): reconcile the satellite allowed_senders row to the owner's
// POST-change consent invariant whenever a trust / block / open-visibility handler fires.
//
// WHY A SEPARATE HOOK (part 1 = allowed-sync.ts is the signed ADD/DELETE + reconcile-by-invariant
// crypto core): this wrapper adds the three FE concerns that must NOT live inline in the UI handlers —
//   1. GATE    — dark until isPSIDiscoveryLive() flips. No /allowed traffic pre-flip, by construction.
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
import { reconcileAllowedForPeer, type PeerConsent } from './allowed-sync';

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
}

export type ReconcileAllowedResult =
  | { action: 'add' | 'delete'; ok: boolean }
  | { skipped: 'dark' | 'no-peer' | 'locked' | 'error' };

/**
 * Reconcile the satellite allowed_senders row for one peer to the owner's POST-change consent.
 * GATE -> seed -> reconcile, all fail-soft. The return value is for tests/telemetry only; the UI
 * handlers call this fire-and-forget (void). NEVER throws, NEVER rejects.
 */
export async function reconcileAllowedOnConsentChange(
  args: ReconcileAllowedHookArgs,
): Promise<ReconcileAllowedResult> {
  const gate = args.gate ?? isPSIDiscoveryLive;
  try {
    if (!gate()) return { skipped: 'dark' };                       // pre-flip: no /allowed traffic
    if (!args.ownerFp || !args.senderFp) return { skipped: 'no-peer' };

    const load = args.loadKeyImpl ?? defaultLoadKey;
    const key = await load(args.ownerFp);
    if (!key?.privateKey || !key.passphrase) return { skipped: 'locked' };  // identity locked → best-effort skip

    const locked = await readPrivateKey({ armoredKey: key.privateKey });
    const decrypted = locked.isDecrypted()
      ? locked
      : await decryptKey({ privateKey: locked, passphrase: key.passphrase });
    const { seed } = extractRawSign(decrypted); // 32B seed: reference into the decrypted key — do NOT zero

    return await reconcileAllowedForPeer({
      ownerFp: args.ownerFp,
      senderFp: args.senderFp,
      seed,
      consent: args.consent,
      fetchImpl: args.fetchImpl,
    });
  } catch (err) {
    // FAIL-SOFT: the local book is the source of truth; the satellite row is a best-effort mirror that
    // self-heals on the next consent change or know-layer sync tick. Never surface to the handler.
    if (typeof console !== 'undefined') {
      console.warn('[psi] allowed_senders reconcile skipped (non-fatal):', err);
    }
    return { skipped: 'error' };
  }
}
