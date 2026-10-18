// src/lib/trust/apply-trust-transition.ts
// THE single trust-transition chokepoint (§1 I-F SYMMETRY PRECEDES VISIBILITY).
//
// WHY THIS EXISTS. Trust could be granted from more than one surface (the contact LIST toggle in
// ContactManagement, the trust-MAP toggle in app/page.tsx, and future ones). Each fork independently
// drifted — the map path forgot the satellite commit AND the emit; the list path forgot trust_history
// (Flint floor-verify #173014). A surface that flips local trust WITHOUT depositing a signed
// affirmation leaves the peer unaware → no mutual edge ever forms, with no signal to the user. That
// fork IS the bug class.
//
// So every trust/break transition routes HERE, making "grant trust" and "deposit the affirmation"
// inseparable by construction: no current or future surface can grant trust without the peer learning.
// Order: (1) local trust write (+ trust_history + #111 open-vis clear on untrust), (2) blind satellite
// commit/revoke, (3) PSI reveal-set reconcile (#572), (4) EMIT-ONLY deposit.
//
// EMIT-ONLY: this writes NOTHING to reciprocal / they_trust_me. Reciprocal flips ONLY on the peer's
// crypto-verified RECEIVE (acceptTrustAffirm). Sending an affirmation is not assuming mutuality
// (anti-coercion: no unilateral visibility). Send fails OPEN (local trust holds, peer re-syncs);
// the consume side stays fail-SAFE.

import { reconcileAllowedOnConsentChange } from '@/lib/sync/reconcile-allowed-hook';
import { sendTrustAffirmToPeer } from '@/lib/trust/trust-affirm-transport';
import { updateContact as realUpdateContact, loadKey as realLoadKey } from '@/lib/identity/client-store';
import type { TrustEvent } from '@/lib/trust/types';

export interface TrustTransitionOwner {
  fingerprint: string;
  /** own armored classical pub (identity.identity.public_key) — signs the affirmation. */
  publicKeyArmored?: string;
  /** §5 canonical-fp binding: own PQ pubkeys (base64), from identity.post_quantum.* (store shape —
   *  NOT identity.identity.pq_*, the card shape). Omitting them drops a canonical sender to classical. */
  pqKemPublicKey?: string;
  pqSigPublicKey?: string;
}

export interface TrustTransitionPeer {
  /** contact record id for the local updateContact patch. */
  contactId: string;
  fingerprint?: string;
  /** peer's armored pub (contact.public_key / edge.peer_public_key) — the seal target. */
  publicKeyArmored?: string;
  blocked?: boolean;
  openVisibility?: boolean;
  perContactPrivate?: boolean;
  metadata?: Record<string, unknown>;
  priorTrustHistory?: TrustEvent[];
}

export interface TrustTransitionDeps {
  /** injectable for tests; defaults to the real client-store ops. */
  updateContact?: (id: string, patch: Record<string, unknown>) => Promise<unknown>;
  loadKey?: (fp: string) => Promise<{ privateKey: string; passphrase: string } | null>;
  /** injectable for tests; defaults to reconcileAllowedOnConsentChange. Fire-and-forget (return
   *  ignored) — the arg shape is pinned to the real hook, the result is not. */
  reconcile?: (args: Parameters<typeof reconcileAllowedOnConsentChange>[0]) => unknown;
  fetchImpl?: typeof fetch;
  /** satellite base (default '' → same-origin /api/trust/*). */
  satelliteBase?: string;
  /** relay base passed through to sendTrustAffirmToPeer (default its own '/api/relay'). */
  relayBase?: string;
  /** timestamp source (default new Date().toISOString()); injectable for deterministic tests. */
  now?: () => string;
}

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function applyTrustTransition(
  owner: TrustTransitionOwner,
  peer: TrustTransitionPeer,
  nextTrusted: boolean,
  deps: TrustTransitionDeps = {},
): Promise<void> {
  const updateContact = deps.updateContact ?? realUpdateContact;
  const loadKey = deps.loadKey ?? realLoadKey;
  const reconcile = deps.reconcile ?? reconcileAllowedOnConsentChange;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const now = deps.now ? deps.now() : new Date().toISOString();

  // (1) LOCAL trust write. trust_history append + #111 survivor-safety: untrust clears open_visibility
  // (reveal consent is trust-gated — reveal set = trusted ∩ open_vis ∩ !blocked, by construction).
  const historyEvent: TrustEvent = {
    timestamp: now,
    action: nextTrusted ? 'trust' : 'break',
    reason: nextTrusted ? 'owner trusted' : 'owner broke trust',
    initiated_by: 'self',
  };
  await updateContact(peer.contactId, {
    trust_level: nextTrusted ? 'trusted' : 'unverified',
    trusted: nextTrusted,
    trusted_since: nextTrusted ? now : null,
    ...(nextTrusted ? { verified_at: now } : {}),
    trust_history: [...(peer.priorTrustHistory ?? []), historyEvent],
    ...(!nextTrusted && {
      metadata: {
        ...(peer.metadata ?? {}),
        share_settings: {
          ...((peer.metadata?.share_settings as Record<string, unknown>) ?? {}),
          open_visibility: false,
        },
      },
    }),
  });

  // (2) SATELLITE blind trust commitment — the satellite never sees WHO you trust (sorted-fp hash).
  if (peer.fingerprint) {
    try {
      const fps = [owner.fingerprint, peer.fingerprint].sort();
      const commitment_hash = await sha256Hex(fps.join('') + 'trust-v1');
      const base = deps.satelliteBase ?? '';
      await fetchImpl(`${base}/api/trust/${nextTrusted ? 'commit' : 'revoke'}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fingerprint: owner.fingerprint, commitment_hash }),
      });
    } catch { /* satellite offline — local trust still works */ }
  }

  // (3) PSI reveal-set reconcile (#572) — fire-and-forget, fail-soft (gated dark pre-flip).
  void reconcile({
    ownerFp: owner.fingerprint,
    senderFp: peer.fingerprint,
    consent: {
      trusted: nextTrusted,
      openVisibility: nextTrusted && peer.openVisibility === true,
      blocked: peer.blocked === true,
      perContactPrivate: peer.perContactPrivate === true,
    },
  });

  // (4) EMIT-ONLY deposit — signed affirmation to the peer's blind mailbox. Best-effort: a failed
  // deposit never breaks the local toggle; keyless peers (no armored pub) simply can't be sealed to.
  if (peer.fingerprint && peer.publicKeyArmored && owner.publicKeyArmored) {
    try {
      const key = await loadKey(owner.fingerprint);
      if (key) {
        await sendTrustAffirmToPeer({
          senderFingerprint: owner.fingerprint,
          senderPublicKeyArmored: owner.publicKeyArmored,
          senderPrivateKeyArmored: key.privateKey,
          passphrase: key.passphrase,
          senderPqKemPublicKey: owner.pqKemPublicKey,
          senderPqSigPublicKey: owner.pqSigPublicKey,
          peerFingerprint: peer.fingerprint,
          peerPublicKeyArmored: peer.publicKeyArmored,
          trusts: nextTrusted,
          fetchImpl,
          relayBase: deps.relayBase,
        });
      }
    } catch { /* deposit best-effort — local + satellite already applied; peer re-syncs */ }
  }
}
