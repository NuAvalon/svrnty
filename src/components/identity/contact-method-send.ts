/**
 * CUR-1 — L1 contact-method SEND seam (UI → fleet).
 *
 * ⛔ FLINT owns per-peer encrypt + mailbox deposit (`encryptContactUpdateTo`,
 * sign ContactUpdateEnvelope, relay deposit). This module is the UI contract only.
 * Do NOT implement crypto here.
 */

import type { MethodKind } from './SovereignIdentityCard';

export type ContactMethodSendRequest = {
  kind: MethodKind;
  value: string;
  /** Fingerprints the user chose to notify this send. Not a constitutional ledger. */
  recipientFingerprints: string[];
};

export type ContactMethodSendResult =
  | { ok: true; status: 'stub-queued'; queued: number; message: string }
  | { ok: false; reason: 'empty-value' | 'no-recipients' | 'stub' | string; message: string };

export type ContactMethodSendFn = (
  req: ContactMethodSendRequest
) => Promise<ContactMethodSendResult>;

/**
 * Stub send — validates UI inputs and reports honestly that the wire is not live.
 * Replace body with Flint's encrypt+deposit when the seam is ready.
 */
export const sendContactMethodUpdate: ContactMethodSendFn = async (req) => {
  const value = req.value.trim();
  if (!value) {
    return {
      ok: false,
      reason: 'empty-value',
      message: 'Enter a value before sending an update.',
    };
  }
  if (!req.recipientFingerprints.length) {
    return {
      ok: false,
      reason: 'no-recipients',
      message: 'Pick at least one person who already has your card.',
    };
  }

  // Fleet seam placeholder — do not encrypt, sign, or deposit from UI code.
  // When live: write per-peer method_delivery awaiting-ack, then acked / undelivered.
  // See src/lib/trust/FLEET_TRUST_RECIPROCITY.md
  return {
    ok: true,
    status: 'stub-queued',
    queued: req.recipientFingerprints.length,
    message: `Prepared update for ${req.recipientFingerprints.length} peer(s) — wire send is not live yet (Flint: per-peer encrypt + mailbox + ack receipts). Local draft can still be saved.`,
  };
};

/** Map UI method kinds to wire allowlist fields (emails today; others need fleet grow). */
export function methodKindToWireField(kind: MethodKind): 'emails' | 'handles' | 'urls' {
  if (kind === 'email') return 'emails';
  if (kind === 'signal') return 'handles';
  return 'urls';
}

export function methodKindLabel(kind: MethodKind): string {
  if (kind === 'email') return 'Email';
  if (kind === 'signal') return 'Signal';
  return 'Site';
}
