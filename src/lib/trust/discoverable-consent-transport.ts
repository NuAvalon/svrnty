// src/lib/trust/discoverable-consent-transport.ts
// PUBLISH side of Carol's discoverable-consent wire (trust-PSI increment #2, TRANSPORT half).
// Seal + deposit Carol's already-signed GLOBAL consent to each of her contacts' blind mailboxes via the
// EXISTING dumb relay (no new relay smarts). Mirror of trust-affirm-transport.sendTrustAffirmToPeer.
//
// ★ UNLIKE trust-affirm (signed per-send, recipient-bound), the discoverable-consent is signed ONCE —
// Carol signs her GLOBAL willingness (scope=global, no per-truster binding) via signDiscoverableConsent,
// and that SAME signed object is sealed+deposited to EACH contact. It is self-authenticating: the
// recipient's applyDiscoverableConsent re-verifies Carol's signature against her stored pubkeys, so the
// transport needn't authenticate the deposit-sender — only deliver per-peer-encrypt + satellite-blind
// (Flint #172716). GLOBAL-v1 ⇒ fan-out to Carol's CONTACTS (the peers she can enumerate); a truster who
// is not her contact simply never receives it → their edge flag stays false (fail-closed by construction).
// Revocation is the same fan-out with a higher-epoch { discoverable:false } signed consent.

import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import type { SignedDiscoverableConsent } from './discoverable-consent';
import {
  DISCOVERABLE_CONSENT_WIRE_TYPE,
  sealDiscoverableConsentTo,
  type DiscoverableConsentWireV0,
} from './discoverable-consent-seal';

/** Seal + deposit one already-signed consent to a single peer's mailbox (opaque blob). */
export async function sendDiscoverableConsentToPeer(args: {
  /** Carol's signed GLOBAL consent (from signDiscoverableConsent) — the SAME object for every peer. */
  signed: SignedDiscoverableConsent;
  peerFingerprint: string;
  peerPublicKeyArmored: string;
  relayBase?: string;
  fetchImpl?: typeof fetch;
}): Promise<{ deposited: boolean }> {
  const fetchImpl = args.fetchImpl ?? fetch;
  const relayBase = args.relayBase ?? '/api/relay';
  const wire: DiscoverableConsentWireV0 = { type: DISCOVERABLE_CONSENT_WIRE_TYPE, ...args.signed };
  const blob = await sealDiscoverableConsentTo(wire, args.peerPublicKeyArmored);
  const mailbox_id = deriveMailboxId(args.peerFingerprint);
  const res = await fetchImpl(`${relayBase}/envelope`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mailbox_id, blob }),
  });
  return { deposited: res.ok };
}

/** A contact Carol can publish to — the fields the deposit needs. */
export interface PublishablePeer {
  fingerprint: string;
  public_key: string;
}

/**
 * PUBLISH (fan-out): deposit Carol's one signed GLOBAL consent to ALL her contacts. Best-effort per peer —
 * one failed deposit does not abort the rest (at-least-once; a missed peer re-receives on the next publish).
 * Peers with no usable public_key are skipped (can't seal to them). Returns deposit counts.
 */
export async function publishDiscoverableConsent(args: {
  signed: SignedDiscoverableConsent;
  contacts: PublishablePeer[];
  relayBase?: string;
  fetchImpl?: typeof fetch;
}): Promise<{ total: number; deposited: number; skipped: number }> {
  let deposited = 0;
  let skipped = 0;
  for (const peer of args.contacts) {
    if (!peer.public_key || !peer.fingerprint) {
      skipped++;
      continue;
    }
    try {
      const res = await sendDiscoverableConsentToPeer({
        signed: args.signed,
        peerFingerprint: peer.fingerprint,
        peerPublicKeyArmored: peer.public_key,
        relayBase: args.relayBase,
        fetchImpl: args.fetchImpl,
      });
      if (res.deposited) deposited++;
    } catch {
      // best-effort: a seal/deposit failure for one peer must not block the rest (re-published next cycle).
    }
  }
  return { total: args.contacts.length, deposited, skipped };
}
