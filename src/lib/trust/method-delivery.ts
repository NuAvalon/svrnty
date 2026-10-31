// src/lib/trust/method-delivery.ts
//
// method_delivery — the LOCAL bookkeeping grammar behind svrnty-addressbook-ack-001's apply-ack wire.
// Living on a contact record's `metadata` bag (already passthrough'd into the TrustEdge the glass
// reads via contact-edge.ts → living-edge-status.ts):
//
//   method_delivery:      'awaiting-ack' | 'acked' | 'undelivered'   (the phase)
//   method_delivery_sig:  string                                        (the owed ack binding —
//                          the update's EnvelopeSignature.classical hex the sender produced; kept only
//                          while awaiting, so a stray/forged ack-of-nothing can never graduate an edge)
//   method_delivery_at:   ISO timestamp                                 (when the mark was written)
//
// Lifecycle: send-contact-update deposit lands → awaiting-ack (+sig +at). A verified apply-ack
// arrives on the consume seam → 'acked' (sig dropped). The TTL-decayed read → 'undelivered'.
//
// PURE — no store, no crypto. Callers do the I/O (client-store updateContact) and the signing
// (crypto/apply-ack.ts). The ONLY write that graduates an edge is markAcked inside the consume seam's
// accept — after verifyApplyAckWire, never from a bare deposit or relay flag.

import type { StoredContact } from '@/lib/contacts/apply-contact-update';
import type { MethodDeliveryPhase } from './living-edge-status';

/** How long 'awaiting-ack' may run before the honest read is 'undelivered'. One relay-TTL horizon. */
export const METHOD_DELIVERY_TTL_MS = 7 * 24 * 60 * 60 * 1000;

type Meta = Record<string, unknown>;

function metaOf(contact: StoredContact): Meta {
  return (contact.metadata ?? {}) as Meta;
}

/** The metadata fragment a sender merges when an update's deposit landed for this peer. */
export function markAwaitingAck(contact: StoredContact, updateSig: string, atIso: string): Meta {
  return {
    ...metaOf(contact),
    method_delivery: 'awaiting-ack',
    method_delivery_sig: updateSig,
    method_delivery_at: atIso,
  };
}

/** The update-sig this peer owes an ack for — present only while the edge is awaiting. */
export function pendingAckSig(contact: StoredContact): string | null {
  const m = metaOf(contact);
  return m.method_delivery === 'awaiting-ack' && typeof m.method_delivery_sig === 'string'
    ? (m.method_delivery_sig as string)
    : null;
}

/**
 * Flip an edge to 'acked' (drops the owed sig — a later stray ack-of-that-sig no longer matches
 * anything). Idempotent: re-marking an 'acked' edge is a no-op write of the same value.
 */
export function markAcked(contact: StoredContact): Meta {
  const m = { ...metaOf(contact) };
  delete m.method_delivery_sig;
  delete m.method_delivery_at;
  m.method_delivery = 'acked';
  return m;
}

/**
 * The phase an edge READS as — TTL-honest: an aged-out 'awaiting-ack' reads 'undelivered' (the peer
 * had a full horizon of polls to ack; silence past it is honest non-arrival, not a false "Delivered"
 * and not a forever-limbo "waiting"). 'acked' is terminal; 'undelivered' may re-await on a resend.
 */
export function methodDeliveryPhase(contact: StoredContact, nowMs: number): MethodDeliveryPhase {
  const m = metaOf(contact);
  const d = m.method_delivery;
  if (d === 'acked' || d === 'undelivered') return d;
  if (d === 'awaiting-ack') {
    const at = typeof m.method_delivery_at === 'string' ? Date.parse(m.method_delivery_at) : NaN;
    if (!Number.isFinite(at) || nowMs - at > METHOD_DELIVERY_TTL_MS) return 'undelivered';
    return 'awaiting-ack';
  }
  return 'none';
}
