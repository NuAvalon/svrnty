/**
 * Living Address Book / Trust Map — honest edge status (glass).
 *
 * Derives UI phases from local book fields + optional metadata stubs.
 * Does NOT invent wire reciprocity, PSI, or delivery acks — those are fleet.
 */

import type { TrustEdge } from '@/lib/trust/types';
import { daysUntilDecay, isDecayed } from '@/lib/trust/types';
import { isSvrnNetworkContact } from '@/lib/contacts/is-svrn-contact';

export type LivingConnectionPhase = 'classical' | 'pending' | 'one-way' | 'linked';
export type LivingTrustPhase = 'none' | 'outbound' | 'inbound' | 'mutual';
export type MethodDeliveryPhase = 'none' | 'awaiting-ack' | 'acked' | 'undelivered';

export type LivingEdgeStatus = {
  connection: LivingConnectionPhase;
  trust: LivingTrustPhase;
  /** True when SVRNTY + linked (both known) — messaging is allowed in product terms. */
  canCommunicate: boolean;
  methodDelivery: MethodDeliveryPhase;
  statusLine: string;
  detailLine: string | null;
  lastMoment: string | null;
  /** 0..1 weather for trusted edges nearing decay (1 = fresh). */
  decayFreshness: number;
};

type EdgeBag = TrustEdge & {
  connection_status?: string;
  pending_intro?: unknown;
  metadata?: {
    connection_status?: string;
    pending_intro?: unknown;
    method_delivery?: MethodDeliveryPhase;
    trust_outbound?: boolean;
    trust_probe?: 'pending' | 'no-ack' | 'reciprocal' | 'fleet-pending';
    last_moment?: string;
    last_moment_at?: string;
  };
};

function isPending(edge: EdgeBag): boolean {
  const status = (edge.connection_status || edge.metadata?.connection_status || '').toLowerCase();
  return status === 'pending' || !!edge.pending_intro || !!edge.metadata?.pending_intro;
}

function relativeMoment(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  const days = Math.round((Date.now() - t) / (24 * 60 * 60 * 1000));
  if (days <= 0) return 'today';
  if (days === 1) return 'yesterday';
  if (days < 14) return `${days}d ago`;
  if (days < 60) return `${Math.round(days / 7)}w ago`;
  if (days < 730) return `${Math.round(days / 30)}mo ago`;
  return `${Math.round(days / 365)}y ago`;
}

function deliveryOf(edge: EdgeBag): MethodDeliveryPhase {
  const d = edge.metadata?.method_delivery;
  if (d === 'awaiting-ack' || d === 'acked' || d === 'undelivered') return d;
  return 'none';
}

/**
 * Pure status for one edge. Fail closed: never claim mutual or delivered without fields.
 */
export function livingEdgeStatus(edge: TrustEdge): LivingEdgeStatus {
  const e = edge as EdgeBag;
  const living = isSvrnNetworkContact({
    fingerprint: e.peer_fingerprint,
    public_key: e.peer_public_key,
  });

  let connection: LivingConnectionPhase;
  if (!living) connection = 'classical';
  else if (isPending(e)) connection = 'pending';
  else connection = 'linked';

  const theyTrustMe = e.mutual?.they_trust_me === true || e.mutual?.reciprocal === true;
  const reciprocal = e.mutual?.reciprocal === true;
  const outboundFlag = e.metadata?.trust_outbound === true || e.metadata?.trust_probe === 'pending';

  let trust: LivingTrustPhase = 'none';
  if (reciprocal) trust = 'mutual';
  else if (e.trusted) trust = 'outbound';
  else if (theyTrustMe) trust = 'inbound';
  else if (outboundFlag) trust = 'outbound';

  const methodDelivery = deliveryOf(e);
  const canCommunicate = living && connection === 'linked';

  const daysLeft = e.trusted ? daysUntilDecay(e) : 0;
  const decayed = isDecayed(e);
  let decayFreshness = 1;
  if (e.trusted && e.decay_days > 0) {
    decayFreshness = Math.max(0, Math.min(1, daysLeft / e.decay_days));
  }

  const lastAt =
    e.metadata?.last_moment_at || e.mutual?.last_sync || e.last_interaction || e.trusted_since;
  const lastMoment = relativeMoment(lastAt);

  let statusLine: string;
  if (connection === 'classical') statusLine = 'Classical book';
  else if (connection === 'pending') statusLine = 'Pending · not linked yet';
  else if (trust === 'mutual') statusLine = 'Mutual trust';
  else if (trust === 'outbound') statusLine = 'Trusted · awaiting mutual';
  else if (trust === 'inbound') statusLine = 'They trust you · you have not';
  else if (canCommunicate) statusLine = 'Linked · can communicate';
  else statusLine = 'Known';

  let detailLine: string | null = null;
  if (methodDelivery === 'awaiting-ack') {
    detailLine = 'Method update sent · waiting for their ack';
  } else if (methodDelivery === 'undelivered') {
    detailLine = 'Method update did not get an ack';
  } else if (methodDelivery === 'acked') {
    detailLine = 'Method update acknowledged';
  } else if (trust === 'outbound' && e.metadata?.trust_probe === 'no-ack') {
    detailLine = 'Trust signal sent · no reciprocity ack yet';
  } else if (trust === 'outbound') {
    detailLine = 'Trust is on your device · reciprocity probe is fleet-owned';
  } else if (decayed) {
    detailLine = 'Trust quiet · past decay window on this device';
  } else if (e.trusted && daysLeft >= 0 && daysLeft < 90) {
    detailLine = `${daysLeft}d until trust goes quiet`;
  } else if (e.metadata?.last_moment) {
    detailLine = e.metadata.last_moment;
  }

  return {
    connection,
    trust,
    canCommunicate,
    methodDelivery,
    statusLine,
    detailLine,
    lastMoment,
    decayFreshness,
  };
}

export function livingStatusChip(status: LivingEdgeStatus): string {
  if (status.connection === 'classical') return 'Classical';
  if (status.connection === 'pending') return 'Pending';
  if (status.trust === 'mutual') return 'Mutual';
  if (status.trust === 'outbound') return 'Trust sent';
  if (status.trust === 'inbound') return 'Trusts you';
  if (status.canCommunicate) return 'Linked';
  return 'Known';
}
