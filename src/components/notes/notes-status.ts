// Honest send-status. The blind mailbox has no delivery query — EXCEPT a cryptographically VERIFIED
// delivery receipt (delivery-receipt.ts), which alone graduates "Sent · unconfirmed." → "Delivered".
// Every UNVERIFIED path stays the floor: Delivered/Read/Expired are forbidden unless receipt-backed.

import { NOTES_COPY } from './notes-copy';

export type NoteBubbleStatus = 'sent-unconfirmed' | 'inbound' | 'not-sent' | 'delivered';

/**
 * Outbound status. `delivered` is TRUE only when a cryptographically VERIFIED delivery receipt has
 * been processed for this note (set upstream by verifyReceiptWire in the consume seam — NEVER from an
 * unverified signal, a relay flag, or a bare deposit ack). Without it, the floor holds.
 */
export function outboundStatus(deposited: boolean, delivered = false): NoteBubbleStatus {
  if (delivered) return 'delivered';
  return deposited ? 'sent-unconfirmed' : 'not-sent';
}

export function statusLabel(status: NoteBubbleStatus): string {
  if (status === 'delivered') return NOTES_COPY.delivered;
  if (status === 'sent-unconfirmed') return NOTES_COPY.sentUnconfirmed;
  if (status === 'not-sent') return NOTES_COPY.notSent;
  return '';
}

const FORBIDDEN_LIVE_STATUS = /\b(Delivered|Read|Expired)\b/;

/**
 * Honesty enforcement (Flint [[green-only-if-enforced]]): a label carrying a live-delivery word
 * (Delivered/Read/Expired) is honest ONLY when the status is 'delivered' — i.e. backed by a VERIFIED
 * receipt — and then ONLY as the exact delivered copy. For every other status the floor holds: no
 * Delivered/Read/Expired, only the floor strings. This is the guard that makes the status enum's
 * verified-only property enforceable, not just conventional.
 */
export function statusIsHonest(status: NoteBubbleStatus, text: string): boolean {
  if (status === 'delivered') {
    // 'Delivered' is permitted ONLY here — and only as the delivered copy, so a 'Read'/'Expired'
    // (or any other forbidden word) can't be smuggled through the delivered branch.
    return text === NOTES_COPY.delivered && !/\b(Read|Expired)\b/.test(text);
  }
  if (FORBIDDEN_LIVE_STATUS.test(text)) return false;
  return text === NOTES_COPY.sentUnconfirmed || text === NOTES_COPY.notSent || text === '';
}

/**
 * The pure floor check (no verified-delivery exception) — retained for callers that assert the
 * unconditional floor. New callers use statusIsHonest(status, text), which permits a verified
 * 'Delivered' only for the 'delivered' status.
 */
export function statusIsHonestFloor(text: string): boolean {
  if (FORBIDDEN_LIVE_STATUS.test(text)) return false;
  return text === NOTES_COPY.sentUnconfirmed || text === NOTES_COPY.notSent || text === '';
}
