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

/**
 * Has this peer already PROVEN it sends delivery receipts? True iff at least one OUTBOUND note in the conversation carries a
 * VERIFIED receipt (`delivered === true`, set only by the receipt consume seam after verifyReceiptWire). Derived from stored
 * notes, so there is nothing new to persist. Strict `=== true`: a truthy non-boolean does not count.
 */
export function peerSendsReceipts(notes: ReadonlyArray<{ direction: string; delivered?: unknown }>): boolean {
  return notes.some((n) => n.direction === 'outbound' && n.delivered === true);
}

/**
 * The secondary hint "Awaiting delivery confirmation" PROMISES that a receipt may arrive. Only the browser sends receipts: our
 * agents never do, and a classical contact cannot. So the promise is made only for a peer who has already proven it sends them
 * (observed capability, same shape as the ratchet's D1 rule); otherwise the note shows the bare floor "Sent · unconfirmed." and
 * nothing that implies a confirmation is coming. (Hypatia #745.)
 */
export function showAwaitingHint(a: {
  outbound: boolean;
  status: NoteBubbleStatus;
  hasReceiptNonce: boolean;
  peerSendsReceipts: boolean;
}): boolean {
  return a.outbound && a.status === 'sent-unconfirmed' && a.hasReceiptNonce && a.peerSendsReceipts;
}

/**
 * D2: say "Triple ratchet is off for <name>" only when it is TRUE and useful: we can send to them (a verified kem key, else the send
 * is "not sent" and the line would be beside the point), their card carries ratchet keys, and we have NOT opened a ratchet frame from
 * them. An observed peer (their app sent us a frame, so the session continues) gets nothing extra; an unknown state gets nothing
 * (we do not guess). There is no "on" line: nothing in this app starts a ratchet, so we never announce one.
 */
export function showRatchetOffLine(a: {
  canSend: boolean;
  hasRatchetKeys: boolean;
  status: 'observed' | 'not-observed' | 'unknown';
}): boolean {
  return a.canSend && a.hasRatchetKeys && a.status === 'not-observed';
}

// claim-sweep:ok guard regex that blocks this claim (TG-1 annotation_ok, Hypatia v1.1.1)
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
