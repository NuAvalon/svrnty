// Honest send-status. The blind mailbox has no delivery query.
// Outbound notes that left the device render "Sent · unconfirmed." — never Delivered/Read/Expired.

import { NOTES_COPY } from './notes-copy';
import type { SendOutcome } from '@/lib/messaging/types';

export type NoteBubbleStatus = 'sent-unconfirmed' | 'sent-uncertain' | 'inbound' | 'not-sent';

/**
 * Honest-state machine (Hypatia's claim-honesty bar + the 4xx-vs-5xx split, ☀8307):
 *   confirmed (2xx)             → 'sent-unconfirmed' — reached the relay; no receipt-of-record.
 *   unconfirmed (5xx/timeout/throw) → 'sent-uncertain' — couldn't confirm it left; NEVER "failed"
 *                                     (a 5xx can sit over a durable deposit — uncertainty resolves
 *                                     to the non-lying state).
 *   refused (authoritative 400/413) → 'not-sent' — provably did not land; the ONLY "Not sent".
 */
export function outboundStatus(outcome: SendOutcome): NoteBubbleStatus {
  if (outcome === 'confirmed') return 'sent-unconfirmed';
  if (outcome === 'refused') return 'not-sent';
  return 'sent-uncertain';
}

export function statusLabel(status: NoteBubbleStatus): string {
  if (status === 'sent-unconfirmed') return NOTES_COPY.sentUnconfirmed;
  if (status === 'sent-uncertain') return NOTES_COPY.sentUncertain;
  if (status === 'not-sent') return NOTES_COPY.notSent;
  return '';
}

const FORBIDDEN_LIVE_STATUS = /\b(Delivered|Read|Expired)\b/;

export function statusIsHonestFloor(text: string): boolean {
  if (FORBIDDEN_LIVE_STATUS.test(text)) return false;
  return (
    text === NOTES_COPY.sentUnconfirmed ||
    text === NOTES_COPY.sentUncertain ||
    text === NOTES_COPY.notSent ||
    text === ''
  );
}
