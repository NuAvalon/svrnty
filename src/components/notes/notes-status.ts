// Honest send-status. The blind mailbox has no delivery query.
// Outbound notes that left the device render "Sent · unconfirmed." — never Delivered/Read/Expired.

import { NOTES_COPY } from './notes-copy';

export type NoteBubbleStatus = 'sent-unconfirmed' | 'inbound' | 'not-sent';

export function outboundStatus(deposited: boolean): NoteBubbleStatus {
  return deposited ? 'sent-unconfirmed' : 'not-sent';
}

export function statusLabel(status: NoteBubbleStatus): string {
  if (status === 'sent-unconfirmed') return NOTES_COPY.sentUnconfirmed;
  if (status === 'not-sent') return NOTES_COPY.notSent;
  return '';
}

const FORBIDDEN_LIVE_STATUS = /\b(Delivered|Read|Expired)\b/;

export function statusIsHonestFloor(text: string): boolean {
  if (FORBIDDEN_LIVE_STATUS.test(text)) return false;
  return text === NOTES_COPY.sentUnconfirmed || text === NOTES_COPY.notSent || text === '';
}
