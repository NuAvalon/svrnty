// src/components/notes/cant-open-notice.ts
// #731: tell the user that messages reached this device but couldn't be opened, from the local dead-letter rows (dead-letter.ts:
// METADATA ONLY, no content). Copy = Hypatia's #731 COPY OF RECORD v1 (svrnty_731_cant_open_copy_of_record_v1.md, 70c7888d), by value.
// Pure: rows in, lines out. The inbox loads the rows and remembers when the S line was last dismissed.
//
// Rule 0: a HELD row (phase 'held') renders NO line, whatever its reason: the thread's held rows already say the app keeps trying.
// Order (pinned): R, L, U, X, S.
//   R  a contact's    ratchet-unopenable / ratchet-local / ratchet-desync / session-reset, sender authenticated AND in the book:
//                     one line per (contact, reason), named from the BOOK; the second sentence depends on the reason.
//   L  a former one   an R-reason row whose fp is present but no longer in the book: count only, no name/fp/ask.
//   U  sender unknown unknown-format, decrypt-failed, missing-key, verify-failed, AND any authenticated-reason row with NO fp: count only.
//   X  too late       expired: count only.
//   S  not a contact  not-in-book: ONE presence line, no number/fp/name/time; after a dismissal it returns only for a row first seen later.
// unverified-frame is not a message (dead-letter.ts NON_MESSAGE_REASONS) and never counts.

import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';
import { isMessageReason, type DeadLetterReason, type DeadLetterRow } from '@/lib/sync/dead-letter';
import { resetOffered } from './ratchet-rows-view';

export type CantOpenGroup = 'R' | 'L' | 'U' | 'X' | 'S';

type RReason = 'ratchet-unopenable' | 'ratchet-local' | 'ratchet-desync' | 'session-reset';

const GROUP: Record<DeadLetterReason, CantOpenGroup | null> = {
  'unknown-format': 'U',
  'decrypt-failed': 'U',
  'missing-key': 'U',
  'verify-failed': 'U',
  'unverified-frame': null,
  'not-in-book': 'S',
  'ratchet-unopenable': 'R',
  'ratchet-local': 'R',
  'ratchet-desync': 'R',
  'session-reset': 'R',
  expired: 'X',
};

export function groupFor(reason: DeadLetterReason): CantOpenGroup | null {
  return isMessageReason(reason) ? GROUP[reason] ?? null : null;
}

export interface CantOpenNotice {
  group: CantOpenGroup;
  text: string;
  /** R only: the contact whose conversation 'Open conversation' opens (NotesInbox shows it only when this device can message them). No resend ask: copy of record 70c7888d. */
  fingerprint?: string;
}

const msgs = (n: number) => (n === 1 ? '1 message' : `${n} messages`);
const them = (n: number) => (n === 1 ? 'it' : 'them');

export const cantOpenU = (n: number) =>
  n === 1
    ? "1 message couldn't be opened on this device, so svrnty can't tell who sent it. This device didn't keep it."
    : `${n} messages couldn't be opened on this device, so svrnty can't tell who sent them. This device didn't keep them.`;
export const cantOpenX = (n: number) =>
  n === 1 ? "1 message arrived after its time limit and wasn't opened." : `${n} messages arrived after their time limit and weren't opened.`;
export const CANT_OPEN_S = "People who aren't in your contacts tried to message you. svrnty doesn't open those.";
export const cantOpenL = (n: number) =>
  n === 1
    ? "1 message from someone no longer in your contacts couldn't be opened on this device. This device didn't keep it."
    : `${n} messages from people no longer in your contacts couldn't be opened on this device. This device didn't keep them.`;

/** The R line for one (contact, reason). `offerReset` is #318's resetOffered (the same predicate as the Reset button and its hints). */
export function cantOpenR(reason: RReason, n: number, name: string, offerReset: boolean): string {
  if (reason === 'session-reset') {
    return `${msgs(n)} from ${name} couldn't be opened because your message session with them was restarted. Ask ${name} to send ${them(n)} again.`;
  }
  const first = `${msgs(n)} from ${name} couldn't be opened on this device.`;
  if (reason === 'ratchet-local') return `${first} Restoring your keys on this device may help with new messages.`;
  if (reason === 'ratchet-desync') {
    return offerReset
      ? `${first} If messages from ${name} keep failing, reset your message session with them, then ask them to send ${them(n)} again.`
      : `${first} Resetting the message session isn't available for this contact yet.`;
  }
  return `${first} Ask ${name} to send ${them(n)} again.`;
}

const R_ORDER: readonly RReason[] = ['ratchet-unopenable', 'ratchet-local', 'ratchet-desync', 'session-reset'];

/**
 * The lines to show, in the pinned order R, L, U, X, S. No rows (or only held / non-message rows) → no lines.
 * nameFor resolves an AUTHENTICATED fingerprint to the contact's name in the book. isAgent says whether that contact is an agent
 * (#318 peerIsAgent): an agent contact is never told to reset its session.
 * sDismissedAt: when the user last dismissed the S line (ISO), or null. S shows only if a not-in-book row was first seen after that.
 */
export function cantOpenNotices(
  rows: readonly DeadLetterRow[],
  nameFor: (fingerprint: string) => string | null,
  sDismissedAt: string | null,
  isAgent: (fingerprint: string) => boolean = () => false,
): CantOpenNotice[] {
  const byContact = new Map<string, { name: string; n: Map<RReason, number> }>();
  let left = 0;
  let u = 0;
  let x = 0;
  let sNew = false;
  const dismissed = sDismissedAt === null ? null : Date.parse(sDismissedAt);
  for (const row of rows) {
    if (row.phase === 'held') continue; // Rule 0
    const g = groupFor(row.reason);
    if (g === 'R') {
      const key = row.fp ? normalizeFingerprintHex(row.fp) : '';
      if (!key) {
        u++; // authenticated reason but no fp: nobody to name (Flint #2594)
        continue;
      }
      const name = nameFor(key);
      if (!name) {
        left++;
        continue;
      }
      const hit = byContact.get(key) ?? { name, n: new Map<RReason, number>() };
      const r = row.reason as RReason;
      hit.n.set(r, (hit.n.get(r) ?? 0) + 1);
      byContact.set(key, hit);
    } else if (g === 'U') u++;
    else if (g === 'X') x++;
    else if (g === 'S') {
      const seen = Date.parse(row.first_seen);
      // A dismissal time that can't be read hides nothing; a row time that can't be read counts as new.
      if (dismissed === null || !Number.isFinite(dismissed) || !Number.isFinite(seen) || seen > dismissed) sNew = true;
    }
  }
  const out: CantOpenNotice[] = [];
  for (const [fingerprint, { name, n }] of byContact) {
    for (const r of R_ORDER) {
      const count = n.get(r);
      if (count) out.push({ group: 'R', text: cantOpenR(r, count, name, resetOffered(true, isAgent(fingerprint))), fingerprint });
    }
  }
  if (left > 0) out.push({ group: 'L', text: cantOpenL(left) });
  if (u > 0) out.push({ group: 'U', text: cantOpenU(u) });
  if (x > 0) out.push({ group: 'X', text: cantOpenX(x) });
  if (sNew) out.push({ group: 'S', text: CANT_OPEN_S });
  return out;
}
