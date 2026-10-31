// src/components/notes/cant-open-notice.ts
// #731: tell the user that messages reached this device but couldn't be opened, from the local dead-letter rows (dead-letter.ts:
// METADATA ONLY, no content). Copy = Hypatia #731 v0.1 (6b627ef3) groups U/X/R + v0.2 (c8f47555) group S; Archie #188111/#188118.
// Pure: rows in, lines out. The inbox loads the rows and remembers when the S line was last dismissed.
//
//   U  sender unknown  unknown-format, decrypt-failed, missing-key, verify-failed   count only, NEVER a name (unauthenticated)
//   X  too late        expired                                                      count only
//   S  not a contact   not-in-book                                                  ONE presence line: no number, no fp, no name, no time
//   R  a contact's     ratchet-unopenable, ratchet-local                            count + the contact's name + "ask them to resend"
//   L  a former contact  R rows whose sender is no longer in the book                count only, no name/fp/ask (Hypatia #188146 (a))
// unverified-frame is not a message (dead-letter.ts NON_MESSAGE_REASONS) and never counts.

import { normalizeFingerprintHex } from '@/lib/identity/fingerprint';
import { isMessageReason, type DeadLetterReason, type DeadLetterRow } from '@/lib/sync/dead-letter';

export type CantOpenGroup = 'R' | 'L' | 'U' | 'X' | 'S';

const GROUP: Record<DeadLetterReason, CantOpenGroup | null> = {
  'unknown-format': 'U',
  'decrypt-failed': 'U',
  'missing-key': 'U',
  'verify-failed': 'U',
  'unverified-frame': null,
  'not-in-book': 'S',
  'ratchet-unopenable': 'R',
  'ratchet-local': 'R',
  expired: 'X',
};

export function groupFor(reason: DeadLetterReason): CantOpenGroup | null {
  return isMessageReason(reason) ? GROUP[reason] ?? null : null;
}

export interface CantOpenNotice {
  group: CantOpenGroup;
  text: string;
  /** R only: the contact to open so the user can ask for a resend. */
  fingerprint?: string;
}

const msgs = (n: number) => (n === 1 ? '1 message' : `${n} messages`);

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
export const cantOpenR = (n: number, name: string) =>
  `${msgs(n)} from ${name} couldn't be opened on this device. Ask ${name} to send ${n === 1 ? 'it' : 'them'} again.`;

/**
 * The lines to show, actionable first (R by contact, then L, U, X, S). No rows → no lines.
 * nameFor resolves an AUTHENTICATED fingerprint to the contact's name in the book. An R row whose sender is no longer in the book has no
 * one to ask: it counts in L, which shows no name. (Not U: U says svrnty can't tell who sent them, which is false for an authenticated sender.)
 * sDismissedAt: when the user last dismissed the S line (ISO), or null. S shows only if a not-in-book row was first seen after that.
 */
export function cantOpenNotices(
  rows: readonly DeadLetterRow[],
  nameFor: (fingerprint: string) => string | null,
  sDismissedAt: string | null,
): CantOpenNotice[] {
  const byContact = new Map<string, { name: string; n: number }>();
  let u = 0;
  let left = 0;
  let x = 0;
  let sNew = false;
  const dismissed = sDismissedAt === null ? null : Date.parse(sDismissedAt);
  for (const row of rows) {
    const g = groupFor(row.reason);
    if (g === 'R') {
      // One line per contact however the fingerprint was cased in the row (Flint nit, Archie #2588).
      const key = row.fp ? normalizeFingerprintHex(row.fp) : '';
      const name = key ? nameFor(key) : null;
      if (!key || !name) {
        left++;
        continue;
      }
      const hit = byContact.get(key) ?? { name, n: 0 };
      hit.n++;
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
  for (const [fingerprint, { name, n }] of byContact) out.push({ group: 'R', text: cantOpenR(n, name), fingerprint });
  if (left > 0) out.push({ group: 'L', text: cantOpenL(left) });
  if (u > 0) out.push({ group: 'U', text: cantOpenU(u) });
  if (x > 0) out.push({ group: 'X', text: cantOpenX(x) });
  if (sNew) out.push({ group: 'S', text: CANT_OPEN_S });
  return out;
}
