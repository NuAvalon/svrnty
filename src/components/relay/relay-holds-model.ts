// src/components/relay/relay-holds-model.ts
// The pure model of the "what the relay holds about you" panel: from the relay's OWN list and the owner's book, who is over-listed and who is under-listed. No I/O, no rendering.
//
//   OVER-LISTED  = the relay lists them and the book does not allow a row (blocked, go-private, closed visibility, or not in the book at all). the revoke check's drain (allowed-revoke.ts) takes them off, so the panel shows a COUNT only.
//                  This is the same rule as the drain's, and relay-holds-model.test.ts runs the real drain to keep the two equal.
//   UNDER-LISTED = the book allows a row and the relay does not list it. Shown as ROWS (a name each) so the owner may Repair one deliberately. Nothing here ever adds on its own.
//
// A failed or unknown read is "unknown", never an empty list; a 410 is "no-list" (the relay keeps none); and a DAMAGED contact book is its own state ("book-damaged", whatever the relay read said, except a 410): it cannot say who is gone or who is allowed, so the panel shows one line, no rows and no Repair.
// A value the relay lists that is not in the book is counted and NEVER named: no fingerprint of an over-listed person is in the model at all, so none can reach the screen and none can be looked up. The relay is untrusted.
import { allowedRowShouldExist, type AllowedListResult, type PeerConsent } from '@/lib/sync/allowed-sync';
import { rowLabel } from './relay-holds-copy';

export interface BookEntry { name: string | null; consent: PeerConsent }
/** One under-listed contact. `fp` is the CONTACT's own fingerprint as the book stores it (the handle a Repair signs for); it is never rendered. */
export interface UnderRow { fp: string; label: string; /** the contact's own name, or null: the repair lines read a nameless one as "this person" mid-sentence */ name: string | null }
export type PanelModel =
  | { kind: 'unknown' }
  | { kind: 'no-list' }
  | { kind: 'book-damaged' }
  | { kind: 'ok'; overCount: number; under: UnderRow[]; noKeyCount: number };

/** The relay's listed fingerprints (lower case, once each) whose consent does not allow a row. The rule the drain uses for a complete book. */
export function overListedFps(listed: AllowedListResult, book: ReadonlyMap<string, BookEntry>): string[] {
  if (listed.status !== 'ok') return [];
  const byLower = new Map<string, BookEntry>();
  for (const [k, e] of book) byLower.set(k.toLowerCase(), e);
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of listed.fps) {
    const k = raw.toLowerCase();
    if (seen.has(k)) continue;
    seen.add(k);
    const e = byLower.get(k);
    if (e && allowedRowShouldExist(e.consent)) continue;
    out.push(k);
  }
  return out;
}

/** How many contacts the book allows who have NO KEY yet: they can never be listed and the book's own comparison skips them, so they are counted here as their own state. */
function wholeCount(n: number): number {
  if (!Number.isInteger(n) || n < 0) throw new Error('relay-holds model: noKeyCount must be a whole number >= 0');
  return n;
}

export function buildPanel(listed: AllowedListResult, book: ReadonlyMap<string, BookEntry>, bookComplete: boolean, noKeyCount: number = 0): PanelModel {
  if (listed.status === 'gone') return { kind: 'no-list' };
  if (!bookComplete) return { kind: 'book-damaged' };   // the book is the problem we can name: its one line, no rows, no Repair
  if (listed.status !== 'ok') return { kind: 'unknown' };
  const listedLower = new Set(listed.fps.map((f) => f.toLowerCase()));
  const under: UnderRow[] = [];
  for (const [fp, e] of book) {
    if (allowedRowShouldExist(e.consent) && !listedLower.has(fp.toLowerCase())) under.push({ fp, label: rowLabel(e.name), name: e.name });
  }
  under.sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1 : a.fp < b.fp ? -1 : a.fp > b.fp ? 1 : 0));
  return { kind: 'ok', overCount: overListedFps(listed, book).length, under, noKeyCount: wholeCount(noKeyCount) };
}

/** "Nothing differs" (the copy owner's RELAY_ALL_MATCH) is true ONLY of a read that worked with zero over-listed, zero under-listed AND zero allowed contacts without a key: such a contact is missing from the comparison, so "exactly" would be false. */
export function showsAllMatch(m: PanelModel): boolean {
  return m.kind === 'ok' && m.overCount === 0 && m.under.length === 0 && m.noKeyCount === 0;
}
