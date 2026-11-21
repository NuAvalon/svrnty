// src/components/relay/relay-holds-port.ts
// The "what the relay holds about you" panel's PORT: everything the screen is given. It reads the last list the revoke check kept (the panel makes NO request of its own), the owner's book, and asks the existing
// check to read again. The real functions are reached only through one injectable seam (PortIo) so the panel's logic runs in node; the screen and the browser spec use realPortIo.
//   - lastRead: the last read of the relay's list, from memory (cleared on lock, logout and identity switch, so a locked device has nothing to show: that is "unknown", never an empty list).
//   - the book is read when it is asked for, every time: Repair's check at the press must see the book as it is NOW.
//   - refresh: the existing tick (runAllowedRevokeTick), the one request path; it never throws.
//   - Repair's add goes through reconcileAllowedOnConsentChange with an ALLOWING consent: one signed ADD, then the rate-limited check pays owed revokes (the person just added is not one of them) and re-reads the list.
import { getAllContacts, getContactBookIntegrity } from '@/lib/identity/client-store';
import { consentFromRecord } from '@/lib/contacts/share-settings-patch';
import { allowedRowShouldExist, type AllowedListResult, type PeerConsent } from '@/lib/sync/allowed-sync';
import { lastListRead } from '@/lib/sync/last-list-read';
import { reconcileAllowedOnConsentChange, runAllowedRevokeTick } from '@/lib/sync/reconcile-allowed-hook';
import { buildPanel, type BookEntry, type PanelModel } from './relay-holds-model';
import type { RepairDeps } from './relay-holds-repair';

export interface BookRecord { fingerprint: string; name: string; consent: PeerConsent }

export interface PortIo {
  lastRead(): { listed: AllowedListResult; at: number } | undefined;
  records(): Promise<BookRecord[]>;
  /** is the book WHOLE (the integrity flag is ok)? Throws if the flag cannot be read. */
  bookWhole(): Promise<boolean>;
  tick(): Promise<void>;
  /** the signed ADD for one contact with the consent just read (true only for a confirmed one) */
  add(fp: string, consent: PeerConsent): Promise<boolean>;
  nowMs(): number;
}

export interface RelayHoldsPort {
  read(): { listed: AllowedListResult; at: number } | undefined;
  book(): Promise<{ entries: Map<string, BookEntry>; complete: boolean; noKeyCount: number }>;
  refresh(): Promise<void>;
  repair: RepairDeps;
  nowMs(): number;
}

/** Two records for one fingerprint follow the revoke check's own rule: the row is kept if EITHER allows it. The name is the allowing record's, else the first one that has a name. */
export function mergeBook(records: ReadonlyArray<BookRecord>): Map<string, BookEntry> {
  const book = new Map<string, BookEntry>();
  for (const r of records) {
    if (!r.fingerprint) continue;
    const name = typeof r.name === 'string' && r.name.trim() ? r.name : null;
    const held = book.get(r.fingerprint);
    if (!held) { book.set(r.fingerprint, { name, consent: r.consent }); continue; }
    if (!allowedRowShouldExist(held.consent) && allowedRowShouldExist(r.consent)) { book.set(r.fingerprint, { name: name ?? held.name, consent: r.consent }); continue; }
    if (held.name === null && name !== null) book.set(r.fingerprint, { name, consent: held.consent });
  }
  return book;
}

/** Contacts the book ALLOWS who have no fingerprint yet: the revoke check's book skips them (they cannot be listed), so the panel counts them itself. A blocked or closed one is nothing owed and is not counted. */
export function countNoKey(records: ReadonlyArray<BookRecord>): number {
  let n = 0;
  for (const r of records) if (!r.fingerprint && allowedRowShouldExist(r.consent)) n++;
  return n;
}

export function makeRelayHoldsPort(ownerFp: string, io: PortIo = realPortIo(ownerFp)): RelayHoldsPort {
  return {
    read: () => io.lastRead(),
    book: async () => { const records = await io.records(); return { entries: mergeBook(records), complete: await io.bookWhole(), noKeyCount: countNoKey(records) }; },
    refresh: async () => { try { await io.tick(); } catch { /* best effort: the next press or tick tries again */ } },
    repair: {
      bookWhole: () => io.bookWhole(),   // asked for at every press, never kept from the draw
      consentOf: async (fp) => mergeBook(await io.records()).get(fp)?.consent ?? null,
      reconcileAdd: (fp, consent) => io.add(fp, consent),
    },
    nowMs: () => io.nowMs(),
  };
}

/** What the screen shows: the model from the last read and the book NOW, and when that read was made. Nothing here makes a request. */
export async function loadPanel(port: RelayHoldsPort): Promise<{ model: PanelModel; at: number | undefined }> {
  const r = port.read();
  if (!r) return { model: { kind: 'unknown' }, at: undefined };             // never read, or forgotten on lock: the panel can only say it could not check
  let book: { entries: Map<string, BookEntry>; complete: boolean; noKeyCount: number };
  try { book = await port.book(); } catch { return { model: { kind: 'unknown' }, at: r.at }; }   // a book or flag that cannot be READ is "could not check", not "damaged"
  return { model: buildPanel(r.listed, book.entries, book.complete, book.noKeyCount), at: r.at };
}

export function realPortIo(ownerFp: string): PortIo {
  return {
    lastRead: () => { const l = lastListRead(ownerFp); return l ? { listed: l.result, at: l.at } : undefined; },
    records: async () => (await getAllContacts(ownerFp)).map((c) => ({ fingerprint: c.fingerprint, name: c.name, consent: consentFromRecord(c) })),   // key-less contacts are kept here: the panel counts them (countNoKey); mergeBook skips them
    bookWhole: async () => (await getContactBookIntegrity(ownerFp)) === 'ok',
    tick: () => runAllowedRevokeTick(ownerFp),
    add: async (fp, consent) => {
      const r = await reconcileAllowedOnConsentChange({ ownerFp, senderFp: fp, consent });
      return 'action' in r && r.action === 'add' && r.ok === true;
    },
    nowMs: () => Date.now(),
  };
}
