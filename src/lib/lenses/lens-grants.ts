// src/lib/lenses/lens-grants.ts
/**
 * Lenses v1.3 — the DEVICE-LOCAL recipient→lens record (contract R1/R2).
 *
 * WHICH lens each contact holds lives HERE — a separate store, never on the contact record:
 *   • `exportAll` writes every contact record into the backup. A grant kept on the contact record
 *     would ride the export — so it lives under its own localStorage namespace instead, which
 *     exportAll does not include (it pulls identity/contacts/keys only). After a restore there is
 *     no record — and R2 applies: a recipient with no record gets the narrowest face (the default
 *     lens), never more.
 *   • The recipient→lens record AND the lens's name stay on this device. Neither is ever put in a
 *     payload, card, log or relay request: the wire payload (lens-wire.ts) carries methods, a seq
 *     and the sender fingerprint only — the lens id and name exist nowhere outside this file's
 *     store and the owner-card bag (itself device-local).
 *
 * ALSO HERE (same device-local class, same never-on-wire rule):
 *   • `capable` — a peer's "can take it" signal (R7): true once a sealed lens HELLO from them was
 *     received and MAC-verified. It is an observation about THEIR client, kept next to the grant.
 *   • `seq`    — the per-recipient send counter stamped into each payload (replay/order floor on
 *     the receive side is `inSeq`, tracking the last seq this device accepted FROM a sender).
 *
 * STORAGE: localStorage key `svrnty.lens-grants.<ownerFp>` — injectable `LensGrantStorage` so the
 * module is pure + unit-testable (node:test). A store that throws or returns junk reads as EMPTY
 * (R2: corrupt or unreadable records behave exactly like no record — the narrowest face).
 */

export interface LensGrant {
  /** The lens id this recipient holds (an id in the owner-card bag). Absent ⇒ narrowest face. */
  lens?: string;
  /** seq of the last 'methods' payload built for this recipient (monotonic per pair). */
  seq?: number;
  /** true once a MAC-verified HELLO from this peer was seen (R7 — the "can take it" signal). */
  capable?: boolean;
}

export interface LensGrantBook {
  v: 1;
  grants: Record<string, LensGrant>;
  /** last 'methods' seq accepted per SENDER fingerprint — the receive-side replay floor. */
  inSeq?: Record<string, number>;
}

export interface LensGrantStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

const CANONICAL_FP = /^[0-9a-f]{64}$/;

export function lensGrantKey(ownerFingerprint: string): string {
  return `svrnty.lens-grants.${ownerFingerprint.replace(/[^0-9a-fA-F]/g, '').toLowerCase()}`;
}

function defaultStorage(): LensGrantStorage | null {
  return typeof window === 'undefined' ? null : window.localStorage;
}

function normalize(fp: unknown): string {
  const v = String(fp ?? '').toLowerCase();
  return CANONICAL_FP.test(v) ? v : '';
}

/**
 * Read the whole grant book. NEVER throws on a hostile/absent store: corrupt or unreadable JSON
 * reads as an empty book (R2 — the send filter then fails closed to the narrowest face for every
 * recipient, which is exactly the "no record" rule applied uniformly).
 */
export function loadLensGrants(ownerFingerprint: string, storage?: LensGrantStorage | null): LensGrantBook {
  const store = storage === undefined ? defaultStorage() : storage;
  const empty: LensGrantBook = { v: 1, grants: {}, inSeq: {} };
  if (!store) return empty;
  try {
    const raw = store.getItem(lensGrantKey(ownerFingerprint));
    if (!raw) return empty;
    const parsed = JSON.parse(raw) as LensGrantBook;
    if (!parsed || typeof parsed !== 'object' || parsed.v !== 1 || typeof parsed.grants !== 'object' || parsed.grants === null) {
      return empty;
    }
    // Sanitize each row: unknown keys are dropped; a non-canonical fingerprint key is dropped.
    const grants: Record<string, LensGrant> = {};
    for (const [fp, g] of Object.entries(parsed.grants)) {
      const nfp = normalize(fp);
      if (!nfp || !g || typeof g !== 'object') continue;
      const row: LensGrant = {};
      if (typeof g.lens === 'string' && g.lens.length > 0 && g.lens.length <= 128) row.lens = g.lens;
      if (Number.isSafeInteger(g.seq) && (g.seq as number) >= 0) row.seq = g.seq;
      if (g.capable === true) row.capable = true;
      grants[nfp] = row;
    }
    const inSeq: Record<string, number> = {};
    if (parsed.inSeq && typeof parsed.inSeq === 'object') {
      for (const [fp, s] of Object.entries(parsed.inSeq)) {
        const nfp = normalize(fp);
        if (nfp && Number.isSafeInteger(s) && (s as number) >= 0) inSeq[nfp] = s as number;
      }
    }
    return { v: 1, grants, inSeq };
  } catch {
    return empty;
  }
}

export function saveLensGrants(ownerFingerprint: string, book: LensGrantBook, storage?: LensGrantStorage | null): void {
  const store = storage === undefined ? defaultStorage() : storage;
  if (!store) return;
  store.setItem(lensGrantKey(ownerFingerprint), JSON.stringify({ v: 1, grants: book.grants, inSeq: book.inSeq ?? {} }));
}

/** The lens id a recipient holds, or null when they have no record (R2 ⇒ caller gives the narrowest face). */
export function lensForRecipient(book: LensGrantBook, recipientFingerprint: string): string | null {
  const fp = normalize(recipientFingerprint);
  if (!fp) return null;
  return book.grants[fp]?.lens ?? null;
}

/** Record (or clear) which lens a recipient holds. Pure on the book — the caller persists. */
export function setRecipientLens(book: LensGrantBook, recipientFingerprint: string, lensId: string | null): LensGrantBook {
  const fp = normalize(recipientFingerprint);
  if (!fp) return book;
  const grants = { ...book.grants };
  const prev = grants[fp] ?? {};
  if (lensId === null) {
    if (prev.lens === undefined) return book;
    const { lens: _drop, ...rest } = prev;
    if (Object.keys(rest).length === 0) delete grants[fp];
    else grants[fp] = rest;
  } else {
    grants[fp] = { ...prev, lens: lensId };
  }
  return { ...book, grants };
}

/** R7: mark a peer as lens-capable (a MAC-verified HELLO was seen from them). */
export function markPeerCapable(book: LensGrantBook, peerFingerprint: string): LensGrantBook {
  const fp = normalize(peerFingerprint);
  if (!fp) return book;
  const prev = book.grants[fp] ?? {};
  if (prev.capable === true) return book;
  return { ...book, grants: { ...book.grants, [fp]: { ...prev, capable: true } } };
}

export function peerIsCapable(book: LensGrantBook, peerFingerprint: string): boolean {
  const fp = normalize(peerFingerprint);
  return !!fp && book.grants[fp]?.capable === true;
}

/** The next per-recipient send seq (monotonic). Pure — the caller persists the bumped book. */
export function nextLensSeq(book: LensGrantBook, recipientFingerprint: string): { book: LensGrantBook; seq: number } {
  const fp = normalize(recipientFingerprint);
  if (!fp) return { book, seq: 0 };
  const prev = book.grants[fp] ?? {};
  const seq = (prev.seq ?? 0) + 1;
  return { book: { ...book, grants: { ...book.grants, [fp]: { ...prev, seq } } }, seq };
}

/**
 * Receive-side floor: accept a 'methods' payload only if its seq is STRICTLY greater than the last
 * accepted seq from this sender. Returns the updated book on accept, null on stale/replay.
 */
export function acceptInSeq(book: LensGrantBook, senderFingerprint: string, seq: number): LensGrantBook | null {
  const fp = normalize(senderFingerprint);
  if (!fp || !Number.isSafeInteger(seq) || seq < 0) return null;
  const last = book.inSeq?.[fp] ?? -1;
  if (seq <= last) return null;
  return { ...book, inSeq: { ...(book.inSeq ?? {}), [fp]: seq } };
}
