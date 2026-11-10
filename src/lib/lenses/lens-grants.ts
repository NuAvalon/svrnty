// src/lib/lenses/lens-grants.ts
/**
 * Lenses v1.3 — the DEVICE-LOCAL recipient→lens record (contract R1/R2).
 *
 * WHICH lens each contact holds lives HERE — a separate store, never on the contact record:
 *   • `exportAll` writes every contact record into the backup. A grant kept on the contact record
 *     would ride the export — so the book lives as its own sealed record instead, which exportAll
 *     does not include. After a restore there is no record — and R2 applies: a recipient with no
 *     record is sent ZERO methods; the update is held and the sender is shown it has not gone.
 *   • The recipient→lens record AND the lens's name stay on this device. Neither is ever put in a
 *     payload, card, log or relay request: the wire payload (lens-wire.ts) carries methods, a seq
 *     and the sender fingerprint only — the lens id and name exist nowhere outside this file's
 *     store and the owner-card bag (itself device-local).
 *
 * ALSO HERE (same device-local class, same never-on-wire rule):
 *   • `capable` — a peer's "can take it" signal (R7): true once a sealed lens HELLO from them was
 *     received and MAC-verified. It is an observation about THEIR client, kept next to the grant.
 *   • `seq`     — the per-recipient send counter stamped into each payload (replay/order floor on
 *                 the receive side is `inSeq`, tracking the last seq this device accepted FROM a
 *                 sender).
 *   • `sent`    — the method KEYS (kind + label, never values) this recipient was last sent OR has
 *                 been explicitly confirmed to receive. A lens edit that would expose a new method
 *                 is a widening: it does not flow until the per-recipient confirm lands its key
 *                 here (contract review-1, the R3 gap).
 *
 * STORAGE — SEALED AT REST: the book is a ranking of the owner's relationships, so the default
 * store is the client-store's AAD-bound sealed-record path (a reserved domain id on the contact-
 * crypto path — it throws when the session is locked and never writes plaintext). An unlocked
 * phone shows all of it; that bound is stated plainly. The `LensGrantStorage` seam stays
 * injectable so the module is pure + unit-testable (node:test). A store that throws or returns
 * junk READS as EMPTY (R2: corrupt or unreadable records behave exactly like no record — zero
 * methods go, the update holds). A store that is LOCKED still throws on WRITE — never plaintext.
 */

export interface LensGrant {
  /** The lens id this recipient holds (an id in the owner-card bag). Absent ⇒ no record: zero methods go. */
  lens?: string;
  /** seq of the last 'methods' payload built for this recipient (monotonic per pair). */
  seq?: number;
  /** true once a MAC-verified HELLO from this peer was seen (R7 — the "can take it" signal). */
  capable?: boolean;
  /** Method ids (R3a — the owner's METHOD id, never the wire slot of kind+label) this recipient
   *  was last sent or was confirmed to receive. Union-only: a method once given stays disclosed
   *  (they keep what they already have), so re-exposing it later needs no new confirm. */
  sent?: string[];
  /** R7a hello budget: {v: lens-capability version sent for, at: wall-clock seconds of the last
   *  send, n: sends this version}. One hello per contact per capability version; at most ONE
   *  retry after the envelope life. The marker lives only in this sealed book (exportAll never
   *  reads it), so a restore allows one more hello per contact — stated cost. */
  hello?: { v: number; at: number; n: number };
}

export interface LensGrantBook {
  v: 1;
  grants: Record<string, LensGrant>;
  /** last 'methods' seq accepted per SENDER fingerprint — the receive-side replay floor. */
  inSeq?: Record<string, number>;
  /** Load-time marker, never persisted: the stored book was PRESENT but could not be read (corrupt
   *  or a throwing store). The send filter still fails closed (zero methods, held, no seq bump)
   *  but reports 'book-unreadable' instead of 'no-record' so the sender can see the difference. */
  unreadable?: boolean;
}

export interface LensGrantStorage {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
}

const CANONICAL_FP = /^[0-9a-f]{64}$/;
/** Bound on stored sent-keys per recipient (a wire method key is ≤ ~128 chars; the cap is far above
 *  the 32-method wire bound to absorb history — truncation only ever ADDS a confirm, never a leak). */
const SENT_MAX_KEYS = 256;
const SENT_KEY_MAX_LEN = 192;
/** A 'methods' seq more than a day ahead of the receiver's clock is refused — a wrong clock must
 *  not poison the replay floor (contract review-1 item 4). */
export const LENS_MAX_FUTURE_SEQ_S = 86400;

export function lensGrantKey(ownerFingerprint: string): string {
  return `svrnty.lens-grants.${ownerFingerprint.replace(/[^0-9a-fA-F]/g, '').toLowerCase()}`;
}

/**
 * The production store: the sealed client-store record (AAD-bound, reserved id, throws when
 * locked). Imported lazily so this module stays pure for unit tests (which always inject a store)
 * and never pulls IndexedDB into a node:test process.
 */
let _clientStore: Promise<typeof import('../identity/client-store')> | null = null;
const clientStore = () => (_clientStore ??= import('../identity/client-store'));

function sealedBookStorage(ownerFingerprint: string): LensGrantStorage {
  return {
    getItem: async () => (await clientStore()).readLensGrantBook(ownerFingerprint),
    setItem: async (_key, value) => {
      await (await clientStore()).writeLensGrantBook(ownerFingerprint, value);
    },
  };
}

function normalize(fp: unknown): string {
  const v = String(fp ?? '').toLowerCase();
  return CANONICAL_FP.test(v) ? v : '';
}

/**
 * Read the whole grant book. NEVER throws on a hostile/absent store: corrupt or unreadable JSON
 * reads as an empty book (R2 — the send filter then sends ZERO methods to every recipient, which
 * is exactly the "no record" rule applied uniformly).
 */
export async function loadLensGrants(ownerFingerprint: string, storage?: LensGrantStorage | null): Promise<LensGrantBook> {
  const store = storage === undefined ? sealedBookStorage(ownerFingerprint) : storage;
  const empty: LensGrantBook = { v: 1, grants: {}, inSeq: {} };
  if (!store) return empty;
  try {
    const raw = await store.getItem(lensGrantKey(ownerFingerprint));
    if (!raw) return empty;
    const parsed = JSON.parse(raw) as LensGrantBook;
    if (!parsed || typeof parsed !== 'object' || parsed.v !== 1 || typeof parsed.grants !== 'object' || parsed.grants === null) {
      return { ...empty, unreadable: true };
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
      const h = g.hello as { v?: unknown; at?: unknown; n?: unknown } | undefined;
      if (h && typeof h === 'object' && Number.isSafeInteger(h.v) && Number.isSafeInteger(h.at) && (h.at as number) >= 0 && Number.isSafeInteger(h.n) && (h.n as number) >= 1 && (h.n as number) <= 2) {
        row.hello = { v: h.v as number, at: h.at as number, n: h.n as number };
      }
      if (Array.isArray(g.sent)) {
        const keys = g.sent.filter((k): k is string => typeof k === 'string' && k.length > 0 && k.length <= SENT_KEY_MAX_LEN);
        if (keys.length) row.sent = [...new Set(keys)].slice(0, SENT_MAX_KEYS);
      }
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
    return { ...empty, unreadable: true };
  }
}

/**
 * Persist the book. With the default sealed store this THROWS when the session is locked —
 * retryable, and never a plaintext fallback (the reviewer's seal-at-rest requirement).
 */
export async function saveLensGrants(ownerFingerprint: string, book: LensGrantBook, storage?: LensGrantStorage | null): Promise<void> {
  const store = storage === undefined ? sealedBookStorage(ownerFingerprint) : storage;
  if (!store) return;
  await store.setItem(lensGrantKey(ownerFingerprint), JSON.stringify({ v: 1, grants: book.grants, inSeq: book.inSeq ?? {} }));
}

/** The lens id a recipient holds, or null when they have no record (R2 ⇒ zero methods go; the update holds). */
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

/** R7a: the hello retry window — one retry at most, after the envelope life (7 days). */
export const LENS_HELLO_RETRY_S = 7 * 86400;

/**
 * R7a: may a hello go to this contact now? True when no marker exists for this capability
 * version, or exactly one retry is due (marker sent ≥ LENS_HELLO_RETRY_S ago, never retried).
 * A marker with n ≥ 2 for this version means the budget is spent — send nothing until the
 * capability version changes.
 */
export function helloDue(book: LensGrantBook, recipientFingerprint: string, capVersion: number, nowSeconds: number = Math.floor(Date.now() / 1000)): boolean {
  const fp = normalize(recipientFingerprint);
  const h = fp ? book.grants[fp]?.hello : undefined;
  if (!h || h.v !== capVersion) return true;
  if (book.grants[fp]?.capable === true) return false; // R7a: their hello came back — retry only "if nothing came back"
  if (h.n >= 2) return false;
  return nowSeconds - h.at >= LENS_HELLO_RETRY_S;
}

/** R7a: record that a hello went out for this capability version (send count n, stamped at). */
export function markHelloSent(book: LensGrantBook, recipientFingerprint: string, capVersion: number, nowSeconds: number = Math.floor(Date.now() / 1000)): LensGrantBook {
  const fp = normalize(recipientFingerprint);
  if (!fp) return book;
  const prev = book.grants[fp] ?? {};
  const n = prev.hello && prev.hello.v === capVersion ? prev.hello.n + 1 : 1;
  return { ...book, grants: { ...book.grants, [fp]: { ...prev, hello: { v: capVersion, at: Math.floor(nowSeconds), n } } } };
}

/** The method ids a recipient was last sent or was confirmed to receive (empty on no record). */
export function lensSentKeys(book: LensGrantBook, recipientFingerprint: string): Set<string> {
  const fp = normalize(recipientFingerprint);
  return new Set(fp ? book.grants[fp]?.sent ?? [] : []);
}

/**
 * Union keys into the recipient's sent-or-confirmed set (contract review-1, the R3 gap fix).
 * Called by the send composer with what it actually put on the wire, and by the Revise confirm
 * path with the widening keys the owner approved. Union-only — a key once recorded stays recorded
 * (they keep what they already have); there is no un-disclose.
 */
export function recordLensKeys(book: LensGrantBook, recipientFingerprint: string, keys: Iterable<string>): LensGrantBook {
  const fp = normalize(recipientFingerprint);
  if (!fp) return book;
  const prev = book.grants[fp] ?? {};
  const merged = new Set(prev.sent ?? []);
  let changed = false;
  for (const k of keys) {
    if (typeof k === 'string' && k.length > 0 && k.length <= SENT_KEY_MAX_LEN && !merged.has(k)) {
      merged.add(k);
      changed = true;
    }
  }
  if (!changed) return book;
  const sent = [...merged].slice(0, SENT_MAX_KEYS);
  return { ...book, grants: { ...book.grants, [fp]: { ...prev, sent } } };
}

/**
 * The next per-recipient send seq (monotonic). The counter lives in this device-local book, which
 * is NOT in the backup — after a restore/clear it would restart and the receiver's strictly-greater
 * floor would class every later payload as stale, possibly forever. So the seq is
 * `max(previous + 1, whole seconds since the epoch)`: monotone per pair AND anchored to wall time,
 * so a wiped book resumes above any floor the old book produced (the receiver refuses seqs more
 * than a day ahead, so a wrong clock still can't poison the floor). Pure — the caller persists.
 */
export function nextLensSeq(
  book: LensGrantBook,
  recipientFingerprint: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): { book: LensGrantBook; seq: number } {
  const fp = normalize(recipientFingerprint);
  if (!fp) return { book, seq: 0 };
  const prev = book.grants[fp] ?? {};
  const seq = Math.max((prev.seq ?? 0) + 1, Math.floor(nowSeconds));
  return { book: { ...book, grants: { ...book.grants, [fp]: { ...prev, seq } } }, seq };
}

/**
 * Receive-side floor: accept a 'methods' payload only if its seq is STRICTLY greater than the last
 * accepted seq from this sender AND no more than a day ahead of the local clock (a wildly-future
 * seq would poison the floor — every honest later payload would read stale). Returns the updated
 * book on accept, null on stale/replay/far-future.
 */
export function acceptInSeq(
  book: LensGrantBook,
  senderFingerprint: string,
  seq: number,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): LensGrantBook | null {
  const fp = normalize(senderFingerprint);
  if (!fp || !Number.isSafeInteger(seq) || seq < 0) return null;
  if (seq > Math.floor(nowSeconds) + LENS_MAX_FUTURE_SEQ_S) return null;
  const last = book.inSeq?.[fp] ?? -1;
  if (seq <= last) return null;
  return { ...book, inSeq: { ...(book.inSeq ?? {}), [fp]: seq } };
}
