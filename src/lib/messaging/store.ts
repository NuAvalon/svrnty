// src/lib/messaging/store.ts
// Separate IndexedDB for notes (Phase 3.2) — NOT the svrnty vault/book database.
// Bodies encrypted at rest with a notes-session AES-GCM key (passphrase-derived).

import type { NoteRecord, NoteThread, RingChannel } from './types';
import { clearedHeld, clearedHeldNote, heldSince, heldSweepAction, isHeldNote, isHeldThread, noteExpired, stampedHeldNote, visibleThreads, type HeldSweepAction } from './held-note';
import type { RatchetSnapshot } from '@/lib/crypto/message-ratchet';
import { onSessionLock } from '@/lib/identity/client-store';
import { DbUpgradeBlocked } from '@/lib/db-upgrade-blocked';
import { isAllowedSettingsPrefix, isAllowedSettingsRowKey } from './settings-row-keys';
import { needsLastActivityHeal, healedLastActivity, activityMs } from './thread-activity';
import { HELD_COUNTS_KEY, applyChange, countFrom, countsFromNotes, heldInboundSender, parseHeldCounts, sealedShape, type CountFallback, type HeldCounts, type HeldCountsRead } from './held-counts';

const DB_NAME = 'svrnty-notes';
const DB_VERSION = 2;
const PBKDF2_ITERATIONS = 600_000;

let _db: IDBDatabase | null = null;
let _notesKey: CryptoKey | null = null;
let _notesSalt: Uint8Array | null = null;
// Bumped on every lock/identity-switch (via lockNotesStore). An in-flight initNotesStore that started
// in an older generation MUST NOT assign the key — else a notes-init started before a lock/switch can
// finish AFTER it and RESTORE the old key (Codex P1 async-init race, 10/10). The check→assign in
// initNotesStore is synchronous (no await between), so it is TOCTOU-free in JS's single thread.
let _notesGeneration = 0;
// Per-identity DB name (P1#1 owner-scope): notes live in `svrnty-notes-<ownerFingerprint>`, so two
// identities — even with the SAME unlock passphrase — get SEPARATE IndexedDBs (each with its own salt →
// distinct AES keys → no cross-identity read, and no shared-DB structural residue). Set by
// initNotesStore; cleared (and the handle closed) on lock/switch so a switch re-opens the NEXT
// identity's DB, never the cached previous one. Legacy single-DB 'svrnty-notes' notes are PRESERVED
// (never opened by this scheme) — orphaned, not deleted.
let _notesDbName: string | null = null;
// The owner the CURRENTLY UNLOCKED notes key/DB belong to. Set together with _notesKey, cleared on lock/switch.
// Lets a caller assert "unlocked FOR this identity" (not just "unlocked") before writing — N10 cross-tab hardening.
let _notesOwner: string | null = null;

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function openDb(): Promise<IDBDatabase> {
  if (_db) return Promise.resolve(_db);
  const dbName = _notesDbName;
  if (!dbName) {
    return Promise.reject(
      new Error('Notes store not initialized — call initNotesStore(passphrase, ownerFingerprint) first'),
    );
  }
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('threads')) {
        const threads = db.createObjectStore('threads', { keyPath: 'thread_id' });
        threads.createIndex('last_activity_at', 'last_activity_at');
      }
      if (!db.objectStoreNames.contains('notes')) {
        const notes = db.createObjectStore('notes', { keyPath: 'note_id' });
        notes.createIndex('thread_id', 'thread_id', { unique: false });
      }
      if (!db.objectStoreNames.contains('ring_channels')) {
        db.createObjectStore('ring_channels', { keyPath: 'channel_id' });
      }
      if (!db.objectStoreNames.contains('settings')) {
        db.createObjectStore('settings', { keyPath: 'key' });
      }
      if (!db.objectStoreNames.contains('ratchet_sessions')) {
        db.createObjectStore('ratchet_sessions', { keyPath: 'peer_fingerprint' });
      }
    };
    req.onsuccess = () => {
      _db = req.result;
      resolve(_db);
    };
    req.onerror = () => reject(req.error);
    // A version upgrade held up by another open tab must not leave open() waiting silently: it rejects with the coded error every helper maps to one sentence.
    req.onblocked = () => reject(new DbUpgradeBlocked());
  });
}

async function txGet<T>(store: string, key: string): Promise<T | undefined> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error);
  });
}

async function txPut(store: string, value: unknown): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function txGetAll<T>(store: string): Promise<T[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).getAll();
    req.onsuccess = () => resolve((req.result as T[]) || []);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Compare-and-swap on the row's ciphertext, as ONE readwrite transaction: get the row, and put the new one ONLY IF the stored blob is still exactly the
 * one the caller decrypted (same iv AND same ciphertext). Every encryptJson draws a fresh iv, so ANY write since the caller's read (a delete, an
 * arriving note writing its own time, a rename) makes the compare fail and nothing is written; a plain "put if present" would still write back the
 * whole record decrypted before the await and roll such a write back. There is no await between the get and the put (both run inside onsuccess), and
 * IndexedDB serialises readwrite transactions on a store. Returns whether it wrote. Callers must encrypt BEFORE calling: WebCrypto cannot run inside an
 * IndexedDB transaction without the transaction auto-committing.
 */
async function txPutIfUnchanged(store: string, key: string, expected: EncryptedBlob, value: unknown): Promise<boolean> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    const os = tx.objectStore(store);
    let wrote = false;
    const existing = os.get(key);
    existing.onsuccess = () => {
      const current = existing.result as { enc?: EncryptedBlob } | undefined;
      if (current?.enc && current.enc.iv === expected.iv && current.enc.ciphertext === expected.ciphertext) {
        os.put(value);
        wrote = true;
      }
    };
    tx.oncomplete = () => resolve(wrote);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

/**
 * Compare-and-swap over SEVERAL rows, as ONE readwrite transaction: every row in `expects` must still be exactly the blob the caller read (same iv AND same ciphertext, as
 * txPutIfUnchanged; `enc: null` = the row must still be ABSENT), and only then are all of `puts` written. If any one moved, nothing is written and the answer is false, so the caller
 * reads again and decides again. This is how a note row and the held-count row change together: a sealed row cannot be read, changed and put inside one transaction (awaiting
 * WebCrypto auto-commits it), so the caller decrypts, decides and encrypts BEFORE this, and this only checks and writes. A settings row may only be touched under an allowed key, so
 * this can never reach 'notes_encryption_salt'.
 */
async function txCommitIfUnchanged(
  expects: Array<{ store: string; key: string; enc: EncryptedBlob | null }>,
  puts: Array<{ store: string; value: unknown }>,
  deletes: Array<{ store: 'notes'; key: string }> = [],
): Promise<boolean> {
  if (expects.length === 0) throw new Error('txCommitIfUnchanged needs at least one row to compare');
  for (const e of expects) if (e.store === 'settings' && !isAllowedSettingsRowKey(e.key)) throw new Error('settings row key not allowed');
  for (const p of puts) if (p.store === 'settings' && !isAllowedSettingsRowKey((p.value as { key?: unknown }).key)) throw new Error('settings row key not allowed');
  const db = await openDb();
  const stores = [...new Set([...expects.map((e) => e.store), ...puts.map((p) => p.store), ...deletes.map((d) => d.store)])];
  return new Promise((resolve, reject) => {
    const tx = db.transaction(stores, 'readwrite');
    let wrote = false;
    let pending = expects.length;
    let allSame = true;
    for (const e of expects) {
      const req = tx.objectStore(e.store).get(e.key);
      req.onsuccess = () => {
        const cur = req.result as { enc?: EncryptedBlob } | undefined;
        const same = e.enc === null ? cur === undefined : !!cur?.enc && cur.enc.iv === e.enc.iv && cur.enc.ciphertext === e.enc.ciphertext;
        if (!same) allSame = false;
        // No await anywhere here: the last read answers, and the writes go out in the same callback, inside the same transaction.
        if (--pending === 0 && allSame) {
          for (const p of puts) tx.objectStore(p.store).put(p.value);
          for (const d of deletes) tx.objectStore(d.store).delete(d.key);
          wrote = true;
        }
      };
    }
    tx.oncomplete = () => resolve(wrote);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

async function txDelete(store: string, key: string): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function deriveNotesKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

interface EncryptedBlob {
  enc_version: 1;
  iv: string;
  ciphertext: string;
}

async function encryptJson(data: unknown): Promise<EncryptedBlob> {
  if (!_notesKey) throw new Error('Notes store locked — call initNotesStore() first');
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const plaintext = new TextEncoder().encode(JSON.stringify(data));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, _notesKey, plaintext),
  );
  return { enc_version: 1, iv: toBase64(iv), ciphertext: toBase64(ciphertext) };
}

async function decryptJson<T>(blob: EncryptedBlob): Promise<T> {
  if (!_notesKey) throw new Error('Notes store locked — call initNotesStore() first');
  const iv = fromBase64(blob.iv);
  const ciphertext = fromBase64(blob.ciphertext);
  const decrypted = new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, _notesKey, ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(decrypted)) as T;
}

/** Unlock the notes DB with the same unlock passphrase the vault uses (separate salt). */
export async function initNotesStore(passphrase: string, ownerFingerprint: string, opts?: { reconcile?: boolean }): Promise<void> {
  if (!ownerFingerprint) {
    throw new Error('initNotesStore requires an ownerFingerprint (P1#1 owner-scope — per-identity DB)');
  }
  const gen = _notesGeneration; // capture at start; a lock/switch mid-init bumps this → refuse the stale key below
  _notesDbName = `${DB_NAME}-${ownerFingerprint}`; // per-identity DB (owner-scope) — set BEFORE openDb
  await openDb();
  const setting = await txGet<{ key: string; value: string }>('settings', 'notes_encryption_salt');
  let salt: Uint8Array;
  if (setting?.value) {
    salt = fromBase64(setting.value);
  } else {
    salt = new Uint8Array(32);
    crypto.getRandomValues(salt);
    await txPut('settings', { key: 'notes_encryption_salt', value: toBase64(salt) });
  }
  const key = await deriveNotesKey(passphrase, salt);
  // P1 async-init race: if a lock/identity-switch happened while we were awaiting IndexedDB + key
  // derivation, DO NOT restore the key. No await between this check and the assignment → the clear
  // from lockNotesStore cannot interleave back in after the check passes.
  if (gen !== _notesGeneration) return;
  _notesKey = key;
  _notesSalt = salt;
  _notesOwner = ownerFingerprint;
  // Off the receive path: put the held-count row right from the notes (it also CREATES the row for everyone, so its presence says nothing about who is frozen).
  if (opts?.reconcile !== false) scheduleHeldMaintenance();
}

export function isNotesStoreUnlocked(): boolean {
  return _notesKey !== null;
}

/** Owner fingerprint the unlocked notes store was opened for (null while locked). */
export function notesStoreOwner(): string | null {
  return _notesKey !== null ? _notesOwner : null;
}

export function lockNotesStore(): void {
  _notesGeneration += 1; // invalidate any in-flight initNotesStore (async-init race, Codex P1 10/10)
  _notesKey = null;
  _notesSalt = null;
  _notesOwner = null;
  // Owner-scope: close + drop the per-identity DB handle so a switch re-opens the NEXT identity's DB,
  // never the cached previous one (else B could read A's DB through the stale _db handle).
  if (_db) {
    _db.close();
    _db = null;
  }
  _notesDbName = null;
}

// P1#1 (cross-identity notes-leak): drop the notes key on every session-lock AND identity-switch.
// client-store fires its session-lock hooks from BOTH lockSession and setActiveFingerprint (the true
// switch chokepoint); we register INWARD (messaging → client-store) so identity-core never imports
// this feature module. Runs once when this module first loads (notes-init at unlock) — before any
// lock/switch; if notes were never opened there is no _notesKey to leak.
onSessionLock(lockNotesStore);

type ThreadRow = { thread_id: string; enc: EncryptedBlob };
type NoteRow = { note_id: string; thread_id: string; enc: EncryptedBlob };
type RingRow = { channel_id: string; enc: EncryptedBlob };

export async function putThread(thread: NoteThread): Promise<void> {
  const enc = await encryptJson(thread);
  await txPut('threads', { thread_id: thread.thread_id, enc } satisfies ThreadRow);
}

/** The ONLY thread reader that returns held threads (a thread that exists because of held notes). Its callers are pinned by a test; every other reader gets listThreads. */
export async function listThreadsIncludingHeld(): Promise<NoteThread[]> {
  return readThreads();
}

export async function listThreads(): Promise<NoteThread[]> {
  return visibleThreads(await readThreads());
}

async function readThreads(): Promise<NoteThread[]> {
  const rows = await txGetAll<ThreadRow>('threads');
  const out: NoteThread[] = [];
  for (const row of rows) {
    try {
      out.push(await decryptJson<NoteThread>(row.enc));
    } catch {
      // corrupt / wrong key — skip
    }
  }
  const now = Date.now();
  const healed: NoteThread[] = [];
  for (const thread of out) healed.push(await healPinnedThread(thread, now));
  return healed.sort((a, b) => activityMs(b.last_activity_at, now) - activityMs(a.last_activity_at, now));
}

/**
 * A thread pinned in the future by an older rule gets a fixed, lower last_activity_at written ONCE (thread-activity.ts: healedLastActivity), after which
 * ordinary activity overtakes it. It only ever lowers a value. The row is re-read first: a note that arrived since this list was read has already
 * written its own clamped time, and then there is nothing to heal and nothing to overwrite. If a note lands between that re-read and the write, the
 * stale value can win briefly; the next note in the thread writes its own clamped time and corrects it. Never throws: on any failure the thread comes back
 * as it was read, and readLastActivity still bounds how it sorts.
 */
async function healPinnedThread(thread: NoteThread, nowMs: number): Promise<NoteThread> {
  if (!needsLastActivityHeal(thread.last_activity_at, nowMs)) return thread;
  try {
    const row = await txGet<ThreadRow>('threads', thread.thread_id);
    // The row is GONE: the conversation was deleted after this list was read (deleteThread removes the notes first and the row last). A missing row is
    // never written: the thread stays in THIS list as read and is gone on the next load. (A change that lands AFTER this check is caught by the
    // compare-and-swap below.)
    if (!row) return thread;
    const current = await decryptJson<NoteThread>(row.enc);
    let sentAts: string[] | null = null;
    try {
      sentAts = (await listNotesForThread(thread.thread_id)).map((n) => n.sent_at);
    } catch {
      sentAts = null; // notes not at hand: healedLastActivity falls back to now + slack
    }
    const value = healedLastActivity(current.last_activity_at, sentAts, nowMs);
    if (value === null) return current;
    const next: NoteThread = { ...current, last_activity_at: value };
    // Encrypt first, then compare-and-swap in ONE transaction against the ciphertext we decrypted: the row can change between the re-read above and this
    // write (a delete, or a note writing its own time), and a plain put would bring a deleted conversation back or roll that write back. If anything
    // wrote since, the heal is skipped; the next load re-checks, and readLastActivity bounds the sort meanwhile.
    const enc = await encryptJson(next);
    const wrote = await txPutIfUnchanged('threads', thread.thread_id, row.enc, { thread_id: thread.thread_id, enc } satisfies ThreadRow);
    return wrote ? next : thread;
  } catch {
    return thread;
  }
}

const NOTE_WRITE_ATTEMPTS = 8;

// Note writes in THIS tab go one at a time. Every held write changes the one count row, and each commit is compare-and-swap against the blob it read, so writers racing inside one tab would
// invalidate each other and only one would win per round (a burst of 50 would exhaust its attempts and throw). Across tabs the compare-and-swap is what keeps it right, and contention there is rare.
let _noteWriteTail: Promise<unknown> = Promise.resolve();
function serializeNoteWrite<T>(run: () => Promise<T>): Promise<T> {
  const mine = _noteWriteTail.then(run, run);
  _noteWriteTail = mine.catch(() => {});   // a failed write never blocks the next one
  return mine;
}

/**
 * THE one write of a note row. If the write changes what counts as a held inbound note (a new held note, a held row replaced by an ordinary one, or the other way round), the
 * held-count row changes IN THE SAME TRANSACTION (held-counts.ts says why that row exists); every other write touches only the note row. Encrypt and decide BEFORE the
 * transaction (WebCrypto cannot run inside one), then commit with a compare-and-swap over the rows that were read (the prior note row, and the count row when it is involved):
 * if either moved meanwhile nothing is written and the whole decision is made again, a bounded number of times, then the write throws (the accept retries) and never leaves a note without
 * its count. A count row that is absent, dirty or unreadable cannot be adjusted, so it is rewritten as DIRTY (a fresh blob, so a reconcile in flight sees it move) and a reconcile is
 * scheduled; a prior row that cannot be decrypted may have been held, so the count row goes dirty then too. Returns whether THIS write created the row (existing and unreadable rows
 * both count as existing, so no receipt for them).
 */
async function writeNote(note: NoteRecord): Promise<boolean> {
  const after = heldInboundSender(note);
  for (let attempt = 0; attempt < NOTE_WRITE_ATTEMPTS; attempt++) {
    const priorRow = await txGet<NoteRow>('notes', note.note_id);
    let before: string | null = null;
    let priorUnreadable = false;
    if (priorRow) {
      try {
        before = heldInboundSender(await decryptJson<NoteRecord>(priorRow.enc));
      } catch {
        priorUnreadable = true;
      }
    }
    const enc = await encryptJson(note);
    const expects: Array<{ store: string; key: string; enc: EncryptedBlob | null }> = [{ store: 'notes', key: note.note_id, enc: priorRow?.enc ?? null }];
    const puts: Array<{ store: string; value: unknown }> = [{ store: 'notes', value: { note_id: note.note_id, thread_id: note.thread_id, enc } satisfies NoteRow }];
    let wroteDirty = false;
    if (before !== after || priorUnreadable) {
      const counter = await readHeldCountsRow();
      expects.push({ store: 'settings', key: HELD_COUNTS_KEY, enc: counter.enc });
      const usable = !priorUnreadable && counter.read !== 'absent' && counter.read !== null && counter.read.state === 'ok' ? counter.read.counts : null;
      const next: HeldCountsRead = usable ? { state: 'ok', counts: applyChange(usable, before, after) } : { state: 'dirty' };
      wroteDirty = usable === null;
      puts.push({ store: 'settings', value: { key: HELD_COUNTS_KEY, enc: await encryptJson(sealedShape(next)) } satisfies SettingsRow });
    }
    if (await txCommitIfUnchanged(expects, puts)) {
      if (wroteDirty) scheduleHeldCountsReconcile();
      return priorRow === undefined;
    }
    await new Promise((r) => setTimeout(r, Math.floor(Math.random() * 4 * (attempt + 1))));   // another tab (or a reconcile) moved a row: back off a little, then decide again
  }
  throw new Error('note write kept losing the race: retry');
}

export async function putNote(note: NoteRecord): Promise<void> {
  await serializeNoteWrite(() => writeNote(note));
}

/**
 * putNote that also says whether THIS write created the row. The existence check is part of the same compare-and-swap that writes it (the prior row must still be absent), so two tabs
 * delivering the same blob get exactly one `true`. An existing row is overwritten, as before; only the answer is new. A row that exists but cannot be decrypted counts as existing
 * (so no receipt for it), the safe side.
 */
export async function putNoteReportingCreated(note: NoteRecord): Promise<boolean> {
  return serializeNoteWrite(() => writeNote(note));
}

/** Fetch one stored note by id (any thread), or null if absent/corrupt. Used by the delivery-receipt
 *  consume seam to recover the OUTBOUND note's expected nonce + recipient before verifying a receipt. */
export async function getNote(noteId: string): Promise<NoteRecord | null> {
  const row = await txGet<NoteRow>('notes', noteId);
  if (!row) return null;
  try {
    return await decryptJson<NoteRecord>(row.enc);
  } catch {
    return null; // wrong key / corrupt — treat as absent (fail-safe: no receipt match ⇒ no false delivered)
  }
}

/** The ONLY note reader that returns held notes. Its callers are pinned by a test; every other reader gets listNotesForThread. */
export async function listNotesIncludingHeld(threadId: string): Promise<NoteRecord[]> {
  return readNotesForThread(threadId, true);
}

export async function listNotesForThread(threadId: string): Promise<NoteRecord[]> {
  return readNotesForThread(threadId, false);
}

async function readNotesForThread(threadId: string, includeHeld: boolean): Promise<NoteRecord[]> {
  const db = await openDb();
  const rows: NoteRow[] = await new Promise((resolve, reject) => {
    const tx = db.transaction('notes', 'readonly');
    const idx = tx.objectStore('notes').index('thread_id');
    const req = idx.getAll(threadId);
    req.onsuccess = () => resolve((req.result as NoteRow[]) || []);
    req.onerror = () => reject(req.error);
  });
  const out: NoteRecord[] = [];
  const now = Date.now();
  for (const row of rows) {
    try {
      const note = await decryptJson<NoteRecord>(row.enc);
      if (noteExpired(note, now)) {   // a HELD note never expires on the sender's retention (the sender chooses it)
        await txDelete('notes', note.note_id);
        continue;
      }
      if (!includeHeld && isHeldNote(note)) continue;
      out.push(note);
    } catch {
      // skip
    }
  }
  return out.sort((a, b) => a.sent_at.localeCompare(b.sent_at));
}

/**
 * sent_at of every INBOUND note already stored from this contact, across all threads (#720 R5b replay guard: a peer's new first frame may replace our
 * session only if its signed time is newer than all of these). The fingerprint compare ignores case, so a differently-cased copy still counts (the
 * stricter direction: it can only make the guard refuse more).
 */
export async function listInboundSentAtFrom(peerFingerprint: string): Promise<string[]> {
  const want = peerFingerprint.toLowerCase();
  const out: string[] = [];
  for (const t of await listThreadsIncludingHeld()) {   // the replay guard must see HELD notes too, or a replayed old first frame could replace the session
    for (const n of await listNotesIncludingHeld(t.thread_id)) {
      if (n.direction === 'inbound' && n.from_fingerprint.toLowerCase() === want) out.push(n.sent_at);
    }
  }
  return out;
}

/** How many notes from this sender are HELD right now (the per-sender cap check). The fingerprint compare ignores case, like the replay guard. */
export async function countHeldFrom(peerFingerprint: string): Promise<number> {
  const want = peerFingerprint.toLowerCase();
  let count = 0;
  for (const t of await listThreadsIncludingHeld()) {
    for (const n of await listNotesIncludingHeld(t.thread_id)) {
      if (heldInboundSender(n) === want) count++;   // the ONE rule (held-counts.ts), shared with the count row's write path and its reconcile
    }
  }
  return count;
}

/** The count row as stored: its blob (null = absent) and what it says. A row that cannot be decrypted or understood reads as null ("unreadable"), never as a number. Throws while locked. */
async function readHeldCountsRow(): Promise<{ enc: EncryptedBlob | null; read: HeldCountsRead | 'absent' }> {
  requireUnlocked();
  const row = await txGet<SettingsRow>('settings', HELD_COUNTS_KEY);
  if (!row?.enc) return { enc: null, read: 'absent' };
  try {
    return { enc: row.enc, read: parseHeldCounts(await decryptJson<unknown>(row.enc)) };
  } catch {
    return { enc: row.enc, read: null };
  }
}

/** One sender's held count from the count row: a number, or the reason the row could not be used. Reads one row and decrypts it; never walks the notes. */
export async function readHeldCount(sender: string): Promise<{ count: number } | { fallback: CountFallback }> {
  return countFrom((await readHeldCountsRow()).read, sender);
}

const _warnedFallback = new Set<CountFallback>();

/**
 * The per-arrival cap check. Answers from the count row (one read). If the row cannot be used (absent, dirty, unreadable) it falls back to the full scan for THIS decision, which is slow
 * but right: never to 0 (that would bypass the cap) and never to "full" (that would refuse a person's evidence early). The reason is logged (once per page load per reason) and a
 * reconcile is scheduled, off this path, to put the row right. A store that cannot be read THROWS (the accept retries), exactly like the scan.
 */
export async function countHeldFromFast(sender: string): Promise<number> {
  const got = await readHeldCount(sender);
  if ('count' in got) return got.count;
  if (!_warnedFallback.has(got.fallback)) {
    _warnedFallback.add(got.fallback);
    console.warn(`[held-count] the count row could not be used (${got.fallback}); using the full scan for this decision`);
  }
  scheduleHeldCountsReconcile();
  return countHeldFrom(sender);
}

let _reconcileRun: Promise<'ok' | 'gave-up'> | null = null;
const RECONCILE_ATTEMPTS = 5;

/**
 * Rebuild the count row from the notes themselves, OFF the receive path (on unlock, and after the row was found unusable). Read the row's blob, walk every thread and note once, seal what
 * the notes say, and write it only if the row is still the blob read before the walk: a held note that landed meanwhile moved the row, so the walk is done again (bounded; 'gave-up'
 * leaves the row as it was, and the next unlock tries again). One run at a time. Throws while locked.
 */
export function reconcileHeldCounts(): Promise<'ok' | 'gave-up'> {
  if (_reconcileRun) return _reconcileRun;
  const run = (async (): Promise<'ok' | 'gave-up'> => {
    for (let attempt = 0; attempt < RECONCILE_ATTEMPTS; attempt++) {
      const { enc: token } = await readHeldCountsRow();
      const counts = new Map<string, number>();
      for (const t of await listThreadsIncludingHeld()) {
        for (const [who, n] of countsFromNotes(await listNotesIncludingHeld(t.thread_id))) counts.set(who, (counts.get(who) ?? 0) + n);
      }
      const enc = await encryptJson(sealedShape({ state: 'ok', counts: counts as HeldCounts }));
      if (await txCommitIfUnchanged([{ store: 'settings', key: HELD_COUNTS_KEY, enc: token }], [{ store: 'settings', value: { key: HELD_COUNTS_KEY, enc } satisfies SettingsRow }])) return 'ok';
    }
    return 'gave-up';
  })();
  _reconcileRun = run.finally(() => {
    _reconcileRun = null;
  });
  return _reconcileRun;
}

function scheduleHeldCountsReconcile(): void {
  reconcileHeldCounts().catch(() => {});   // best effort: a locked store, or a store that cannot be read, leaves the row as it was
}

export type HeldAgeLimits = { limitDays?: number; graceDays?: number };
export type HeldAgeStepResult = HeldSweepAction | 'gone' | 'unreadable' | 'lost-race';
export type HeldAgeSweep = { deleted: number; stamped: number; cleared: number; kept: number; skipped: number };

/**
 * The ONE counted delete of a held note, shared by the age sweep and the owner's own delete: the note row goes and the count row drops by one in the SAME compare-and-swap (and a count row that cannot be
 * adjusted is written DIRTY, so the next arrival counts by the scan and a rebuild is scheduled). The caller has just read and decrypted `priorRow`; this only compares and writes, so a row that moved meanwhile
 * makes it answer false and the caller reads again. A held row is NEVER removed by a bare delete, which would leave the count high and refuse a person's evidence early. The row's thread row is left alone:
 * held notes are found by walking threads, so removing a thread row that a held note may still point at could strand that note (the empty held thread stays, hidden).
 */
async function commitCountedHeldDelete(noteId: string, priorRow: NoteRow, note: NoteRecord): Promise<boolean> {
  const counter = await readHeldCountsRow();
  const expects: Array<{ store: string; key: string; enc: EncryptedBlob | null }> = [{ store: 'notes', key: noteId, enc: priorRow.enc }, { store: 'settings', key: HELD_COUNTS_KEY, enc: counter.enc }];
  const usable = counter.read !== 'absent' && counter.read !== null && counter.read.state === 'ok' ? counter.read.counts : null;
  const next: HeldCountsRead = usable ? { state: 'ok', counts: applyChange(usable, heldInboundSender(note), null) } : { state: 'dirty' };
  const countRow = { key: HELD_COUNTS_KEY, enc: await encryptJson(sealedShape(next)) } satisfies SettingsRow;
  const committed = await txCommitIfUnchanged(expects, [{ store: 'settings', value: countRow }], [{ store: 'notes', key: noteId }]);
  if (committed && usable === null) scheduleHeldCountsReconcile();
  return committed;
}

/**
 * ONE held note, one step of the age sweep (held-note.ts: heldSweepAction decides, on the OWNER'S clock). The row is read HERE, inside the retry loop, so the decision is always made on the latest copy.
 * A stamp rewrites the note row only (its sender and held-ness do not change, so the count does not), compare-and-swap against the blob that was read. A DELETE is the counted twin of writeNote: the note
 * row goes and the count row drops by one in the SAME compare-and-swap (and a count row that cannot be adjusted is written DIRTY, so the next arrival counts by the scan and a rebuild is scheduled): a held
 * row is NEVER removed by a bare delete, which would leave the count high and refuse a person's evidence early. A row that cannot be decrypted is skipped: unknown age means keep.
 */
async function heldAgeStep(noteId: string, nowMs: number, limits?: HeldAgeLimits): Promise<HeldAgeStepResult> {
  for (let attempt = 0; attempt < NOTE_WRITE_ATTEMPTS; attempt++) {
    const priorRow = await txGet<NoteRow>('notes', noteId);
    if (!priorRow) return 'gone';
    let note: NoteRecord;
    try {
      note = await decryptJson<NoteRecord>(priorRow.enc);
    } catch {
      return 'unreadable';
    }
    const action = heldSweepAction(note, nowMs, limits?.limitDays, limits?.graceDays);
    if (action === 'keep') return 'keep';
    let committed: boolean;
    if (action === 'delete') {
      committed = await commitCountedHeldDelete(noteId, priorRow, note);
    } else {
      const enc = await encryptJson(stampedHeldNote(note, action, nowMs));
      committed = await txCommitIfUnchanged([{ store: 'notes', key: noteId, enc: priorRow.enc }], [{ store: 'notes', value: { note_id: note.note_id, thread_id: note.thread_id, enc } satisfies NoteRow }]);
    }
    if (committed) return action;
    await new Promise((r) => setTimeout(r, Math.floor(Math.random() * 4 * (attempt + 1))));   // another tab (or a write) moved a row: back off a little, then decide again on the new copy
  }
  return 'lost-race';
}

let _sweepRun: Promise<HeldAgeSweep> | null = null;

export type HeldMoveResult = 'done' | 'gone' | 'not-held' | 'unreadable' | 'lost-race';

/**
 * The counted RELEASE of one held note (the owner moves it to the inbox): the note row becomes an ordinary note (held, held_at and expiry_seen_at all go together), the count row drops by one, and the
 * note's thread row stops being held, ALL in one compare-and-swap. In one, because the alternatives are both unsafe: un-holding the thread first would show an empty conversation in Chat while the note is still
 * hidden, and un-holding it after would leave an ordinary note inside a hidden thread that nothing lists. The thread row loses only its held flag (last_activity_at is not touched), and other held notes in
 * it stay hidden because each note carries its own flag. Nothing here is a creation and nothing is sent.
 */
async function commitCountedHeldRelease(priorRow: NoteRow, note: NoteRecord, threadRow: ThreadRow, thread: NoteThread): Promise<boolean> {
  const counter = await readHeldCountsRow();
  const expects: Array<{ store: string; key: string; enc: EncryptedBlob | null }> = [
    { store: 'notes', key: note.note_id, enc: priorRow.enc },
    { store: 'threads', key: thread.thread_id, enc: threadRow.enc },
    { store: 'settings', key: HELD_COUNTS_KEY, enc: counter.enc },
  ];
  const usable = counter.read !== 'absent' && counter.read !== null && counter.read.state === 'ok' ? counter.read.counts : null;
  const next: HeldCountsRead = usable ? { state: 'ok', counts: applyChange(usable, heldInboundSender(note), null) } : { state: 'dirty' };
  const puts: Array<{ store: string; value: unknown }> = [
    { store: 'notes', value: { note_id: note.note_id, thread_id: note.thread_id, enc: await encryptJson(clearedHeldNote(note)) } satisfies NoteRow },
    { store: 'settings', value: { key: HELD_COUNTS_KEY, enc: await encryptJson(sealedShape(next)) } satisfies SettingsRow },
  ];
  if (isHeldThread(thread)) puts.push({ store: 'threads', value: { thread_id: thread.thread_id, enc: await encryptJson(clearedHeld(thread)) } satisfies ThreadRow });
  const committed = await txCommitIfUnchanged(expects, puts);
  if (committed && usable === null) scheduleHeldCountsReconcile();
  return committed;
}

/**
 * The OWNER'S own delete or release of ONE held note (the hold view). The row is read inside the retry loop; a note that is not held exactly true is refused ('not-held'), so this can never remove or
 * rewrite an ordinary note; one that cannot be decrypted is left alone ('unreadable'). Both moves are counted (above) and go through the per-tab write queue like every other note write.
 */
async function ownerHeldStep(noteId: string, what: 'delete' | 'release'): Promise<HeldMoveResult> {
  for (let attempt = 0; attempt < NOTE_WRITE_ATTEMPTS; attempt++) {
    const priorRow = await txGet<NoteRow>('notes', noteId);
    if (!priorRow) return 'gone';
    let note: NoteRecord;
    try {
      note = await decryptJson<NoteRecord>(priorRow.enc);
    } catch {
      return 'unreadable';
    }
    if (!isHeldNote(note)) return 'not-held';
    let committed: boolean;
    if (what === 'delete') {
      committed = await commitCountedHeldDelete(noteId, priorRow, note);
    } else {
      const threadRow = await txGet<ThreadRow>('threads', note.thread_id);
      if (!threadRow) return 'unreadable';
      let thread: NoteThread;
      try {
        thread = await decryptJson<NoteThread>(threadRow.enc);
      } catch {
        return 'unreadable';
      }
      committed = await commitCountedHeldRelease(priorRow, note, threadRow, thread);
    }
    if (committed) return 'done';
    await new Promise((r) => setTimeout(r, Math.floor(Math.random() * 4 * (attempt + 1))));   // another tab (or a write) moved a row: back off a little, then decide again on the new copy
  }
  return 'lost-race';
}

/** The owner deletes ONE held note (counted). Never an ordinary note: that answers 'not-held' and changes nothing. */
export function deleteHeldNote(noteId: string): Promise<HeldMoveResult> {
  return serializeNoteWrite(() => ownerHeldStep(noteId, 'delete'));
}

/** The owner moves ONE held note to the inbox (counted; it stays a rewrite of an existing row, never a creation). Never an ordinary note: that answers 'not-held' and changes nothing. */
export function releaseHeldNote(noteId: string): Promise<HeldMoveResult> {
  return serializeNoteWrite(() => ownerHeldStep(noteId, 'release'));
}

/** The held notes from ONE sender, newest first (by when this device held them). User-initiated, off the receive path: it walks every thread's held notes once. Throws while locked. */
export async function listHeldFrom(fingerprint: string): Promise<NoteRecord[]> {
  requireUnlocked();
  const want = fingerprint.toLowerCase();
  const out: NoteRecord[] = [];
  for (const t of await listThreadsIncludingHeld()) {
    for (const n of await listNotesIncludingHeld(t.thread_id)) if (heldInboundSender(n) === want) out.push(n);
  }
  return out.sort((a, b) => heldSince(b) - heldSince(a) || (a.note_id < b.note_id ? -1 : 1));
}

/** Every sender that has held notes on this device, with how many. For the hold view only (the number is shown inside it, never on the way in). Throws while locked. */
export async function listHeldSenders(): Promise<Array<{ from_fingerprint: string; count: number }>> {
  requireUnlocked();
  const counts = new Map<string, number>();
  for (const t of await listThreadsIncludingHeld()) {
    for (const n of await listNotesIncludingHeld(t.thread_id)) {
      const who = heldInboundSender(n);
      if (who !== null) counts.set(who, (counts.get(who) ?? 0) + 1);
    }
  }
  return [...counts.entries()].map(([from_fingerprint, count]) => ({ from_fingerprint, count })).sort((a, b) => (a.from_fingerprint < b.from_fingerprint ? -1 : 1));
}

/**
 * Apply the hold's age limit to every held note, on the owner's clock, OFF the receive path (at unlock, after the count row is put right). One run at a time. Each note goes through the same per-tab
 * write queue as every other note write. `nowMs` and `limits` exist for tests; production passes neither (so the limit is the one named number in held-note.ts). Throws while locked.
 */
export function sweepHeldAge(nowMs: number = Date.now(), limits?: HeldAgeLimits): Promise<HeldAgeSweep> {
  if (_sweepRun) return _sweepRun;
  const run = (async (): Promise<HeldAgeSweep> => {
    requireUnlocked();
    const out: HeldAgeSweep = { deleted: 0, stamped: 0, cleared: 0, kept: 0, skipped: 0 };
    for (const t of await listThreadsIncludingHeld()) {
      for (const n of await listNotesIncludingHeld(t.thread_id)) {
        if (!isHeldNote(n)) continue;
        const r = await serializeNoteWrite(() => heldAgeStep(n.note_id, nowMs, limits));
        if (r === 'delete') out.deleted++;
        else if (r === 'stamp-held-at' || r === 'stamp-expiry') out.stamped++;
        else if (r === 'clear-expiry') out.cleared++;
        else if (r === 'keep') out.kept++;
        else out.skipped++;
      }
    }
    return out;
  })();
  _sweepRun = run.finally(() => {
    _sweepRun = null;
  });
  return _sweepRun;
}

// At unlock, off the receive path: put the count row right FIRST, then apply the age limit (the counted deletes then adjust a row that is right). Best effort: a locked store, or one that cannot be read, leaves everything as it was.
function scheduleHeldMaintenance(): void {
  reconcileHeldCounts().catch(() => {}).then(() => sweepHeldAge()).catch(() => {});
}

export async function deleteThread(threadId: string): Promise<void> {
  // A delete is about what the owner can SEE. Held notes are evidence (kept until the owner removes them from the hold view), so every held note stays, and so
  // does the thread row they hang on: the include-held readers find held notes by walking threads, so a deleted row would strand them where the cap count, the
  // replay guard and the hold view could never reach them. The kept row is flagged held, which hides it from every default reader like any held thread.
  const notes = await listNotesIncludingHeld(threadId);
  for (const n of notes) if (!isHeldNote(n)) await txDelete('notes', n.note_id);
  if (notes.some((n) => isHeldNote(n))) {
    const row = await txGet<ThreadRow>('threads', threadId);
    if (row) await putThread({ ...(await decryptJson<NoteThread>(row.enc)), held: true });
  } else await txDelete('threads', threadId);
}

// ── Encrypted rows in the existing 'settings' store (#720 dead-letter records) ───────────────────────────────────────────────────
// NO schema bump: DB_VERSION stays 2, so a rollback to a v2 build cannot hit an IndexedDB VersionError and lock the user out of their
// own notes. A row is {key, enc}: encrypted with the SAME notes key as every other row, in the same per-identity DB, so it is
// unreadable after lock / identity switch exactly like a note. Only keys allowed by isAllowedSettingsRowKey may be written or read
// through here, so none of this can touch 'notes_encryption_salt'. Reads and lists THROW while locked, so a caller can tell "locked"
// from "nothing there".
type SettingsRow = { key: string; enc: EncryptedBlob };

function requireRowKey(key: string): void {
  if (!isAllowedSettingsRowKey(key)) throw new Error('settings row key not allowed');
}

function requireUnlocked(): void {
  if (!_notesKey) throw new Error('Notes store locked — call initNotesStore() first');
}

export async function putEncryptedSetting(key: string, value: unknown): Promise<void> {
  requireRowKey(key);
  const enc = await encryptJson(value);
  await txPut('settings', { key, enc } satisfies SettingsRow);
}

export async function getEncryptedSetting<T>(key: string): Promise<T | null> {
  requireRowKey(key);
  requireUnlocked();
  const row = await txGet<SettingsRow>('settings', key);
  if (!row?.enc) return null;
  try {
    return await decryptJson<T>(row.enc);
  } catch {
    return null; // wrong key / corrupt — treat as absent
  }
}

export async function listEncryptedSettings<T>(prefix: string): Promise<Array<{ key: string; value: T }>> {
  if (!isAllowedSettingsPrefix(prefix)) throw new Error('settings row prefix not allowed');
  requireUnlocked();
  const db = await openDb();
  const rows: SettingsRow[] = await new Promise((resolve, reject) => {
    const tx = db.transaction('settings', 'readonly');
    const req = tx.objectStore('settings').getAll(IDBKeyRange.bound(prefix, `${prefix}\uffff`));
    req.onsuccess = () => resolve((req.result as SettingsRow[]) || []);
    req.onerror = () => reject(req.error);
  });
  const out: Array<{ key: string; value: T }> = [];
  for (const row of rows) {
    if (!row?.enc || typeof row.key !== 'string') continue;
    try {
      out.push({ key: row.key, value: await decryptJson<T>(row.enc) });
    } catch {
      /* skip a row that will not decrypt */
    }
  }
  return out;
}

export async function deleteEncryptedSetting(key: string): Promise<void> {
  requireRowKey(key);
  await txDelete('settings', key);
}

export async function putRingChannel(channel: RingChannel): Promise<void> {
  const enc = await encryptJson(channel);
  await txPut('ring_channels', { channel_id: channel.channel_id, enc } satisfies RingRow);
}

export async function listRingChannels(): Promise<RingChannel[]> {
  const rows = await txGetAll<RingRow>('ring_channels');
  const out: RingChannel[] = [];
  for (const row of rows) {
    try {
      out.push(await decryptJson<RingChannel>(row.enc));
    } catch {
      // skip
    }
  }
  return out;
}

export function newNoteId(): string {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return `note_${toBase64(b).replace(/[+/=]/g, '').slice(0, 16)}`;
}

export function newThreadId(): string {
  const b = new Uint8Array(12);
  crypto.getRandomValues(b);
  return `thr_${toBase64(b).replace(/[+/=]/g, '').slice(0, 16)}`;
}

/** Per-note delivery-receipt freshness nonce (hex). Sealed+signed inside NoteWireV0.receipt_nonce and
 *  kept on the local outbound NoteRecord as the sender's source-of-truth for receipt verification. */
export function newReceiptNonce(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

/** `version` counts writes to this row (R5). A row written before it existed has none and counts as 1; no row counts as 0. */
type RatchetRow = { peer_fingerprint: string; enc: EncryptedBlob; version?: number };

/** The version a CAS write must expect for what is currently stored: 0 = no row, a legacy row without a counter = 1. Pure, so it is unit-tested without IndexedDB. */
export function ratchetRowVersion(row: { version?: number } | undefined): number {
  return row ? (row.version ?? 1) : 0;
}

/** The session row changed between our read and our write (another tab or task advanced it). Nothing was written. */
export class RatchetSessionConflictError extends Error {
  constructor() {
    super('ratchet session changed under us: nothing was written; retry from the current state');
    this.name = 'RatchetSessionConflictError';
  }
}

/**
 * Persist a 1:1 triple-ratchet snapshot, encrypted with the notes-store key, ONLY IF the stored row is still at `expectedVersion`
 * (the version we read). The compare and the put share one readwrite transaction, so no other tab can slip a write between them.
 * A mismatch aborts the transaction and throws RatchetSessionConflictError. This is the net under the per-peer lock (R5).
 */
export async function putRatchetSession(peerFingerprint: string, snapshot: RatchetSnapshot, expectedVersion: number): Promise<void> {
  const enc = await encryptJson(snapshot);
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction('ratchet_sessions', 'readwrite');
    const os = tx.objectStore('ratchet_sessions');
    const cur = os.get(peerFingerprint);
    cur.onsuccess = () => {
      const have = ratchetRowVersion(cur.result as RatchetRow | undefined);
      if (have !== expectedVersion) {
        reject(new RatchetSessionConflictError());
        tx.abort();
        return;
      }
      os.put({ peer_fingerprint: peerFingerprint, enc, version: have + 1 } satisfies RatchetRow);
    };
    cur.onerror = () => reject(cur.error);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new RatchetSessionConflictError());
  });
}

/**
 * What is stored for this peer. THREE states, on purpose (R3): a row that EXISTS but cannot be read (wrong key, torn write,
 * corruption) is NOT "no session". Collapsing the two made the caller start a fresh initiator session and overwrite the
 * unreadable row, silently replacing the real session with a parallel one the peer's chain no longer matches.
 */
export type RatchetSessionRead =
  | { state: 'absent' }
  | { state: 'unreadable' }
  | { state: 'ok'; snapshot: RatchetSnapshot; version: number };

export async function readRatchetSession(peerFingerprint: string): Promise<RatchetSessionRead> {
  const row = await txGet<RatchetRow>('ratchet_sessions', peerFingerprint);
  if (!row) return { state: 'absent' };
  try {
    return { state: 'ok', snapshot: await decryptJson<RatchetSnapshot>(row.enc), version: ratchetRowVersion(row) };
  } catch {
    return { state: 'unreadable' };
  }
}

/**
 * Delete ONE peer's session row (#720 reset, Flint reset-semantics R1). Returns whether a row existed. Reads and deletes in one readwrite
 * transaction. UNCONDITIONAL on purpose (no version compare): a reset must also clear an UNREADABLE row, which has no version to compare.
 * The caller holds the per-peer session lock (R5), which is what keeps this from racing an open or a seal. Touches no other store and no
 * other peer: notes, threads, trust and dead-letter records are not here.
 */
export async function deleteRatchetSession(peerFingerprint: string): Promise<boolean> {
  const db = await openDb();
  return new Promise<boolean>((resolve, reject) => {
    const tx = db.transaction('ratchet_sessions', 'readwrite');
    const os = tx.objectStore('ratchet_sessions');
    let existed = false;
    const cur = os.get(peerFingerprint);
    cur.onsuccess = () => {
      existed = cur.result !== undefined;
      if (existed) os.delete(peerFingerprint);
    };
    cur.onerror = () => reject(cur.error);
    tx.oncomplete = () => resolve(existed);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error('ratchet session delete aborted'));
  });
}

/** Back-compat for existing callers/exports: the snapshot, or null for BOTH absent and unreadable. New code uses readRatchetSession. */
export async function getRatchetSession(peerFingerprint: string): Promise<RatchetSnapshot | null> {
  const r = await readRatchetSession(peerFingerprint);
  return r.state === 'ok' ? r.snapshot : null;
}
