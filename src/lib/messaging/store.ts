// src/lib/messaging/store.ts
// Separate IndexedDB for notes (Phase 3.2) — NOT the svrnty vault/book database.
// Bodies encrypted at rest with a notes-session AES-GCM key (passphrase-derived).

import type { NoteRecord, NoteThread, RingChannel } from './types';
import type { RatchetSnapshot } from '@/lib/crypto/message-ratchet';
import { onSessionLock } from '@/lib/identity/client-store';
import { isAllowedSettingsPrefix, isAllowedSettingsRowKey } from './settings-row-keys';
import { needsLastActivityHeal, healedLastActivity, activityMs } from './thread-activity';

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
 * Put a row ONLY IF a row with this key still exists, as ONE readwrite transaction: the existence check and the write have no await between them, so
 * IndexedDB (which serialises readwrite transactions on a store) lets either a concurrent delete commit first (the check misses and nothing is written)
 * or this write commit first (and the delete then removes it). Either way a deleted row stays deleted. Returns whether it wrote. Callers must encrypt
 * BEFORE calling: WebCrypto cannot run inside an IndexedDB transaction without the transaction auto-committing.
 */
async function txPutIfPresent(store: string, key: string, value: unknown): Promise<boolean> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    const os = tx.objectStore(store);
    let wrote = false;
    const existing = os.get(key);
    existing.onsuccess = () => {
      if (existing.result !== undefined) {
        os.put(value);
        wrote = true;
      }
    };
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
export async function initNotesStore(passphrase: string, ownerFingerprint: string): Promise<void> {
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

export async function listThreads(): Promise<NoteThread[]> {
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
    // never written: the thread stays in THIS list as read and is gone on the next load. (A delete that lands AFTER this check is caught by the
    // single-transaction write below.)
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
    // Encrypt first, then check-and-write in ONE transaction: the row can still disappear between the re-read above and this write (a delete is its own
    // series of transactions), and a plain put would bring a deleted conversation back.
    const enc = await encryptJson(next);
    const wrote = await txPutIfPresent('threads', thread.thread_id, { thread_id: thread.thread_id, enc } satisfies ThreadRow);
    return wrote ? next : thread;
  } catch {
    return thread;
  }
}

export async function putNote(note: NoteRecord): Promise<void> {
  const enc = await encryptJson(note);
  await txPut('notes', {
    note_id: note.note_id,
    thread_id: note.thread_id,
    enc,
  } satisfies NoteRow);
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

export async function listNotesForThread(threadId: string): Promise<NoteRecord[]> {
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
      if (note.retention.expires_at && new Date(note.retention.expires_at).getTime() < now) {
        await txDelete('notes', note.note_id);
        continue;
      }
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
  for (const t of await listThreads()) {
    for (const n of await listNotesForThread(t.thread_id)) {
      if (n.direction === 'inbound' && n.from_fingerprint.toLowerCase() === want) out.push(n.sent_at);
    }
  }
  return out;
}

export async function deleteThread(threadId: string): Promise<void> {
  const notes = await listNotesForThread(threadId);
  for (const n of notes) await txDelete('notes', n.note_id);
  await txDelete('threads', threadId);
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
