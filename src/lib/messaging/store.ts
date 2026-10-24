// src/lib/messaging/store.ts
// Separate IndexedDB for notes (Phase 3.2) — NOT the svrnty vault/book database.
// Bodies encrypted at rest with a notes-session AES-GCM key (passphrase-derived).

import type { NoteRecord, NoteThread, RingChannel } from './types';
import { onSessionLock } from '@/lib/identity/client-store';

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
      // svrnty #616 (v2): message-management stores — additive only. 'archive'
      // holds hidden-from-inbox notes; 'recently_deleted' is the recoverable
      // bin. Rows are the SAME {note_id, thread_id, enc} shape plus a *_at
      // stamp — the EncryptedBlob is moved verbatim (Flint line: no new
      // key/blob format). Legacy data is never touched by the migration.
      if (!db.objectStoreNames.contains('archive')) {
        const archive = db.createObjectStore('archive', { keyPath: 'note_id' });
        archive.createIndex('thread_id', 'thread_id', { unique: false });
      }
      if (!db.objectStoreNames.contains('recently_deleted')) {
        const bin = db.createObjectStore('recently_deleted', { keyPath: 'note_id' });
        bin.createIndex('thread_id', 'thread_id', { unique: false });
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
}

export function isNotesStoreUnlocked(): boolean {
  return _notesKey !== null;
}

export function lockNotesStore(): void {
  _notesGeneration += 1; // invalidate any in-flight initNotesStore (async-init race, Codex P1 10/10)
  _notesKey = null;
  _notesSalt = null;
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
  return out.sort((a, b) => b.last_activity_at.localeCompare(a.last_activity_at));
}

export async function putNote(note: NoteRecord): Promise<void> {
  const enc = await encryptJson(note);
  await txPut('notes', {
    note_id: note.note_id,
    thread_id: note.thread_id,
    enc,
  } satisfies NoteRow);
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

export async function deleteThread(threadId: string): Promise<void> {
  const notes = await listNotesForThread(threadId);
  for (const n of notes) await txDelete('notes', n.note_id);
  await txDelete('threads', threadId);
}

// ── svrnty #616: message management (archive / recently_deleted) ──────────
// Rows move between stores with their EncryptedBlob VERBATIM — management is
// a row operation, never a crypto one. Every batch runs inside ONE readwrite
// transaction spanning source+dest, so a multi-select action is all-or-
// nothing (abort leaves zero rows moved, never a partial state).

/** How long a binned note stays recoverable before listDeletedNotes purges it. */
export const DELETED_RETENTION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

type MovedRow = { note_id: string; thread_id: string; enc: EncryptedBlob } &
  Record<string, unknown>;

async function _moveNotes(
  srcStore: 'notes' | 'archive' | 'recently_deleted',
  dstStore: 'notes' | 'archive' | 'recently_deleted' | null,
  noteIds: string[],
  stamp?: { field: 'archived_at' | 'deleted_at' },
  strip?: string[],
): Promise<number> {
  const db = await openDb();
  const stores = dstStore ? [srcStore, dstStore] : [srcStore];
  return new Promise((resolve, reject) => {
    const tx = db.transaction(stores, 'readwrite');
    const src = tx.objectStore(srcStore);
    const dst = dstStore ? tx.objectStore(dstStore) : null;
    let moved = 0;
    for (const id of noteIds) {
      const get = src.get(id);
      get.onsuccess = () => {
        const row = get.result as MovedRow | undefined;
        if (!row) return; // already absent — absent is not an error
        if (dst) {
          const out: MovedRow = { ...row };
          for (const k of strip ?? []) delete out[k];
          if (stamp) out[stamp.field] = new Date().toISOString();
          dst.put(out);
        }
        src.delete(id);
        moved += 1;
      };
    }
    tx.oncomplete = () => resolve(moved);
    tx.onabort = tx.onerror = () => reject(tx.error);
  });
}

/** Archive: hide from inbox, recoverable forever. Atomic batch. */
export function archiveNotes(noteIds: string[]): Promise<number> {
  return _moveNotes('notes', 'archive', noteIds, { field: 'archived_at' });
}

/** Soft delete: notes → recently_deleted bin. Atomic batch. */
export function deleteNotes(noteIds: string[]): Promise<number> {
  return _moveNotes('notes', 'recently_deleted', noteIds, { field: 'deleted_at' });
}

/** Restore from the bin back to the live store (stamp removed). */
export function restoreNotes(noteIds: string[]): Promise<number> {
  return _moveNotes('recently_deleted', 'notes', noteIds, undefined, ['deleted_at']);
}

/** Restore from archive back to the live store (stamp removed). */
export function restoreArchived(noteIds: string[]): Promise<number> {
  return _moveNotes('archive', 'notes', noteIds, undefined, ['archived_at']);
}

/** Permanent delete from the bin. Irreversible — caller confirms first. */
export function purgeDeleted(noteIds: string[]): Promise<number> {
  return _moveNotes('recently_deleted', null, noteIds);
}

async function _listManaged(
  storeName: 'archive' | 'recently_deleted',
  stampField: 'archived_at' | 'deleted_at',
  threadId?: string,
): Promise<(NoteRecord & { [k: string]: unknown })[]> {
  const db = await openDb();
  const rows: MovedRow[] = await new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = threadId
      ? tx.objectStore(storeName).index('thread_id').getAll(threadId)
      : tx.objectStore(storeName).getAll();
    req.onsuccess = () => resolve((req.result as MovedRow[]) || []);
    req.onerror = () => reject(req.error);
  });
  const out: (NoteRecord & { [k: string]: unknown })[] = [];
  const now = Date.now();
  for (const row of rows) {
    try {
      const note = await decryptJson<NoteRecord>(row.enc);
      const stamp = row[stampField] as string | undefined;
      if (
        storeName === 'recently_deleted' &&
        stamp &&
        now - new Date(stamp).getTime() > DELETED_RETENTION_MS
      ) {
        await txDelete('recently_deleted', row.note_id); // bin retention purge
        continue;
      }
      out.push({ ...note, [stampField]: stamp });
    } catch {
      // corrupt / wrong key — skip
    }
  }
  return out.sort((a, b) =>
    String(b[stampField] ?? '').localeCompare(String(a[stampField] ?? '')));
}

/** Archived notes, newest-archived first. */
export function listArchivedNotes(
  threadId?: string,
): Promise<(NoteRecord & { archived_at?: string })[]> {
  return _listManaged('archive', 'archived_at', threadId);
}

/** Binned notes still inside retention, newest-deleted first. Rows past
 * DELETED_RETENTION_MS are hard-purged on this read (lazy sweep — same
 * convention as expires_at in listNotesForThread). */
export function listDeletedNotes(
  threadId?: string,
): Promise<(NoteRecord & { deleted_at?: string })[]> {
  return _listManaged('recently_deleted', 'deleted_at', threadId);
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
