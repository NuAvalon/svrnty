// src/lib/messaging/store.ts
// Separate IndexedDB for notes (Phase 3.2) — NOT the svrnty vault/book database.
// Bodies encrypted at rest with a notes-session AES-GCM key (passphrase-derived).

import type { NoteRecord, NoteThread, RingChannel } from './types';

const DB_NAME = 'svrnty-notes';
const DB_VERSION = 1;
const PBKDF2_ITERATIONS = 600_000;

let _db: IDBDatabase | null = null;
let _notesKey: CryptoKey | null = null;
let _notesSalt: Uint8Array | null = null;

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
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
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
export async function initNotesStore(passphrase: string): Promise<void> {
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
  _notesKey = await deriveNotesKey(passphrase, salt);
  _notesSalt = salt;
}

export function isNotesStoreUnlocked(): boolean {
  return _notesKey !== null;
}

export function lockNotesStore(): void {
  _notesKey = null;
  _notesSalt = null;
}

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
