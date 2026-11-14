// src/lib/lenses/lens-grants-store.test.ts — v1.10 B1: on the REAL sealed store, ABSENT and
// UNREADABLE are different verdicts. Only a genuinely absent record reads as an empty book;
// locked, wrong-passphrase (tag failure), a corrupted sealed row and a store error all read
// unreadable — read-only, never an empty stand-in a save could overwrite.
// Run: npx tsx --test src/lib/lenses/lens-grants-store.test.ts
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  initSessionKey, lockSession, readLensGrantBook, writeLensGrantBook,
} from '../identity/client-store';
import { encryptContactRecord } from '../identity/contact-crypto';
import { loadLensGrants, saveLensGrants, type LensGrantBook } from './lens-grants';

const OWNER = 'c'.repeat(64);
const BOOK: LensGrantBook = { v: 1, grants: {}, inSeq: {} };

// ---------- a minimal IndexedDB over Maps — real crypto path, no dependency ----------
// Covers the surface client-store.ts uses: open/upgrade, transaction (single + multi store),
// get/put/delete/getAll/getAllKeys/clear, index().get/getAll, tx.oncomplete/onerror.

type Row = { keyPath: string; rows: Map<unknown, unknown>; indexes: Map<string, string> };
const stores = new Map<string, Row>();
let failOpens = false;

function settle(r: Record<string, unknown>, value: unknown) {
  r.result = value;
  queueMicrotask(() => {
    const fn = r.onsuccess as (() => void) | null;
    fn?.call(r);
  });
}
function req(value: () => unknown) {
  const r: Record<string, unknown> = { result: null, error: null, onsuccess: null, onerror: null };
  queueMicrotask(() => { try { settle(r, value()); } catch (e) { r.error = e; (r.onerror as (() => void) | null)?.call(r); } });
  return r;
}
function storeFor(name: string) {
  const s = stores.get(name);
  if (!s) throw new Error(`missing store ${name}`);
  return s;
}
function objectStore(name: string) {
  const s = storeFor(name);
  const byPath = (kp: string, k: unknown) => [...s.rows.values()].filter((v) => (v as Record<string, unknown>)?.[kp] === k);
  return {
    get: (k: unknown) => req(() => s.rows.get(k)),
    put: (v: Record<string, unknown>) => req(() => { s.rows.set(v[s.keyPath], v); return v; }),
    delete: (k: unknown) => req(() => { s.rows.delete(k); }),
    getAll: () => req(() => [...s.rows.values()]),
    getAllKeys: () => req(() => [...s.rows.keys()]),
    clear: () => req(() => { s.rows.clear(); }),
    count: () => req(() => s.rows.size),
    index: (n: string) => ({
      get: (k: unknown) => req(() => byPath(s.indexes.get(n)!, k)[0]),
      getAll: (k?: unknown) => req(() => (k === undefined ? [...s.rows.values()] : byPath(s.indexes.get(n)!, k))),
    }),
  };
}
const db = {
  objectStoreNames: { contains: (n: string) => stores.has(n) },
  createObjectStore: (name: string, opts: { keyPath: string }) => {
    const s: Row = { keyPath: opts.keyPath, rows: new Map(), indexes: new Map() };
    stores.set(name, s);
    return { createIndex: (n: string, kp: string) => { s.indexes.set(n, kp); } };
  },
  transaction: (names: string | string[], _mode: string) => {
    const tx = {
      oncomplete: null as (() => void) | null,
      onerror: null as (() => void) | null,
      objectStore: (n: string) => objectStore(n),
    };
    queueMicrotask(() => tx.oncomplete?.());
    return tx;
  },
  close: () => {},
};

beforeEach(() => {
  stores.clear();
  failOpens = false;
  (globalThis as Record<string, unknown>).indexedDB = {
    open: (_name: string, _ver?: number) => {
      const r: Record<string, unknown> = { result: db, error: null, onsuccess: null, onerror: null, onupgradeneeded: null, onblocked: null };
      if (failOpens) {
        r.error = new Error('simulated IDB failure');
        queueMicrotask(() => (r.onerror as (() => void) | null)?.call(r));
      } else {
        queueMicrotask(() => (r.onupgradeneeded as ((e: unknown) => void) | null)?.call(r, { target: r }));
        queueMicrotask(() => (r.onsuccess as (() => void) | null)?.call(r));
      }
      return r;
    },
  };
  lockSession();
});

const rawRow = () => {
  const s = stores.get('settings')!;
  return [...s.rows.values()].find((v) => (v as { key: string }).key === `lens_book:${OWNER}`) as
    | { key: string; value: { iv: string; ciphertext: string } } | undefined;
};

test('B1: ABSENT reads as a readable empty book — the one case null may mean', async () => {
  await initSessionKey('pw');
  assert.equal(await readLensGrantBook(OWNER), null);
  assert.deepEqual(await loadLensGrants(OWNER), { v: 1, grants: {}, inSeq: {} });
});

test('B1: LOCKED reads UNREADABLE — not empty, and nothing may save over it', async () => {
  lockSession(); // no session key at all
  await assert.rejects(() => readLensGrantBook(OWNER), /locked/);
  const book = await loadLensGrants(OWNER);
  assert.equal(book.unreadable, true, 'a locked session is unreadable, never an empty stand-in');
  await assert.rejects(() => saveLensGrants(OWNER, { ...book, unreadable: undefined }), /unreadable|locked/i);
});

test('B1: sealed roundtrip — unlock under the SAME passphrase reads the real book back', async () => {
  await initSessionKey('pw');
  await writeLensGrantBook(OWNER, JSON.stringify({ v: 1, grants: {}, inSeq: { [OWNER]: 7 } }));
  lockSession();
  await initSessionKey('pw');
  const book = await loadLensGrants(OWNER);
  assert.equal(book.unreadable ?? false, false, 'a good read is a readable book');
  assert.equal(book.inSeq?.[OWNER], 7);
});

test('B1: WRONG PASSPHRASE reads UNREADABLE — a tag failure, never an empty book', async () => {
  await initSessionKey('pw');
  await writeLensGrantBook(OWNER, JSON.stringify(BOOK));
  lockSession();
  await initSessionKey('other-pw'); // same salt (persists in settings), different key
  assert.equal((await loadLensGrants(OWNER)).unreadable, true);
  await assert.rejects(() => readLensGrantBook(OWNER));
});

test('B1: a CORRUPTED sealed record reads UNREADABLE — and a refused save leaves the bytes identical', async () => {
  await initSessionKey('pw');
  await writeLensGrantBook(OWNER, JSON.stringify(BOOK));
  const row = rawRow()!;
  const bytes = row.value.ciphertext;
  row.value.ciphertext = (bytes[0] === 'A' ? 'B' : 'A') + bytes.slice(1); // tag failure
  const before = JSON.stringify(row.value);
  const book = await loadLensGrants(OWNER);
  assert.equal(book.unreadable, true, 'a corrupted sealed row is unreadable, not absent');
  await saveLensGrants(OWNER, book); // read-only: the save is refused (silently — never throws into a poll)
  assert.equal(JSON.stringify(rawRow()!.value), before, 'the sealed bytes are untouched — R2a read-only');
});

test('B1: a STORE ERROR reads UNREADABLE — transient faults can never stand in as empty', async () => {
  await initSessionKey('pw');
  failOpens = true;
  assert.equal((await loadLensGrants(OWNER)).unreadable, true);
  await assert.rejects(() => readLensGrantBook(OWNER));
});

test('B1/T2: a sealed NON-STRING payload reads UNREADABLE — and a refused save leaves the bytes identical', async () => {
  await initSessionKey('pw');
  // Seal an OBJECT under the book's AAD id — a well-formed row whose decrypted payload is not a
  // book string at all. Kills the mutant `if (typeof rec !== 'string') return null` (absent→empty).
  const saltRow = [...stores.get('settings')!.rows.values()].find((v) => (v as { key: string }).key === 'key_encryption_salt') as { value: string };
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode('pw'), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: Buffer.from(saltRow.value, 'base64'), iterations: 600_000, hash: 'SHA-256' },
    keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
  );
  const payload = await encryptContactRecord(key, 'lenses:grant-book', OWNER, { not: 'a book string' });
  stores.get('settings')!.rows.set(`lens_book:${OWNER}`, { key: `lens_book:${OWNER}`, value: payload });
  const before = JSON.stringify(rawRow()!.value);
  assert.equal((await loadLensGrants(OWNER)).unreadable, true, 'a non-string decrypted payload is unreadable, not absent');
  await assert.rejects(() => readLensGrantBook(OWNER), /not a book/);
  await saveLensGrants(OWNER, { v: 1, grants: {}, inSeq: {}, unreadable: true });
  assert.equal(JSON.stringify(rawRow()!.value), before, 'the sealed bytes are untouched — the refused save stands');
});
