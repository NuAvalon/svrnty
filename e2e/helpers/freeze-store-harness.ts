// Browser-side harness for the REAL notes store (the encrypted IndexedDB one), bundled by esbuild and injected into a page. It exposes the store's own functions
// and a RAW row reader, so a spec can check both behaviour (which reader returns a held note) and what is at rest (which plaintext keys a held row has).
import { initNotesStore, sweepHeldAge, readHeldCount, countHeldFromFast, reconcileHeldCounts, putThread, putNoteReportingCreated, listThreads, listNotesForThread, listThreadsIncludingHeld, listNotesIncludingHeld, countHeldFrom, deleteThread, getNote, listInboundSentAtFrom } from '../../src/lib/messaging/store';
import type { NoteRecord, NoteThread } from '../../src/lib/messaging/types';
import { initSessionKey, loadKey, updateContact } from '../../src/lib/identity/client-store';
import { blockPatch } from '../../src/lib/contacts/metadata-patches';

interface RawRow { store: string; keys: string[]; encKeys: string[]; plaintext: Record<string, unknown>; encBytes: number }

declare global {
  interface Window {
    __fz: {
      init(owner: string): Promise<void>;
      /** Open the notes store the way the APP does: unlock a session from the typed passphrase, then use the identity key's OWN passphrase (loadKey), which is what the live poll passes. */
      initApp(owner: string, typedPassphrase: string): Promise<void>;
      /** Set or clear the block flag through the app's own contact store (it handles a sealed or a plaintext record), the state the Block action leaves. */
      setBlocked(contactId: string, blocked: boolean): Promise<void>;
      putThread(t: NoteThread): Promise<void>;
      putNote(n: NoteRecord): Promise<boolean>;
      threads(): Promise<NoteThread[]>;
      notes(threadId: string): Promise<NoteRecord[]>;
      allThreads(): Promise<NoteThread[]>;
      allNotes(threadId: string): Promise<NoteRecord[]>;
      countHeld(fp: string): Promise<number>;
      del(threadId: string): Promise<void>;
      get(noteId: string): Promise<NoteRecord | null>;
      sentAt(fp: string): Promise<string[]>;
      raw(): Promise<RawRow[]>;
      /** Unlock WITH the unlock-time reconcile (the way the app does), and wait for it: the held-count row exists for everyone afterwards. */
      initReconciled(owner: string): Promise<'ok' | 'gave-up'>;
      /** Unlock the way the app does and RETURN: the unlock-time reconcile runs in the background, nobody waits for it. */
      initOnly(owner: string): Promise<void>;
      /** The held-count row's own answer for a sender: a number, or the reason it could not be used. */
      held(fp: string): Promise<{ count: number } | { fallback: string }>;
      /** The per-arrival cap check: the row's answer, or the full scan when the row cannot be used. */
      fast(fp: string): Promise<number>;
      reconcile(): Promise<'ok' | 'gave-up'>;
      /** Every row of the notes DB's settings store: key, whether it is sealed, and the sealed size (the salt row is plaintext). */
      settingsRows(): Promise<Array<{ key: string; sealed: boolean; encBytes: number; ivLen: number }>>;
      /** Replace one settings row's blob with raw bytes that are not a valid ciphertext (a corrupt row). */
      corruptSetting(key: string): Promise<void>;
      /** Control: the NAIVE counter (read, await, write) on a scratch row, run n times at once. Returns the final value; a correct counter would say n. */
      naiveCounter(n: number): Promise<number>;
      /** Remove one settings row (the store as an older build left it: held notes, and no count row). */
      deleteSetting(key: string): Promise<void>;
      /** Replace one note row's blob with bytes that are not a valid ciphertext (a note that can no longer be read). */
      corruptNote(noteId: string, threadId: string): Promise<void>;
      /** Apply the hold's age limit NOW, on the clock the spec gives (production passes none): what was deleted, stamped, cleared, kept or skipped. `limits` is for the off-switch case. */
      sweep(nowMs: number, limits?: { limitDays?: number; graceDays?: number }): Promise<{ deleted: number; stamped: number; cleared: number; kept: number; skipped: number }>;
    };
  }
}

async function rawRows(): Promise<RawRow[]> {
  const dbs = (await indexedDB.databases()).filter((d) => d.name && /notes/i.test(d.name));
  const out: RawRow[] = [];
  for (const info of dbs) {
    const db: IDBDatabase = await new Promise((res, rej) => { const r = indexedDB.open(info.name!); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    for (const store of ['notes', 'threads']) {
      if (!db.objectStoreNames.contains(store)) continue;
      const rows: Array<Record<string, unknown>> = await new Promise((res, rej) => { const q = db.transaction(store, 'readonly').objectStore(store).getAll(); q.onsuccess = () => res(q.result as never); q.onerror = () => rej(q.error); });
      for (const row of rows) {
        const enc = (row.enc ?? {}) as Record<string, unknown>;
        const { enc: _e, ...plaintext } = row; void _e;
        const len = (v: unknown): number => (typeof v === 'string' ? v.length : v instanceof ArrayBuffer ? v.byteLength : ArrayBuffer.isView(v) ? (v as ArrayBufferView).byteLength : 0);
        out.push({ store, keys: Object.keys(row).sort(), encKeys: Object.keys(enc).sort(), plaintext, encBytes: Object.values(enc).reduce<number>((a, v) => a + len(v), 0) });
      }
    }
    db.close();
  }
  return out;
}

window.__fz = {
  init: (owner) => initNotesStore('e2e-passphrase-1234', owner, { reconcile: false }),   // no background reconcile: the older specs read raw rows and must stay deterministic
  initApp: async (owner, typedPassphrase) => {
    await initSessionKey(typedPassphrase);
    const key = await loadKey(owner);
    if (!key?.passphrase) throw new Error('no stored identity key for this owner');
    await initNotesStore(key.passphrase, owner);
  },
  setBlocked: async (contactId, blocked) => { await updateContact(contactId, (fresh) => blockPatch(fresh, blocked)); },
  putThread: (t) => putThread(t),
  putNote: (n) => putNoteReportingCreated(n),
  threads: () => listThreads(),
  notes: (id) => listNotesForThread(id),
  allThreads: () => listThreadsIncludingHeld(),
  allNotes: (id) => listNotesIncludingHeld(id),
  countHeld: (fp) => countHeldFrom(fp),
  del: (id) => deleteThread(id),
  get: (id) => getNote(id),
  sentAt: (fp) => listInboundSentAtFrom(fp),
  raw: rawRows,
  initReconciled: async (owner) => { await initNotesStore('e2e-passphrase-1234', owner); return reconcileHeldCounts(); },
  initOnly: (owner) => initNotesStore('e2e-passphrase-1234', owner),
  held: (fp) => readHeldCount(fp),
  fast: (fp) => countHeldFromFast(fp),
  reconcile: () => reconcileHeldCounts(),
  settingsRows: async () => {
    const dbs = (await indexedDB.databases()).filter((d) => d.name && /notes/i.test(d.name));
    const out: Array<{ key: string; sealed: boolean; encBytes: number; ivLen: number }> = [];
    for (const info of dbs) {
      const db: IDBDatabase = await new Promise((res, rej) => { const r = indexedDB.open(info.name!); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
      const rows: Array<Record<string, unknown>> = await new Promise((res, rej) => { const q = db.transaction('settings', 'readonly').objectStore('settings').getAll(); q.onsuccess = () => res(q.result as never); q.onerror = () => rej(q.error); });
      for (const row of rows) {
        const enc = row.enc as { iv?: string; ciphertext?: string } | undefined;
        out.push({ key: String(row.key), sealed: !!enc, encBytes: enc?.ciphertext ? enc.ciphertext.length : 0, ivLen: enc?.iv ? enc.iv.length : 0 });
      }
      db.close();
    }
    return out.sort((a, b) => (a.key < b.key ? -1 : 1));
  },
  corruptSetting: async (key) => {
    const dbs = (await indexedDB.databases()).filter((d) => d.name && /notes/i.test(d.name));
    for (const info of dbs) {
      const db: IDBDatabase = await new Promise((res, rej) => { const r = indexedDB.open(info.name!); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
      await new Promise<void>((res, rej) => { const tx = db.transaction('settings', 'readwrite'); tx.objectStore('settings').put({ key, enc: { iv: 'AAAAAAAAAAAAAAAA', ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAA' } }); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); });
      db.close();
    }
  },
  deleteSetting: async (key) => {
    const dbs = (await indexedDB.databases()).filter((d) => d.name && /notes/i.test(d.name));
    for (const info of dbs) {
      const db: IDBDatabase = await new Promise((res, rej) => { const r = indexedDB.open(info.name!); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
      await new Promise<void>((res, rej) => { const tx = db.transaction('settings', 'readwrite'); tx.objectStore('settings').delete(key); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); });
      db.close();
    }
  },
  sweep: (nowMs, limits) => sweepHeldAge(nowMs, limits),
  corruptNote: async (noteId, threadId) => {
    const dbs = (await indexedDB.databases()).filter((d) => d.name && /notes/i.test(d.name));
    for (const info of dbs) {
      const db: IDBDatabase = await new Promise((res, rej) => { const r = indexedDB.open(info.name!); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
      await new Promise<void>((res, rej) => { const tx = db.transaction('notes', 'readwrite'); tx.objectStore('notes').put({ note_id: noteId, thread_id: threadId, enc: { iv: 'AAAAAAAAAAAAAAAA', ciphertext: 'AAAAAAAAAAAAAAAAAAAAAAAA' } }); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); });
      db.close();
    }
  },
  naiveCounter: async (n) => {
    const db: IDBDatabase = await new Promise((res, rej) => { const r = indexedDB.open('b2-naive-control'); r.onupgradeneeded = () => r.result.createObjectStore('c'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    const get = (): Promise<number> => new Promise((res, rej) => { const q = db.transaction('c', 'readonly').objectStore('c').get('n'); q.onsuccess = () => res((q.result as number | undefined) ?? 0); q.onerror = () => rej(q.error); });
    const put = (v: number): Promise<void> => new Promise((res, rej) => { const tx = db.transaction('c', 'readwrite'); tx.objectStore('c').put(v, 'n'); tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error); });
    await put(0);
    await Promise.all(Array.from({ length: n }, async () => { const v = await get(); await new Promise((r) => setTimeout(r, 1)); await put(v + 1); }));
    const final = await get();
    db.close();
    return final;
  },
};
