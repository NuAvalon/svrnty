// Browser-side harness for the REAL notes store (the encrypted IndexedDB one), bundled by esbuild and injected into a page. It exposes the store's own functions
// and a RAW row reader, so a spec can check both behaviour (which reader returns a held note) and what is at rest (which plaintext keys a held row has).
import { initNotesStore, putThread, putNoteReportingCreated, listThreads, listNotesForThread, listThreadsIncludingHeld, listNotesIncludingHeld, countHeldFrom, deleteThread, getNote, listInboundSentAtFrom } from '../../src/lib/messaging/store';
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
  init: (owner) => initNotesStore('e2e-passphrase-1234', owner),
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
};
