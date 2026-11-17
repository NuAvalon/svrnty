// e2e/helpers/suppression-restore-harness.ts
// Bundled by esbuild and injected into the page by e2e/suppression-restore.spec.ts. It drives the app's REAL store (IndexedDB, the sealed settings rows, the session key) from inside
// the page: every write and read goes through the same functions the export and restore call. The only thing done outside them is corrupt(), which damages a stored row on purpose so the
// "left out" case is a real unreadable record, not a stub.
import {
  initSessionKey, getActiveFingerprint, updateSuppressionRecord, getSuppressionRecord, readRemovedList, readPendingGlobalOff, recordRemovedContact,
  readSuppressionCarryStatus, restoreCarriedSuppression, confirmGlobalOffAfterRestore,
} from '@/lib/identity/client-store';

type Rec = { global: boolean; groups: string[]; persons: string[] };

declare global {
  interface Window {
    __sup: {
      init(passphrase: string): Promise<void>;
      owner(): Promise<string | null>;
      seed(owner: string, rec: Rec): Promise<void>;
      remove(owner: string, durableId: string): Promise<void>;
      status(owner: string): Promise<string>;
      read(owner: string): Promise<{ record: Rec | null; removed: unknown; pending: unknown }>;
      restore(owner: string, carried: unknown, backupAt: string): Promise<unknown>;
      confirm(owner: string): Promise<string>;
      corrupt(owner: string): Promise<void>;
    };
  }
}

window.__sup = {
  init: (passphrase) => initSessionKey(passphrase) as unknown as Promise<void>,
  owner: () => getActiveFingerprint(),
  seed: async (owner, rec) => { await updateSuppressionRecord(owner)(() => ({ write: rec, result: true })); },
  remove: (owner, id) => recordRemovedContact(owner, id),
  status: (owner) => readSuppressionCarryStatus(owner),
  read: async (owner) => ({ record: await getSuppressionRecord(owner), removed: await readRemovedList(owner), pending: await readPendingGlobalOff(owner) }),
  restore: (owner, carried, backupAt) => restoreCarriedSuppression(owner, carried, backupAt),
  confirm: (owner) => confirmGlobalOffAfterRestore(owner),
  // Flip the first character of the stored ciphertext: the AES-GCM tag no longer matches, so the row exists but cannot be read.
  corrupt: (owner) => new Promise<void>((resolve, reject) => {
    const open = indexedDB.open('svrnty');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction('settings', 'readwrite');
      const store = tx.objectStore('settings');
      const get = store.get(`suppression:${owner}`);
      get.onsuccess = () => {
        const row = get.result as { key: string; value?: { ciphertext: string } } | undefined;
        if (!row?.value) { reject(new Error('no suppression row to corrupt')); return; }
        const c = row.value.ciphertext;
        row.value.ciphertext = (c[0] === 'A' ? 'B' : 'A') + c.slice(1);
        store.put(row);
      };
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => reject(tx.error);
    };
  }),
};
