// e2e/helpers/block-latch-harness.ts
// Bundled by esbuild and injected into the page by e2e/block-latch-idb.spec.ts. It runs the app's REAL stores (IndexedDB, AES-GCM, the book manifest) and the REAL latch helpers from inside the
// page. Nothing here stands in for the thing under test: Block / Unblock / Remove go through setContactBlocked / removeContactWithLatch exactly as the two screens call them, and the
// latch rows are read from the real settings store.
import {
  initSessionKey, addContact, updateContact, getContact, getAllContacts, getSuppressionRecord, readRemovedList, updateSuppressionRecord,
  createBeaconPorts, beaconPairIdFor, listIdentities, repairSuppressionRecord, repairSuppressionOrRefuse, relatchBlocksForOwner,
} from '@/lib/identity/client-store';
import { setContactBlocked, removeContactWithLatch } from '@/lib/trust/block-latch-wiring';
import { blockPatch } from '@/lib/contacts/metadata-patches';
import { emptySuppression } from '@/lib/trust/suppression';

type Kind = 'removed' | 'frozen' | null;

declare global {
  interface Window {
    __bl: {
      init(passphrase: string): Promise<void>;
      add(owner: string, name: string, fingerprint: string): Promise<string>;
      /** What the genesis init writes: an EXPLICIT empty suppression record, only when none is stored. */
      initRecord(owner: string): Promise<void>;
      block(owner: string, id: string, fingerprint: string, blocked: boolean): Promise<{ finished: boolean }>;
      /** The block flag alone (what a Block whose later steps did not run would leave). */
      flagOnly(id: string, blocked: boolean): Promise<void>;
      remove(owner: string, id: string, fingerprint: string): Promise<void>;
      latchKind(owner: string, fingerprint: string): Promise<Kind>;
      latchRows(): Promise<number>;
      record(owner: string): Promise<{ persons: string[]; global: boolean } | null>;
      removedList(owner: string): Promise<string[] | 'absent' | 'unreadable'>;
      isBlocked(id: string): Promise<boolean>;
      has(id: string): Promise<boolean>;
      repair(owner: string): Promise<string>;
      gate(owner: string): Promise<'ok' | string>;
      relatch(owner: string): Promise<{ outcome: string; latched: number; failed: number }>;
      /** A restore's effect, minus the rebuild: the record and the removed list name people, no latch exists. */
      plantRecord(owner: string, persons: string[]): Promise<void>;
      ownerFp(): Promise<string>;
      /** What a Trust tap does to its own pair's local latch (beacon-client.ts): clear it. */
      trustTapClears(owner: string, fingerprint: string): Promise<void>;
      /** TEST-ONLY construction: give a contact the raw fingerprint a real bound-key contact carries inside its ciphertext (addContact refuses one without a key). */
      setFingerprint(id: string, fingerprint: string): Promise<void>;
      /** DIAGNOSTIC: what getAllContacts returns for this owner (shape only). */
      dump(owner: string): Promise<Array<{ id: string; fingerprint: unknown; blocked: unknown; metaBlocked: unknown; keys: string[] }>>;
    };
  }
}

/** The settings rows of the app's database: the real app holds more than one IndexedDB, so pick the one that has a `settings` store. */
const rawKeys = async (): Promise<string[]> => {
  for (const info of await indexedDB.databases()) {
    const db: IDBDatabase = await new Promise((res, rej) => { const r = indexedDB.open(info.name as string); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
    try {
      if (!db.objectStoreNames.contains('settings')) continue;
      return await new Promise<string[]>((res, rej) => { const q = db.transaction('settings', 'readonly').objectStore('settings').getAllKeys(); q.onsuccess = () => res(q.result as string[]); q.onerror = () => rej(q.error); });
    } finally { db.close(); }
  }
  throw new Error('no database with a settings store');
};

window.__bl = {
  init: (p) => initSessionKey(p) as unknown as Promise<void>,
  add: async (owner, name, fingerprint) => (await addContact(owner, { name, email: '', public_key: '', fingerprint, trust_level: 'unverified' } as never)).id,
  initRecord: async (owner) => { await updateSuppressionRecord(owner)((held) => (held.state === 'absent' ? { write: emptySuppression(), result: undefined } : { result: undefined })); },
  block: (owner, id, fingerprint, blocked) => setContactBlocked(owner, fingerprint, blocked, async () => { await updateContact(id, (fresh) => blockPatch(fresh, blocked)); }),
  flagOnly: async (id, blocked) => { await updateContact(id, (fresh) => blockPatch(fresh, blocked)); },
  remove: (owner, id, fingerprint) => removeContactWithLatch(owner, id, fingerprint),
  latchKind: async (owner, fingerprint) => createBeaconPorts(owner).latch.kindOf(await beaconPairIdFor(fingerprint), 'local'),
  latchRows: async () => (await rawKeys()).filter((k) => k.startsWith('beacon_latch:')).length,
  record: async (owner) => { const r = await getSuppressionRecord(owner); return r ? { persons: [...r.persons], global: r.global } : null; },
  removedList: async (owner) => { const r = await readRemovedList(owner); return r.state === 'ok' ? [...r.value] : r.state; },
  isBlocked: async (id) => { const c = (await getContact(id)) as { blocked?: unknown; metadata?: { blocked?: unknown } } | null; return !!(c && (c.blocked || c.metadata?.blocked)); },
  has: async (id) => (await getContact(id)) !== null && (await getContact(id)) !== undefined,
  repair: (owner) => repairSuppressionRecord(owner),
  gate: async (owner) => { try { await repairSuppressionOrRefuse(owner); return 'ok'; } catch (e) { return (e as { code?: string }).code ?? (e as Error).name; } },
  relatch: (owner) => relatchBlocksForOwner(owner),
  trustTapClears: async (owner, fingerprint) => { await createBeaconPorts(owner).latch.clearLatched(await beaconPairIdFor(fingerprint), 'local'); },
  ownerFp: async () => (await listIdentities())[0]?.fingerprint ?? '',
  setFingerprint: async (id, fingerprint) => { await updateContact(id, { fingerprint } as never); },
  dump: async (owner) => (await getAllContacts(owner)).map((c) => { const r = c as unknown as { id: string; fingerprint?: unknown; blocked?: unknown; metadata?: { blocked?: unknown } }; return { id: r.id, fingerprint: r.fingerprint, blocked: r.blocked, metaBlocked: r.metadata?.blocked, keys: Object.keys(r).sort() }; }),
  plantRecord: async (owner, persons) => {
    await updateSuppressionRecord(owner)((held) => ({ write: { ...(held.state === 'ok' ? held.value : emptySuppression()), persons }, result: undefined }));
  },
};

