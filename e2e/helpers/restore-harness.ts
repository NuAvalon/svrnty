// e2e/helpers/restore-harness.ts
// Bundled by esbuild and injected into the page by e2e/restore-with-password.spec.ts (page script policy off). It drives the app's own store functions
// against the REAL IndexedDB so the spec can build a backup, seed a device that already holds an owner, and read the state back.
import {
  initSessionKey, lockSession, exportAll, addContact, storeKey, storeVault, verifyPassphrase,
  loadIdentity, loadKey, loadPQKeys, loadDeviceMailbox, getAllContacts,
} from '@/lib/identity/client-store';
import { serializeMailboxKeypair } from '@/lib/crypto/mailbox-keys';

declare global { interface Window { __rh: Record<string, (...a: any[]) => Promise<any>> } }

window.__rh = {
  async all(fp: string, pw: string) { await initSessionKey(pw); return exportAll(fp, true); },
  async addContacts(fp: string, pw: string, rows: any[]) { await initSessionKey(pw); for (const r of rows) await addContact(fp, r); lockSession(); return true; },
  /** A device that holds the owner's key under `pwKeys` and, when given, a vault under `pwVault` (the mixed device). No identity row: the gate shows. */
  async seed(fp: string, keys: { privateKey: string; passphrase: string }, pwKeys: string, pwVault?: string) {
    await initSessionKey(pwKeys); await storeKey(fp, keys.privateKey, keys.passphrase);
    if (pwVault) { await initSessionKey(pwVault); await storeVault(fp, { seeded: true }); }
    lockSession(); return true;
  },
  /** The other mixed device: the owner's key under `pwKeys` and one encrypted contact row under `pwContact` (same device salt, a different passphrase). */
  async seedKeyAndContact(fp: string, keys: { privateKey: string; passphrase: string }, pwKeys: string, pwContact: string, row: any) {
    await initSessionKey(pwKeys); await storeKey(fp, keys.privateKey, keys.passphrase);
    await initSessionKey(pwContact); await addContact(fp, row);
    lockSession(); return true;
  },
  async verify(fp: string, pw: string) { return verifyPassphrase(fp, pw); },
  /** The logical state of the owner after a restore, read under `pw`. Volatile fields (ids, added_at) are left out. */
  async snapshot(fp: string, pw: string) {
    await initSessionKey(pw);
    const mailbox = await loadDeviceMailbox(fp);
    const contacts = (await getAllContacts(fp)).map((c: any) => ({ name: c.name, email: c.email, fingerprint: c.fingerprint ?? null, blocked: !!c.blocked, metaBlocked: !!c.metadata?.blocked, trust: c.trust_level }))
      .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
    const out = { identity: await loadIdentity(fp), key: await loadKey(fp), pq: await loadPQKeys(fp), mailbox: mailbox ? serializeMailboxKeypair(mailbox) : null, contacts };
    lockSession(); return out;
  },
};
