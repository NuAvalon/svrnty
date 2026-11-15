// e2e/helpers/restore-harness.ts
// Bundled by esbuild and injected into the page by e2e/restore-with-password.spec.ts (page script policy off). It drives the app's own store functions
// against the REAL IndexedDB so the spec can build a backup, seed a device that already holds an owner, and read the state back.
import {
  initSessionKey, lockSession, exportAll, addContact, storeKey, storeVault, verifyPassphrase,
  removeContact, loadIdentity, loadKey, loadPQKeys, loadDeviceMailbox, getAllContacts, storeIdentity, storeDeviceMailbox, writeDeliveryDefault,
  setSuppressionRecord, setHeldAffirmatives, writeLensGrantBook, setBeaconSeedsUnsafeForTest, ensureBeaconKeyRecord,
  markBeaconPairConfirmed, createBeaconPorts,
} from '@/lib/identity/client-store';
import { serializeMailboxKeypair } from '@/lib/crypto/mailbox-keys';
import { emptySuppression } from '@/lib/trust/suppression';

declare global { interface Window { __rh: Record<string, (...a: any[]) => Promise<any>> } }

/** One owner-sealed settings record (by its name in OWNER_SEALED_SETTINGS), written by that record's own writer. Needs an unlocked session. */
async function writeSealed(fp: string, name: string) {
  if (name === 'suppression') await setSuppressionRecord(fp, emptySuppression());
  else if (name === 'held-affirms') await setHeldAffirmatives(fp, {});
  else if (name === 'delivery-default') await writeDeliveryDefault(fp, { v: 1, value: 'unknown' });
  else if (name === 'lens-book') await writeLensGrantBook(fp, '{}');
  else if (name === 'beacon-seeds') await setBeaconSeedsUnsafeForTest(fp, {});
  else if (name === 'beacon-key') await ensureBeaconKeyRecord(fp);
  // The ONLY test caller of the confirm writer: a confirmed row is the record under test here, and no product code path may write one.
  else if (name === 'beacon-confirmed') await markBeaconPairConfirmed(fp, '4c'.repeat(32), 1);
  else throw new Error(`unknown sealed record ${name}`);
}

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
  /** A device that holds the owner whole (identity row + key + device mailbox under `pw`, so the unlock step has nothing to heal) but has NO receipts default: a restore rewrites the identity row byte for byte, writes the receipts default, then fails at the key. */
  async seedHeldFull(fp: string, keys: { privateKey: string; passphrase: string }, identity: any, mailbox: any, pw: string) {
    await initSessionKey(pw); await storeIdentity(fp, identity); await storeKey(fp, keys.privateKey, keys.passphrase); await storeDeviceMailbox(fp, mailbox);
    lockSession(); return true;
  },
  /** The key (and a contact, when `row` is given) under `pwA`, the owner's receipts default under `pwB` (same device salt): the receipts record is the one that does not open. */
  async seedKeyContactDelivery(fp: string, keys: { privateKey: string; passphrase: string }, pwA: string, pwB: string, row: any) {
    await initSessionKey(pwA); await storeKey(fp, keys.privateKey, keys.passphrase); if (row) await addContact(fp, row);
    await initSessionKey(pwB); await writeDeliveryDefault(fp, { v: 1, value: 'unknown' });
    lockSession(); return true;
  },
  /** The key under `pwA`, and ONE owner-sealed settings record (by its name in OWNER_SEALED_SETTINGS) under `pwB`, written by that record's own writer. */
  async seedKeyAndSealed(fp: string, keys: { privateKey: string; passphrase: string }, pwA: string, pwB: string, name: string) {
    await initSessionKey(pwA); await storeKey(fp, keys.privateKey, keys.passphrase);
    await initSessionKey(pwB);
    await writeSealed(fp, name);
    lockSession(); return true;
  },
  /** The key under `pwA`, and ONE beacon row (a pair record, or a local / remote latch) written by the app's own ports under `pwB`. pwA === pwB makes it the one-domain control. */
  async seedKeyAndBeaconRow(fp: string, keys: { privateKey: string; passphrase: string }, pwA: string, pwB: string, kind: 'pair' | 'latch-local' | 'latch-remote') {
    await initSessionKey(pwA); await storeKey(fp, keys.privateKey, keys.passphrase);
    await initSessionKey(pwB);
    const ports = createBeaconPorts(fp);
    const pairId = 'a1'.repeat(32);
    if (kind === 'pair') {
      const wrote = await ports.store.cas(pairId, 0, { pairId, observedMatch: false, spentEpochs: [], refusedEpochs: [], rows: [], pendingWithdraws: [], version: 1 });
      if (!wrote) throw new Error('the pair row was not written');
    } else await ports.latch.setLatched(pairId, kind === 'latch-local' ? 'local' : 'remote');
    lockSession(); return true;
  },
  /** The key and a LOCAL latch row under `pwA`, and a second, REMOTE latch row under `pwB`: two rows of ONE collection, the first (in key order) openable under the key's passphrase. */
  async seedKeyAndTwoLatchRows(fp: string, keys: { privateKey: string; passphrase: string }, pwA: string, pwB: string) {
    await initSessionKey(pwA); await storeKey(fp, keys.privateKey, keys.passphrase);
    await createBeaconPorts(fp).latch.setLatched('a1'.repeat(32), 'local');
    await initSessionKey(pwB);
    await createBeaconPorts(fp).latch.setLatched('b2'.repeat(32), 'remote');
    lockSession(); return true;
  },
  /** ONLY one owner-sealed settings record under `pw` (no key, no contact): what a partial wipe can leave. */
  async seedSealedOnly(fp: string, pw: string, name: string) { await initSessionKey(pw); await writeSealed(fp, name); lockSession(); return true; },
  /** ONLY the contact book manifest under `pw`: a contact added and removed again leaves the empty book's manifest (a MAC, not a sealed record), with no key and no contact row. */
  async seedContactManifestOnly(fp: string, pw: string, row: Parameters<typeof addContact>[1]) { await initSessionKey(pw); const c = await addContact(fp, row); await removeContact(c.id); lockSession(); return true; },
  /** ONLY a beacon row under `pw` (a local latch, or a pair record): no key, no contact, nothing else: the state left when an identity's keys are cleared but its settings rows are not. */
  async seedBeaconRowOnly(fp: string, pw: string, kind: 'pair' | 'latch-local') {
    await initSessionKey(pw);
    const ports = createBeaconPorts(fp);
    const pairId = 'a1'.repeat(32);
    if (kind === 'pair') {
      const wrote = await ports.store.cas(pairId, 0, { pairId, observedMatch: false, spentEpochs: [], refusedEpochs: [], rows: [], pendingWithdraws: [], version: 1 });
      if (!wrote) throw new Error('the pair row was not written');
    } else await ports.latch.setLatched(pairId, 'local');
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
