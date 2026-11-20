// e2e/helpers/beacon-confirmed-harness.ts
// Bundled by esbuild and injected into the page by e2e/beacon-confirmed-generation.spec.ts (page script policy off). It drives the app's own store functions against the REAL IndexedDB: the real
// confirmed row, the real contact book, and the real production confirmed port the beacon client asks.
import { initSessionKey, lockSession, addContact, updateContact, getAllContacts, beaconPairIdFor, markBeaconPairConfirmed, createBeaconConfirmedPort } from '@/lib/identity/client-store';

type Held = { id: string; fingerprint: string | undefined; beacon_public_key: string | undefined; beacon_key_generation: number | undefined };
declare global {
  interface Window {
    __bc: {
      init(pw: string): Promise<void>;
      lock(): Promise<void>;
      pairId(fp: string): Promise<string>;
      setBeaconKey(contactId: string, key: string, generation: number): Promise<void>;
      addKeyless(owner: string): Promise<void>;
      confirm(owner: string, contactFingerprint: string, generation: number): Promise<void>;
      isConfirmed(owner: string, pairId: string): Promise<boolean>;
      held(owner: string): Promise<Held[]>;
    };
  }
}

window.__bc = {
  /** Unlock a session from the typed passphrase (the same keys the app derived: same device salt). */
  init: async (pw: string) => { await initSessionKey(pw); },
  lock: async () => { lockSession(); },
  /** The LOCAL pair id of the pair with this contact on this device. */
  pairId: (fp: string) => beaconPairIdFor(fp),
  /** What a later replace would write on the contact: the held beacon key and its generation. */
  setBeaconKey: async (contactId: string, key: string, generation: number) => { await updateContact(contactId, { beacon_public_key: key, beacon_key_generation: generation } as never); },
  /** A contact with no key and so no fingerprint: it has no pair, and the scan for a pair id must step over it. */
  addKeyless: async (owner: string) => { await addContact(owner, { name: 'Keyless', email: 'keyless@example.test', public_key: '', fingerprint: '', trust_level: 'known' } as never); },
  /** The ONLY writer of the confirmed row (a live confirm); monotone upward. It takes the CONTACT's fingerprint and derives the pair id itself. */
  confirm: async (owner: string, contactFingerprint: string, generation: number) => { await markBeaconPairConfirmed(owner, contactFingerprint, generation); },
  /** The production port, as the beacon client asks it. */
  isConfirmed: (owner: string, pairId: string) => createBeaconConfirmedPort(owner).isConfirmed(pairId),
  /** What the contact book holds for each contact (id, fingerprint as stored, held beacon key and generation): the precondition a spec checks before it asks the port. */
  held: async (owner: string) => (await getAllContacts(owner)).map((c) => ({ id: c.id, fingerprint: c.fingerprint, beacon_public_key: c.beacon_public_key, beacon_key_generation: c.beacon_key_generation })),
};
