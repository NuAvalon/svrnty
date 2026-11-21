// src/lib/trust/beacon-confirm-wiring.ts: binds the confirm glue to the real store. DARK: nothing imports this file yet (a screen will, behind the beacon switch).
// Own key: the STRICT reader (never creates a key). Held key and the contact's fingerprint: the owner's own contact list, found by the contact id. Lock: the contact lock of the safety writes.
// Write: the one function that records a confirmed pair. The hook: the store's session-lock hook, which fires on a lock and on every switch of identity.
import { readBeaconKeyRecord, getAllContacts, markBeaconPairConfirmed, onSessionLock } from '../identity/client-store';
import { publicKeyOf } from '../identity/beacon-key-record';
import { withSafetyWrite } from '../contacts/safety-write';
import { createConfirmGlue, type ConfirmGlue, type GlueOptions, type GluePorts } from './beacon-confirm-glue';

export function createBeaconConfirmGlue(ownerFingerprint: string, opts?: GlueOptions): ConfirmGlue {
  const contactOf = async (contactId: string) => (await getAllContacts(ownerFingerprint)).find((c) => c.id === contactId);
  const ports: GluePorts = {
    async readOwn() {
      const r = await readBeaconKeyRecord(ownerFingerprint);
      return r.state === 'held' ? { publicKey: await publicKeyOf(r.record), generation: r.record.key_generation } : undefined;
    },
    async readHeld(contactId) {
      const c = await contactOf(contactId);
      return c && typeof c.beacon_public_key === 'string' && typeof c.beacon_key_generation === 'number' ? { publicKey: c.beacon_public_key, generation: c.beacon_key_generation } : undefined;
    },
    withContactLock: (contactId, run) => withSafetyWrite(contactId, run),
    async writeConfirmed(contactId, generation) {
      const c = await contactOf(contactId);
      if (!c) throw new Error('beacon confirm: no such contact');
      await markBeaconPairConfirmed(ownerFingerprint, c.fingerprint, generation);
    },
    onLock: onSessionLock,
  };
  return createConfirmGlue(ports, opts);
}
