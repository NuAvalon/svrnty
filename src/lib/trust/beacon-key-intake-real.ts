// src/lib/trust/beacon-key-intake-real.ts — #956 S1b: the REAL ports for beacon-key-intake.ts, wired to the sealed stores.
//
// This is the only place that connects the key replacement to storage. It is small on purpose: every decision is in beacon-key-intake.ts and
// beacon-key-replace.ts, which are tested with fakes; this file is exercised by the browser spec against the real stores.
import {
  beaconPairIdFor, createBeaconConfirmedPort, createBeaconPorts, destroyBeaconSeedsAndStartOver, readBeaconKeyRecord, readBeaconSeeds, updateBeaconSeeds, updateContactIf,
} from '../identity/client-store';
import { secretOf } from '../identity/beacon-key-record';
import { checkBeaconPublicKey } from '../crypto/beacon-key';
import { replaceContactBeaconKeyWith, type KeyIntakePorts, type ReplaceTarget } from './beacon-key-intake';
import type { KeyReplaceOutcome } from './beacon-key-replace';

export function realKeyIntakePorts(ownerFingerprint: string): KeyIntakePorts {
  return {
    pairIdFor: beaconPairIdFor,
    decodeKey: async (publicKey) => {
      const c = await checkBeaconPublicKey(publicKey);
      return c.ok ? ([c.point[0], c.point[1]] as const) : null;
    },
    ownSecret: async () => {
      const r = await readBeaconKeyRecord(ownerFingerprint);
      if (r.state === 'none') return undefined;                            // no beacon key was ever held: nothing could have been deposited from here
      if (r.state === 'unreadable') throw new Error('the beacon key is held but cannot be read');   // never "none": a key we cannot read proves nothing about the rows
      return secretOf(r.record);
    },
    seeds: {
      read: () => readBeaconSeeds(ownerFingerprint),
      update: (mutate) => updateBeaconSeeds(ownerFingerprint, mutate),
      reset: () => destroyBeaconSeedsAndStartOver(ownerFingerprint),
    },
    store: createBeaconPorts(ownerFingerprint).store,
    confirmed: createBeaconConfirmedPort(ownerFingerprint),
    writeKeyIf: async (contactId, expected, next) => {
      const r = await updateContactIf(contactId, (cur) =>
        cur.beacon_public_key === expected.publicKey && cur.beacon_key_generation === expected.generation
          ? { beacon_public_key: next.publicKey, beacon_key_generation: next.generation }
          : null);
      return r.applied;
    },
    now: () => Date.now(),
    onUnexpected: (where, err) => console.error('beacon key replacement:', where, err),
  };
}

/** What a screen calls on a 'replace' verdict. Never throws: every failure is a refusal that leaves the saved key unchanged. */
export async function replaceContactBeaconKey(ownerFingerprint: string, target: ReplaceTarget): Promise<KeyReplaceOutcome> {
  try {
    return await replaceContactBeaconKeyWith(realKeyIntakePorts(ownerFingerprint), target);   // building the ports can throw too (a locked session)
  } catch {
    return { kind: 'refused' };
  }
}
