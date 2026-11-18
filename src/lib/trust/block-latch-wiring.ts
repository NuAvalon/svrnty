// src/lib/trust/block-latch-wiring.ts: the ONE module the screens call for Block, Unblock and Remove, so the contact book and the trust map cannot drift apart. It binds
// the injected orchestration in block-latch.ts to the real store, the real latch and the real suppression write. DARK: nothing here sends a request (blockLatchPortsFor writes the same
// LOCAL latch createBeaconWire writes while the wire is OFF; when the beacon client gets its first importer that moves to wire.client.removeAtTap, a go-live gate).
//
// It lives here and not in client-store.ts because block-suppression.ts already imports client-store: importing it back would be a cycle.
import { blockLatchPortsFor, recordRemovedContact, removeContact } from '@/lib/identity/client-store';
import { applyBlockSuppression } from '@/lib/trust/block-suppression';
import { blockWithLatch, removeWithLatch, unblockKeepingLatch } from '@/lib/trust/block-latch';

export { BlockUnfinishedError } from '@/lib/trust/block-latch';

/** Remove a contact: record the removal, set the latch, then delete (a keyless contact is simply deleted). The caller wraps this in withSafetyWrite. */
export function removeContactWithLatch(ownerFingerprint: string, contactId: string, durableId: string | null | undefined): Promise<void> {
  return removeWithLatch({
    durableId: durableId ?? '',
    ...blockLatchPortsFor(ownerFingerprint),
    recordRemoved: (id) => recordRemovedContact(ownerFingerprint, id),
    removeContactRecord: () => removeContact(contactId),
  });
}

/**
 * Block or Unblock. `writeBlockFlag` is the screen's own flag write (it takes the safety locks). Block: latch, flag, then the AWAITED suppression write; `finished` is false when that write
 * did not finish, and the screen then throws BlockUnfinishedError AFTER it has refreshed. Unblock leaves the latch (a later Trust tap clears its own) and is `finished` as before.
 */
export async function setContactBlocked(
  ownerFingerprint: string,
  durableId: string | null | undefined,
  blocked: boolean,
  writeBlockFlag: () => Promise<void>,
): Promise<{ finished: boolean }> {
  const applySuppression = () => applyBlockSuppression(ownerFingerprint, durableId, blocked);
  if (!blocked) {
    await unblockKeepingLatch({ writeBlockFlag, applySuppression });
    return { finished: true };
  }
  const r = await blockWithLatch({ peerDurableId: durableId, ...blockLatchPortsFor(ownerFingerprint), writeBlockFlag, applySuppression });
  return { finished: r.finished };
}
