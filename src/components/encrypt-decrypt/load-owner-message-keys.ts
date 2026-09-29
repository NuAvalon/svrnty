// Load SenderKeys + MyKeys for the unlocked session. I/O only; crypto is fleet.

import { loadKey, loadPQKeys } from '@/lib/identity/client-store';
import {
  assembleOwnerMessageKeys,
  parseStoredPqBundle,
  pqPubsFromIdentity,
  unlockArmoredIdentityKey,
  type OwnerMessageKeys,
} from './encrypt-decrypt-keys';

export async function loadOwnerMessageKeys(
  fingerprint: string,
  identity: unknown,
): Promise<OwnerMessageKeys | null> {
  const key = await loadKey(fingerprint);
  if (!key?.privateKey) return null;
  const pqStored = await loadPQKeys(fingerprint);
  const pq = parseStoredPqBundle(pqStored, pqPubsFromIdentity(identity));
  if (!pq) return null;
  const unlocked = await unlockArmoredIdentityKey(key.privateKey, key.passphrase);
  return assembleOwnerMessageKeys(unlocked, pq);
}
