// src/lib/messaging/adopt-floor-store.ts
// L-318a: the adopt floor as an encrypted row in the per-owner notes DB's 'settings' store (same rows API as reset-flag-store.ts; no schema bump).
// Reads THROW while the store is locked, so a caller can tell "locked" from "no floor".
import { getEncryptedSetting, putEncryptedSetting } from './store';
import { adoptFloorKey, parseAdoptFloorRow, raisedFloor, type AdoptFloorRow } from './adopt-floor';
import { normalizeResetFp } from './reset-flag';

/** The stored floor for this contact (ISO), or undefined when there is none or the row fails validation. THROWS when the store is locked. */
export async function getAdoptFloor(peerFp: string): Promise<string | undefined> {
  const key = adoptFloorKey(peerFp);
  if (!key) return undefined;
  return parseAdoptFloorRow(await getEncryptedSetting<unknown>(key))?.sent_at;
}

/**
 * A session with this contact was just created or adopted from a first frame signed `sentAtIso`: raise the floor to it (never lower it).
 * Reads first, so an unchanged floor costs one read and no write. THROWS on a locked store; the caller treats it as best effort (the
 * floor then stays where it was, which is the pre-L-318a behaviour, never a stricter one).
 */
export async function raiseAdoptFloor(peerFp: string, sentAtIso: string): Promise<boolean> {
  const fp = normalizeResetFp(peerFp);
  const key = adoptFloorKey(peerFp);
  if (!fp || !key) return false;
  const next = raisedFloor(await getAdoptFloor(fp), sentAtIso, Date.now());
  if (next === null) return false;
  await putEncryptedSetting(key, { fp, sent_at: next } satisfies AdoptFloorRow);
  return true;
}
