// src/lib/messaging/reset-flag-store.ts
// #720 R4: the reset flag as an encrypted row in the per-owner notes DB's 'settings' store (same rows API as dead-letter-store.ts; no schema
// bump). Reads THROW while the store is locked, so a caller can tell "locked" from "not set".
import { deleteEncryptedSetting, getEncryptedSetting, listEncryptedSettings, putEncryptedSetting } from './store';
import { RESET_FLAG_PREFIX, normalizeResetFp, parseResetFlagRow, resetFlagKey, type ResetFlagRow } from './reset-flag';

function keyOrThrow(peerFp: string): string {
  const key = resetFlagKey(peerFp);
  if (!key) throw new Error('unsafe contact fingerprint');
  return key;
}

/** The user's reset of this contact completed. THROWS when the store is locked or unwritable (a repeated reset sets it again). */
export async function setResetFlag(peerFp: string, resetAtIso: string): Promise<void> {
  const fp = normalizeResetFp(peerFp);
  const row = parseResetFlagRow({ fp, reset_at: resetAtIso });
  if (!fp || !row) throw new Error('invalid reset flag');
  await putEncryptedSetting(keyOrThrow(fp), row satisfies ResetFlagRow);
}

export async function hasResetFlag(peerFp: string): Promise<boolean> {
  return parseResetFlagRow(await getEncryptedSetting<unknown>(keyOrThrow(peerFp))) !== null;
}

/** Every contact this device has reset and not heard from since (fingerprints, lowercase hex). A row that fails validation, or whose key and fp disagree, is skipped. */
export async function listResetFlags(): Promise<string[]> {
  const out: string[] = [];
  for (const { key, value } of await listEncryptedSettings<unknown>(RESET_FLAG_PREFIX)) {
    const row = parseResetFlagRow(value);
    if (row && key === `${RESET_FLAG_PREFIX}${row.fp}`) out.push(row.fp);
  }
  return out.sort();
}

/**
 * A frame from this contact opened: the flag is over. Reads first, so the common case (no flag) costs one read and no write.
 * Returns whether a flag was cleared. THROWS on a locked store; the caller treats it as best effort (the next opened frame clears it).
 */
export async function clearResetFlagIfSet(peerFp: string): Promise<boolean> {
  const key = resetFlagKey(peerFp);
  if (!key) return false;
  if (!(await getEncryptedSetting<unknown>(key))) return false;
  await deleteEncryptedSetting(key);
  return true;
}
