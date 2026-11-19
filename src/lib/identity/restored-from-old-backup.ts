// src/lib/identity/restored-from-old-backup.ts: the owner's "restored from an older backup" marker, and the two decisions around it. PURE: no storage, no screen, no clock of its own.
//
// What it is for. A backup in the older format can only be restored with the passphrase; a new backup also opens with the recovery code. After such a restore the owner is shown ONE
// notice on their Identity tab until they make a new backup. The notice has to outlive the restore screen (that screen is gone by then), so the fact is kept as one small sealed owner
// record (client-store.ts, listed in OWNER_SEALED_SETTINGS like the other owner records).
//
// Rules this file holds, each pinned by restored-from-old-backup.test.ts:
//  - WRITTEN only by a restore of an older-format file, and only when that restore stored a recovery vault (the restored contents carry one). A device with no recovery vault makes
//    a new backup with no recovery envelope, so the notice would promise what the new file cannot keep: it is not written.
//  - CLEARED only by a finished export of the new (sealed, vault) backup. Never by the Dismiss button, never by a plaintext or legacy export path.
//  - NEVER part of any backup: exportAll and the vault payload do not carry it (a restore of the new backup must not come back with the notice already set).
//  - A marker that is absent or cannot be read shows nothing. The notice is a reminder, not a gate; the restore screen's own hint still warns before the restore.
/** What a sealed owner record reads as (the same shape as the trust code's SealedRead, declared here so this pure file imports nothing from it). */
export type OwnerRecordRead<T> = { state: 'ok'; value: T } | { state: 'absent' } | { state: 'unreadable' };

/** The stored marker: exact keys, version 1. `restored_at` is when the restore finished (plain ISO time). */
export interface RestoredFromOldBackup {
  v: 1;
  restored_at: string;
}

const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/; // the anchored pattern also bounds the length

/** The strict reader for the stored marker. Null means unreadable. */
export function parseRestoredFromOldBackup(x: unknown): RestoredFromOldBackup | null {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return null;
  const r = x as Record<string, unknown>;
  const keys = Object.keys(r);
  if (keys.length !== 2 || !keys.includes('v') || !keys.includes('restored_at')) return null;
  if (r.v !== 1) return null;
  if (typeof r.restored_at !== 'string' || !ISO_TIME.test(r.restored_at)) return null;
  return { v: 1, restored_at: r.restored_at };
}

/**
 * The marker a restore should leave, or null for none. `headerVersion` is the file's own header version; `recovery` is the restored contents' recovery vault (what the restore stores,
 * and what the next backup packs). Only an older-format (3) file, and only with a vault in it.
 */
export function markerForRestore(headerVersion: number | undefined, recovery: unknown, now: Date): RestoredFromOldBackup | null {
  if (headerVersion !== 3) return null;
  if (!recovery) return null;
  return { v: 1, restored_at: now.toISOString() };
}

/** Whether the notice shows: only a readable marker, and not dismissed this session. Absent and unreadable both show nothing. */
export function shouldShowRestoredNudge(read: OwnerRecordRead<RestoredFromOldBackup>, dismissedThisSession: boolean): boolean {
  if (dismissedThisSession) return false;
  return read.state === 'ok';
}
