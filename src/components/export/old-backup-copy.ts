// src/components/export/old-backup-copy.ts
// The words about a backup made in the older format (copy ledger rows 329a, 329b and the two buttons). Reviewed copy: do not reword it here; a change needs the copy owner's new row and
// new hash. Plain ASCII, straight apostrophes.
//   - They say what the owner can do and why: a new backup can also be restored with the recovery code. They name no format number and promise no social recovery (it is not built).
//   - Not now hides the notice for this session only; it comes back on the next load until a new backup has been made.
// Run: npx tsx --test src/components/export/old-backup-copy.test.ts

/** Row 329a (175 chars, sha256 prefix 697091a9f466eb77): under the file's details on the restore screen, before the restore. */
export const OLD_BACKUP_PRE_RESTORE_HINT = 'This backup is from an older version, so it can only be restored with your passphrase. After you restore it, make a new backup so you can also restore with your recovery code.';
/** Row 329b (169 chars, de59608988bc7d47): the notice on the Identity tab after such a restore. */
export const OLD_BACKUP_NOTICE = 'This backup could only be restored with your passphrase. Make a new backup now, so that if you ever lose your passphrase you can restore with your recovery code instead.';
/** Row 329b: the two buttons. Make a new backup opens the existing Full Backup flow and nothing else; Not now hides the notice for this session. */
export const OLD_BACKUP_MAKE_NEW = 'Make a new backup'; // 17 chars, d98cf9e9ac8384b2
export const OLD_BACKUP_NOT_NOW = 'Not now'; // 7 chars, a0e63d7c7125d29a
