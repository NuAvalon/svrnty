// src/lib/headless/join-backup.ts
// J5 (Flint, task:698): before a join can change anything, copy the store to a dated 0600 backup.
// Found by the live-relay run: a brand-new agent has NO store.json until its first write, so the unconditional copy made
// `mint` then `join` refuse with backup-failed (ENOENT). The rule (Flint #1444):
//   - lstat says ENOENT  -> nothing exists to protect: skip (and only then)
//   - a symlink          -> refuse (existsSync follows links, so a dangling link would read as "missing" and the later write would follow it)
//   - any other error    -> refuse (rethrown; the caller reports backup-failed)
import { lstatSync, copyFileSync, chmodSync } from 'node:fs';

export type BackupResult = { skipped: true } | { skipped: false; path: string };

export function backupStoreBeforeJoin(storePath: string, now: Date = new Date()): BackupResult {
  try {
    if (lstatSync(storePath).isSymbolicLink()) {
      throw new Error('store.json is a symlink; refusing to back it up or write through it');
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { skipped: true };
    throw e;
  }
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.\d+Z$/, 'Z');
  const path = `${storePath}.bak-${stamp}`;
  copyFileSync(storePath, path);
  chmodSync(path, 0o600);
  return { skipped: false, path };
}
