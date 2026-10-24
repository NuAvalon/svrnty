/**
 * Crash- and race-safe persistence for a headless agent's state files (store.json, ratchet-sessions.json,
 * gate.json, issued-codes.json). Flint 2026-10-24: a plain writeFileSync truncates then writes, so a
 * concurrent reader can see a torn file; the old readers treated "won't parse" as "empty", and the next
 * write then persisted the empty state over the real one (address book or ratchet sessions wiped).
 *
 *  - writeFileAtomic: unlink any stale <path>.tmp.<pid>, create it O_EXCL 0600 → write → fsync → rename,
 *    then fsync the dir. A reader sees the old file or the new one. With backup (default) the previous
 *    copy is kept as <path>.bak (0600), but only if it was valid JSON, so a bad file never overwrites the
 *    last good backup. Ratchet state passes backup:false: a restored stale ratchet re-derives chain keys
 *    that were already used (key/nonce reuse), so there must be nothing to restore.
 *  - readJsonStrict: a MISSING file is empty; a file that EXISTS but won't parse is an error (fail closed).
 *
 * This removes torn reads. It does not serialize writers: two processes can still lose each other's
 * update (read-modify-write); that needs one writer per agent dir.
 */
import {
  chmodSync, closeSync, copyFileSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync,
  unlinkSync, writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';

export const RESTORE_BAK_HINT = 'Restore from <path>.bak or repair it by hand.';
export const RATCHET_HINT =
  'Do NOT restore a backup of ratchet state (a stale ratchet reuses chain keys): move the file aside and ' +
  're-handshake; sessions re-establish, send plain until each is confirmed.';

function isValidJson(path: string): boolean {
  try {
    JSON.parse(readFileSync(path, 'utf8'));
    return true;
  } catch {
    return false;
  }
}

function unlinkQuiet(path: string): void {
  try { unlinkSync(path); } catch { /* absent */ }
}

export function writeFileAtomic(path: string, data: string, opts: { mode?: number; backup?: boolean } = {}): void {
  const mode = opts.mode ?? 0o600;
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true });
  const tmp = `${path}.tmp.${process.pid}`;
  unlinkQuiet(tmp);                                       // a crashed run's leftover: never reuse or follow it
  const fd = openSync(tmp, 'wx', mode);                   // O_CREAT|O_EXCL: no symlink follow
  try {
    writeFileSync(fd, data);                              // loops until every byte is written
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    if ((opts.backup ?? true) && existsSync(path) && isValidJson(path)) {
      const bakTmp = `${path}.bak.tmp.${process.pid}`;
      unlinkQuiet(bakTmp);
      copyFileSync(path, bakTmp);
      chmodSync(bakTmp, 0o600);                           // copyFileSync's mode isn't guaranteed under every umask/fs
      renameSync(bakTmp, `${path}.bak`);
    }
    renameSync(tmp, path);
  } catch (e) {
    unlinkQuiet(tmp);
    throw e;
  }
  try {
    const dfd = openSync(dir, 'r');
    try { fsyncSync(dfd); } finally { closeSync(dfd); }
  } catch { /* best effort: durability across power loss, not correctness */ }
}

export function readJsonStrict<T>(path: string, empty: T, hint: string = RESTORE_BAK_HINT): T {
  if (!existsSync(path)) return empty;
  const text = readFileSync(path, 'utf8');
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(
      `${path} exists but is not valid JSON (${text.length} bytes): refusing to treat it as empty, ` +
      `which would overwrite it. ${hint.replace('<path>', path)}`,
    );
  }
}
