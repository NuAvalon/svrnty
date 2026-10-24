/**
 * Crash- and race-safe persistence for a headless agent's state files (store.json, ratchet-sessions.json,
 * gate.json, issued-codes.json). Flint 2026-10-24: a plain writeFileSync truncates then writes, so a
 * concurrent reader can see a torn file; the old readers treated "won't parse" as "empty", and the next
 * write then persisted the empty state over the real one (address book or ratchet sessions wiped).
 *
 *  - writeFileAtomic: <path>.tmp.<pid> (0600) → fsync → rename. A reader sees the old file or the new one.
 *    The previous copy is kept as <path>.bak, but only if it was valid JSON, so a bad file never
 *    overwrites the last good backup.
 *  - readJsonStrict: a MISSING file is empty; a file that EXISTS but won't parse is an error (fail closed).
 *
 * This removes torn reads. It does not serialize writers: two processes can still lose each other's
 * update (read-modify-write); that needs one writer per agent dir.
 */
import {
  closeSync, copyFileSync, existsSync, fchmodSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync,
  unlinkSync, writeSync,
} from 'node:fs';
import { dirname } from 'node:path';

function isValidJson(path: string): boolean {
  try {
    JSON.parse(readFileSync(path, 'utf8'));
    return true;
  } catch {
    return false;
  }
}

export function writeFileAtomic(path: string, data: string, mode = 0o600): void {
  mkdirSync(dirname(path), { recursive: true });
  const tmp = `${path}.tmp.${process.pid}`;
  const fd = openSync(tmp, 'w', mode);
  try {
    fchmodSync(fd, mode);                      // a leftover tmp from a crashed run keeps its old mode otherwise
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    if (existsSync(path) && isValidJson(path)) {
      const bakTmp = `${path}.bak.tmp.${process.pid}`;
      copyFileSync(path, bakTmp);
      renameSync(bakTmp, `${path}.bak`);
    }
    renameSync(tmp, path);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* already gone */ }
    throw e;
  }
}

export function readJsonStrict<T>(path: string, empty: T): T {
  if (!existsSync(path)) return empty;
  const text = readFileSync(path, 'utf8');
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(
      `${path} exists but is not valid JSON (${text.length} bytes): refusing to treat it as empty, ` +
      `which would overwrite it. Restore from ${path}.bak or repair it by hand.`,
    );
  }
}
