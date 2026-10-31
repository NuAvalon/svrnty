// src/lib/headless/headless-dead-letter.ts
// #713 for HEADLESS clients (Flint #189046, Archie #189049): a dead-letter sink, so a headless loss is RECORDED, not only counted.
// Without a sink, consume-mailbox acks every consumed envelope and a loss is only bump()ed into summary.lost. With this sink, the ack
// door records the row FIRST and acks only after the write succeeded; a failing write leaves the envelope on the relay (unrecorded++).
//
// What a row is (makeDeadLetterRow, dead-letter.ts): envelope id, first_seen, reason, blob KIND, and a fingerprint only for an
// AUTHENTICATED reason. METADATA ONLY: never the blob, never plaintext, never a key.
//
// Storage: one JSON map {envelope_id: row} in the agent dir, rewritten atomically (writeFileAtomic: O_EXCL temp at 0600 from birth, fsync,
// rename). A map, not an append-only log, because the FE contract needs clear() (a later success replaces the flag, R5) and bounded pruning
// (planPrune: 30 days, per-budget caps); both are rewrites either way. The EARLIEST first_seen wins on re-record, as the FE store does.
// A file that exists but can't be parsed is NOT treated as empty (readJsonStrict throws): record() fails, so nothing is acked unrecorded.

import { existsSync, statSync } from 'node:fs';
import { dirname } from 'node:path';
import type { DeadLetterSink } from '@/lib/sync/consume-mailbox';
import { parseDeadLetterRow, planPrune, type DeadLetterRow } from '@/lib/sync/dead-letter';
import { readJsonStrict, writeFileAtomic } from './atomic-file';
import { withWriterLock } from './writer-lock';

export const DEAD_LETTER_FILE = 'dead-letters.json';

type RowMap = Record<string, DeadLetterRow>;

function load(path: string): RowMap {
  const raw = readJsonStrict<Record<string, unknown>>(path, {});
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) throw new Error('dead-letter file is not an object');
  const out: RowMap = {};
  for (const [k, v] of Object.entries(raw)) {
    const row = parseDeadLetterRow(v);
    if (row && row.envelope_id === k) out[k] = row; // a malformed or mis-keyed row is dropped on the next write, never trusted
  }
  return out;
}

let writes = 0;
/** Test seam: how many times the dead-letter file was written in this process (Archie #189076 NEG: N losses in one poll = one write). */
export function __deadLetterWritesForTest(): number {
  return writes;
}

function save(path: string, rows: RowMap): void {
  writes++;
  writeFileAtomic(path, JSON.stringify(rows), { mode: 0o600, backup: false });
  // writeFileAtomic creates at 0600, and umask can only remove bits; check anyway, in the same step (never trust a mode you didn't stat).
  const mode = statSync(path).mode & 0o777;
  if (mode & 0o077) throw new Error(`dead-letter file mode ${mode.toString(8)} is group/other-accessible`);
}

type Op = { kind: 'record'; row: DeadLetterRow } | { kind: 'clear'; id: string };

function earliest(prev: DeadLetterRow | undefined, row: DeadLetterRow): DeadLetterRow {
  return prev && Date.parse(prev.first_seen) <= Date.parse(row.first_seen) ? { ...row, first_seen: prev.first_seen } : row;
}

/**
 * @param path    the dead-letter file in the agent dir
 * @param lockDir the agent dir whose writer lock (.writer.lock, the SAME lock HeadlessStore takes) guards every read-merge-write.
 *                Defaults to the file's directory.
 */
export function headlessDeadLetterSink(path: string, now: () => number = () => Date.now(), lockDir: string = dirname(path)): DeadLetterSink {
  // STAGING + MERGE UNDER THE LOCK (Flint #189078/#189091, Archie #189086). record()/clear() only queue an op in memory; nothing is cached
  // from disk. flush() and settle() take the agent-dir writer lock, RE-READ the file INSIDE the lock, apply the queued ops in order (a
  // record keeps the EARLIEST first_seen against what is on disk), write, and release. A map loaded before the lock is never written back,
  // so another process on the same agent dir (the Weft's catch-up + poll + intake) can't erase rows it never saw. Only local file work runs
  // inside the lock (read, merge, write): no network.
  // consume-mailbox calls flush() before every ack chunk and acks only if it resolved: every row is durable before ITS envelope's ack.
  let ops: Op[] = [];
  const commit = (prune: boolean): void => {
    withWriterLock(lockDir, () => {
      const disk = existsSync(path) ? load(path) : {};
      let changed = false;
      for (const op of ops) {
        if (op.kind === 'record') {
          disk[op.row.envelope_id] = earliest(disk[op.row.envelope_id], op.row);
          changed = true;
        } else if (op.id in disk) {
          delete disk[op.id];
          changed = true;
        }
      }
      if (prune) {
        for (const id of planPrune(Object.values(disk), now())) {
          delete disk[id];
          changed = true;
        }
      }
      if (changed) save(path, disk);
    });
    ops = []; // only after the write succeeded: a failed commit keeps the ops for the next flush (and the chunk stays on the relay)
  };
  return {
    record: async (row) => {
      ops.push({ kind: 'record', row });
      return row;
    },
    clear: async (envelopeId) => {
      // Every stored note asks for a clear (R5). With no file, no row can exist for it: queue nothing, so a clean poll never takes the lock.
      if (!existsSync(path) && !ops.some((o) => o.kind === 'record')) return;
      ops.push({ kind: 'clear', id: envelopeId });
    },
    flush: async () => {
      if (ops.length === 0) return;
      commit(false);
    },
    settle: async () => {
      if (ops.length === 0 && !existsSync(path)) return;
      commit(true);
    },
  };
}
