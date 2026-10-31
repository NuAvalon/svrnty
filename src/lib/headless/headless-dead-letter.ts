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
import type { DeadLetterSink } from '@/lib/sync/consume-mailbox';
import { parseDeadLetterRow, planPrune, type DeadLetterRow } from '@/lib/sync/dead-letter';
import { readJsonStrict, writeFileAtomic } from './atomic-file';

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

export function headlessDeadLetterSink(path: string, now: () => number = () => Date.now()): DeadLetterSink {
  // STAGING (Archie #189076, Flint C1): one sink per poll. The file is read once, record()/clear() only change the in-memory map, and
  // flush() writes it once if anything changed. consume-mailbox calls flush() before every ack chunk and acks only if it resolved, so
  // record-before-ack holds while a backlog costs at most one write per chunk. A load or write failure throws out of record()/flush(),
  // which leaves the envelope on the relay.
  let rows: RowMap | null = null;
  let dirty = false;
  const loaded = (): RowMap => (rows ??= existsSync(path) ? load(path) : {});
  const flush = async (): Promise<void> => {
    if (!dirty || rows === null) return;
    save(path, rows);
    dirty = false;
  };
  return {
    record: async (row) => {
      const m = loaded();
      const prev = m[row.envelope_id];
      // The stored row carries the EARLIEST first_seen (FE parity: putDeadLetter keeps the first sighting).
      const kept: DeadLetterRow = prev && Date.parse(prev.first_seen) <= Date.parse(row.first_seen) ? { ...row, first_seen: prev.first_seen } : row;
      m[row.envelope_id] = kept;
      dirty = true;
      return kept;
    },
    clear: async (envelopeId) => {
      if (rows === null && !existsSync(path)) return; // nothing was ever recorded: no file, no read
      const m = loaded();
      if (!(envelopeId in m)) return;
      delete m[envelopeId];
      dirty = true;
    },
    settle: async () => {
      if (rows === null && !existsSync(path)) return;
      const m = loaded();
      for (const id of planPrune(Object.values(m), now())) {
        delete m[id];
        dirty = true;
      }
      await flush();
    },
    flush,
  };
}
