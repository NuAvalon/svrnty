// src/lib/identity/backup-shards-shape.ts
// The recovery-pieces record inside a plaintext backup is untrusted file content: it is stored as it came and later read by the give-a-piece screen, which prints its
// threshold ("Any N of your keepers ..."). A record that cannot be a set this app minted would make that line say something false: a threshold of 1 reads as "no single
// piece can", and a threshold above the number of pieces can never be met. Every set the app mints has an integer threshold of at least 2 (createShards refuses less),
// exactly `total` pieces, and every piece carries the same threshold. This reads the record and says what is wrong with it, or nothing. It touches no store, so the
// import can run it before its first write. It imports only the coded error, on purpose.

import { RestoreThrow } from '../crypto/coded-error';

export type ShardsProblem = 'not-an-object' | 'threshold' | 'not-a-list' | 'total' | 'unreachable' | 'bad-piece' | 'piece-threshold';

/** What is wrong with a backup's recovery-pieces record, or null when it is a usable set (or there is no record at all). */
export function backupShardsProblem(record: unknown): ShardsProblem | null {
  if (record === undefined || record === null) return null;
  if (typeof record !== 'object' || Array.isArray(record)) return 'not-an-object';
  const r = record as { threshold?: unknown; total?: unknown; shards?: unknown };
  if (!Number.isInteger(r.threshold) || (r.threshold as number) < 2) return 'threshold';
  if (!Array.isArray(r.shards)) return 'not-a-list';
  if (r.total !== r.shards.length) return 'total';   // a list's length is an integer, so this also refuses a non-integer or non-number total
  if ((r.threshold as number) > (r.total as number)) return 'unreachable';
  for (const piece of r.shards) {
    if (piece === null || typeof piece !== 'object' || Array.isArray(piece)) return 'bad-piece';
    if ((piece as { threshold?: unknown }).threshold !== r.threshold) return 'piece-threshold';
  }
  return null;
}

/** Refuse a backup whose recovery-pieces record is not a usable set. The message is for the console only; the screen's words come from the code. */
export function assertBackupShardsShape(record: unknown): void {
  const problem = backupShardsProblem(record);
  if (problem) throw new RestoreThrow('backup-shards-malformed', `Invalid backup: the recovery pieces record is not a usable set (${problem})`);
}
