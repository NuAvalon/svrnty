// src/lib/identity/backup-shards-shape.ts
// The recovery-pieces record inside a plaintext backup is untrusted file content: it is stored as it came and later read by the give-a-piece screen, which prints its
// threshold ("Any N of your keepers ..."). A record that cannot be a set this app minted would make that line say something false: a threshold of 1 reads as "no single
// piece can", and a threshold above the number of pieces can never be met. Every set the app mints has an integer threshold of at least 2 (createShards refuses less),
// exactly `total` pieces, the same threshold on every piece, one index per piece, and the owner's own fingerprint on each piece. This reads the record and says what is wrong
// with it, or nothing. It touches no store and imports nothing, so the import can judge it before its first write. It never reads a piece's data.

export type ShardsProblem = 'not-an-object' | 'threshold' | 'not-a-list' | 'total' | 'unreachable' | 'bad-piece' | 'piece-threshold' | 'piece-fingerprint' | 'piece-index';

/** What is wrong with a backup's recovery-pieces record, or null when it is a usable set (or there is no record at all). `boundFingerprint` is the identity the backup was bound to. */
export function backupShardsProblem(record: unknown, boundFingerprint: string): ShardsProblem | null {
  if (record === undefined || record === null) return null;
  if (typeof record !== 'object' || Array.isArray(record)) return 'not-an-object';
  const r = record as { threshold?: unknown; total?: unknown; shards?: unknown };
  if (!Number.isInteger(r.threshold) || (r.threshold as number) < 2) return 'threshold';
  if (!Array.isArray(r.shards)) return 'not-a-list';
  if (r.total !== r.shards.length) return 'total';   // a list's length is an integer, so this also refuses a non-integer or non-number total
  if ((r.threshold as number) > (r.total as number)) return 'unreachable';
  const indexes = new Set<number>();
  for (const piece of r.shards) {
    if (piece === null || typeof piece !== 'object' || Array.isArray(piece)) return 'bad-piece';
    const p = piece as { threshold?: unknown; identity_fingerprint?: unknown; index?: unknown };
    if (p.threshold !== r.threshold) return 'piece-threshold';
    if (p.identity_fingerprint !== undefined && p.identity_fingerprint !== boundFingerprint) return 'piece-fingerprint';   // when a piece names an identity, it is this one's
    if (!Number.isInteger(p.index) || indexes.has(p.index as number)) return 'piece-index';
    indexes.add(p.index as number);
  }
  return null;
}
