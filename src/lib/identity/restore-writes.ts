// src/lib/identity/restore-writes.ts
// What a failed restore left on the device, decided by comparing two snapshots. No dependencies, so it is unit-tested directly.

/** A count and a digest per place the restore writes this owner's records. */
export type OwnerSnapshot = Record<string, { n: number; d: string }>;
export type RestoreWrites = 'none' | 'some' | 'unknown';

/**
 * Compare the snapshot taken just before the restore's first owner-record write with the device now:
 * 'none' = identical (nothing was saved), 'some' = different, 'unknown' = either side could not be read (then nothing may be claimed either way).
 */
export function restoreWritesVerdict(before: OwnerSnapshot | null, after: OwnerSnapshot | null): RestoreWrites {
  if (!before || !after) return 'unknown';
  const places = new Set([...Object.keys(before), ...Object.keys(after)]);
  for (const place of places) {
    if (before[place]?.n !== after[place]?.n || before[place]?.d !== after[place]?.d) return 'some';
  }
  return 'none';
}

/** The verdict rides on the error the restore threw, so the screen can read it without the restore deciding any wording. */
export function restoreWritesOf(err: unknown): RestoreWrites | undefined {
  return err && typeof err === 'object' ? (err as { restoreWrites?: RestoreWrites }).restoreWrites : undefined;
}

export function tagRestoreWrites(err: unknown, writes: RestoreWrites): void {
  if (err && typeof err === 'object') (err as { restoreWrites?: RestoreWrites }).restoreWrites = writes;
}
