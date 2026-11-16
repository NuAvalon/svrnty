// src/lib/trust/suppression-restore.ts: what a restore does with a carried suppression record (and removed list), and the person's one confirmation. PURE over injected ports:
// no storage, clock or randomness of its own. DARK: nothing imports it outside tests yet; the storage wiring comes after it is reviewed.
//
// The rules (the design ruling for the piece-2 restore gate):
//  - The carried value is accepted ONLY by parseCarriedSuppression, and the caller passes it from a source the passphrase authenticated (never a plaintext file). Anything else is "none".
//  - A device with a READABLE record: MERGE by tightening, never reduce. A device with NO record: write the carried persons and groups with global ON; a backup's global-off waits for
//    the person's confirmation on a screen that names the backup's date, because a backup can be stale and a file password can craft one.
//  - A record that exists but cannot be read is NEVER overwritten: it stays as it is (an unreadable record reads as "suppress everyone").
//  - The fresh-device write is put-if-absent: if another writer got there first, this falls back to the merge, so a restore never replaces a record it did not read.
//  - The record is written BEFORE the pending confirmation: if the second write fails the person is simply never asked and stays private.
//  - confirmGlobalOff is the ONLY path that writes global:false after a restore, and it needs the pending marker this restore left.
//  - The removed list merges by union; over the cap it REFUSES; an unreadable stored list is never overwritten.
import type { SuppressionRecord } from './suppression';
import { confirmGlobalOff, freshDeviceWrite, mergeByTightening, mergeRemoved, parseCarriedSuppression, type CarriedSuppression } from './suppression-carry';

/** What a sealed owner record reads as: a value, no row at all, or a row that could not be opened or understood. */
export type SealedRead<T> = { state: 'ok'; value: T } | { state: 'absent' } | { state: 'unreadable' };

/** Left by a restore onto a device with no record, when the backup said global:false. The date is the vault's own timestamp as text, or null when it was not a plain ISO time. */
export interface PendingGlobalOff {
  v: 1;
  backup_at: string | null;
}

const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const isoOrNull = (x: unknown): string | null => (typeof x === 'string' && ISO_TIME.test(x) ? x : null); // the anchored pattern also bounds the length

/** The strict reader for the stored marker: exact keys, version 1, a plain ISO time or null. Null means unreadable. */
export function parsePendingGlobalOff(x: unknown): PendingGlobalOff | null {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return null;
  const r = x as Record<string, unknown>;
  const keys = Object.keys(r);
  if (keys.length !== 2 || !keys.includes('v') || !keys.includes('backup_at')) return null;
  if (r.v !== 1) return null;
  if (r.backup_at !== null && isoOrNull(r.backup_at) === null) return null;
  return { v: 1, backup_at: r.backup_at as string | null };
}

/** The strict reader for the stored removed list: the same rules as the carried one (lowercase 64-hex ids, no duplicates, no holes, the cap). Null means unreadable. */
export const parseRemovedList = (x: unknown): string[] | null =>
  parseCarriedSuppression({ v: 1, global: false, groups: [], persons: [], removed: x })?.removed ?? null;

export type RemovedAppend = { kind: 'write'; list: string[] } | { kind: 'noop' } | { kind: 'refuse'; why: 'bad-id' | 'unreadable' | 'too-large' };

/**
 * What recording one Remove does to the stored list. A Remove that cannot be recorded must FAIL (the caller records BEFORE its latch write): a Remove that leaves no durable id is the
 * exact loss this list exists to stop. So an unreadable list, a full list and a malformed id all REFUSE; an id already there is a no-op, not an error.
 */
export function planRemovedAppend(held: SealedRead<string[]>, durableId: string): RemovedAppend {
  if (parseRemovedList([durableId]) === null) return { kind: 'refuse', why: 'bad-id' };
  if (held.state === 'unreadable') return { kind: 'refuse', why: 'unreadable' };
  const existing = held.state === 'ok' ? held.value : [];
  if (existing.includes(durableId)) return { kind: 'noop' };
  const merged = mergeRemoved(existing, [durableId]);
  return merged.ok ? { kind: 'write', list: merged.removed } : { kind: 'refuse', why: 'too-large' };
}

export interface RestorePorts {
  readSuppression(): Promise<SealedRead<SuppressionRecord>>;
  /** Put-if-absent, atomic: true when it wrote, false when a record was already there. */
  writeSuppressionIfAbsent(rec: SuppressionRecord): Promise<boolean>;
  replaceSuppression(rec: SuppressionRecord): Promise<void>;
  readRemoved(): Promise<SealedRead<string[]>>;
  writeRemoved(list: string[]): Promise<void>;
  readPending(): Promise<SealedRead<PendingGlobalOff>>;
  writePending(p: PendingGlobalOff): Promise<void>;
  clearPending(): Promise<void>;
}

export type SuppressionOutcome = 'none-no-carried-record' | 'kept-unreadable' | 'merged' | 'written-fresh' | 'merged-after-race' | 'race-unreadable';
export type RemovedOutcome = 'none-no-carried-record' | 'none-nothing-new' | 'kept-unreadable' | 'written' | 'refused-too-large';

export interface RestoreReport {
  suppression: SuppressionOutcome;
  /** True when a confirmation is now waiting: the backup said global off and this device has no record of its own. */
  pendingGlobalOff: boolean;
  removed: RemovedOutcome;
}

/**
 * Apply a carried record (and its removed list) to this device. `carriedRaw` is whatever the authenticated vault held under `suppression`; `backupAt` is the vault's own
 * timestamp. A port that throws propagates: the caller decides (the restore itself must not fail over this), and nothing is half-applied in a loosening direction.
 */
export async function restoreSuppression(carriedRaw: unknown, backupAt: unknown, ports: RestorePorts): Promise<RestoreReport> {
  const carried = parseCarriedSuppression(carriedRaw);
  if (carried === null) return { suppression: 'none-no-carried-record', pendingGlobalOff: false, removed: 'none-no-carried-record' };

  const report: RestoreReport = { suppression: 'kept-unreadable', pendingGlobalOff: false, removed: 'none-nothing-new' };
  const held = await ports.readSuppression();
  if (held.state === 'ok') {
    await ports.replaceSuppression(mergeByTightening(held.value, carried));
    report.suppression = 'merged';
  } else if (held.state === 'absent') {
    const fresh = freshDeviceWrite(carried);
    if (await ports.writeSuppressionIfAbsent(fresh.record)) {
      report.suppression = 'written-fresh';
      if (fresh.globalOffWaitsForConfirm) {
        await ports.writePending({ v: 1, backup_at: isoOrNull(backupAt) });
        report.pendingGlobalOff = true;
      }
    } else {
      // Another writer got there first: never replace what this restore did not read. Read it and merge, or leave it alone if it cannot be read.
      const now = await ports.readSuppression();
      if (now.state === 'ok') {
        await ports.replaceSuppression(mergeByTightening(now.value, carried));
        report.suppression = 'merged-after-race';
      } else {
        report.suppression = 'race-unreadable';
      }
    }
  }

  report.removed = await restoreRemoved(carried, ports);
  return report;
}

async function restoreRemoved(carried: CarriedSuppression, ports: RestorePorts): Promise<RemovedOutcome> {
  const held = await ports.readRemoved();
  if (held.state === 'unreadable') return 'kept-unreadable';
  const existing = held.state === 'ok' ? held.value : [];
  const merged = mergeRemoved(existing, carried.removed);
  if (!merged.ok) return 'refused-too-large';
  if (merged.removed.length === existing.length) return 'none-nothing-new';
  await ports.writeRemoved(merged.removed);
  return 'written';
}

export type ConfirmOutcome = 'confirmed' | 'no-pending' | 'pending-unreadable' | 'record-unreadable';

/**
 * The person's confirmation: switch global OFF and clear the marker. It needs the marker a restore left, so a screen that calls it by mistake cannot turn global off by itself.
 * The record is written BEFORE the marker is cleared, so a failure in between leaves a marker that can be confirmed again (idempotent), never a lost one.
 */
export async function confirmPendingGlobalOff(ports: RestorePorts): Promise<ConfirmOutcome> {
  const pending = await ports.readPending();
  if (pending.state === 'absent') return 'no-pending';
  if (pending.state === 'unreadable') return 'pending-unreadable';
  const held = await ports.readSuppression();
  if (held.state !== 'ok') return 'record-unreadable';
  await ports.replaceSuppression(confirmGlobalOff(held.value));
  await ports.clearPending();
  return 'confirmed';
}
