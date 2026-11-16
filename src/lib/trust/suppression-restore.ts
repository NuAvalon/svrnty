// src/lib/trust/suppression-restore.ts: what a restore does with a carried suppression record (and removed list), and the person's one confirmation. PURE over injected ports:
// no storage, clock or randomness of its own. The storage wiring is in the identity store, which is this module's only importer.
//
// The rules (the design ruling for the piece-2 restore gate):
//  - The carried value is accepted ONLY by parseCarriedSuppression, and the caller passes it from a source the passphrase authenticated (never a plaintext file). Anything else is "none".
//  - A device with a READABLE record: MERGE by tightening, never reduce. A device with NO record: write the carried persons and groups with global ON; a backup's global-off waits for
//    the person's confirmation on a screen that names the backup's date, because a backup can be stale and a file password can craft one.
//  - A record that exists but cannot be read is NEVER overwritten: it stays as it is (an unreadable record reads as "suppress everyone").
//  - EVERY change to a stored record is ONE atomic read-modify-write: the port reads the record, runs `decide` on what it read, and commits only if the record is still exactly that;
//    otherwise it runs `decide` again on the newer record. So a write that lands in between (a second tab, a Remove) is never overwritten by a stale result, and the unguarded
//    read-then-replace form is not in the port at all. `decide` is therefore PURE: it can run more than once.
//  - The record is written BEFORE the pending confirmation: if the second write fails the person is simply never asked and stays private.
//  - confirmGlobalOff is the ONLY path that writes global:false after a restore, and it needs the pending marker this restore left.
//  - The removed list merges by union; over the cap it REFUSES; an unreadable stored list is never overwritten.
import type { SuppressionRecord } from './suppression';
import { carrySuppression, confirmGlobalOff, freshDeviceWrite, mergeByTightening, mergeRemoved, parseCarriedSuppression, type CarriedSuppression } from './suppression-carry';

/** What a sealed owner record reads as: a value, no row at all, or a row that could not be opened or understood. */
export type SealedRead<T> = { state: 'ok'; value: T } | { state: 'absent' } | { state: 'unreadable' };

/** What a `decide` returns: a new value to commit (with the result to hand back), or just the result (nothing is written). */
export type Decision<T, R> = { write: T; result: R } | { result: R };

/**
 * One atomic read-modify-write over a sealed record. The port reads it (ok / absent / unreadable), calls `decide`, and commits a `write` only if the record is STILL exactly what it read;
 * a lost comparison runs `decide` again on the newer record. After a bounded number of lost comparisons it throws with nothing written. A port refuses (throws) a `write` decided on an
 * UNREADABLE record: an unreadable record is never overwritten.
 */
export type Update<T> = <R>(decide: (held: SealedRead<T>) => Decision<T, R>) => Promise<R>;

/**
 * How a store plugs in. `read` returns the record's current state AND a token for exactly what was read (the raw stored row); `commit` writes `value` only if the record is STILL exactly that
 * token (one atomic compare-and-swap in the store) and says whether it did.
 */
export interface UpdateIO<T> {
  read(): Promise<{ token: unknown; held: SealedRead<T> }>;
  commit(token: unknown, value: T): Promise<boolean>;
}

export const UPDATE_MAX_ATTEMPTS = 5;

/**
 * The atomic read-modify-write over one sealed record: read, decide, and commit only if the record is unchanged; a lost comparison decides again on the newer record. After
 * `maxAttempts` lost comparisons it throws with nothing written, never last-writer-wins. A `write` decided on an UNREADABLE record is refused (throws): an unreadable record is never overwritten.
 */
export function makeUpdate<T>(io: UpdateIO<T>, maxAttempts: number = UPDATE_MAX_ATTEMPTS): Update<T> {
  return async <R,>(decide: (held: SealedRead<T>) => Decision<T, R>): Promise<R> => {
    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      const { token, held } = await io.read();
      const decision = decide(held);
      if (!('write' in decision)) return decision.result;
      if (held.state === 'unreadable') throw new Error('Refusing to overwrite a sealed record that cannot be read');
      if (await io.commit(token, decision.write)) return decision.result;
    }
    throw new Error('A sealed record changed too often while it was being updated; nothing was written');
  };
}

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

/** Record one Remove atomically (the plan is decided on the record the port read, and re-decided if another write landed first). The caller throws on a refusal, so its Remove fails. */
export function recordRemoval(update: Update<string[]>, durableId: string): Promise<RemovedAppend> {
  return update<RemovedAppend>((held) => {
    const plan = planRemovedAppend(held, durableId);
    return plan.kind === 'write' ? { write: plan.list, result: plan } : { result: plan };
  });
}

/** The sentence for a Remove that could not be recorded, or null when it was (written, or already there). The caller throws it, so its Remove fails and writes no latch. */
export function removalRefusal(plan: RemovedAppend): string | null {
  return plan.kind === 'refuse' ? `Cannot record this Remove (${plan.why}): refusing, so no latch is written without it` : null;
}

/**
 * What the sealed vault carries, from what the store read. All or nothing: an unreadable removed list means NOTHING is carried (undefined), and so does a record that could not be read or
 * that the strict parser would refuse. An absent removed list is an empty one.
 */
export function suppressionToCarry(record: SuppressionRecord | null, removed: SealedRead<string[]>): CarriedSuppression | undefined {
  if (removed.state === 'unreadable') return undefined;
  return carrySuppression(record, removed.state === 'ok' ? removed.value : []);
}

export interface RestorePorts {
  updateSuppression: Update<SuppressionRecord>;
  updateRemoved: Update<string[]>;
  readPending(): Promise<SealedRead<PendingGlobalOff>>;
  writePending(p: PendingGlobalOff): Promise<void>;
  clearPending(): Promise<void>;
}

export type SuppressionOutcome = 'none-no-carried-record' | 'kept-unreadable' | 'merged' | 'written-fresh';
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

  const done = await ports.updateSuppression<'merged' | 'written-fresh' | 'written-fresh-waiting' | 'kept-unreadable'>((held) => {
    if (held.state === 'ok') return { write: mergeByTightening(held.value, carried), result: 'merged' };
    if (held.state === 'absent') {
      const fresh = freshDeviceWrite(carried);
      return { write: fresh.record, result: fresh.globalOffWaitsForConfirm ? 'written-fresh-waiting' : 'written-fresh' };
    }
    return { result: 'kept-unreadable' };
  });
  const waiting = done === 'written-fresh-waiting';
  if (waiting) await ports.writePending({ v: 1, backup_at: isoOrNull(backupAt) });

  return { suppression: waiting ? 'written-fresh' : done, pendingGlobalOff: waiting, removed: await restoreRemoved(carried, ports) };
}

function restoreRemoved(carried: CarriedSuppression, ports: RestorePorts): Promise<RemovedOutcome> {
  return ports.updateRemoved<RemovedOutcome>((held) => {
    if (held.state === 'unreadable') return { result: 'kept-unreadable' };
    const existing = held.state === 'ok' ? held.value : [];
    const merged = mergeRemoved(existing, carried.removed);
    if (!merged.ok) return { result: 'refused-too-large' };
    if (merged.removed.length === existing.length) return { result: 'none-nothing-new' };
    return { write: merged.removed, result: 'written' };
  });
}

export type ConfirmOutcome = 'confirmed' | 'no-pending' | 'pending-unreadable' | 'record-unreadable';

/**
 * The person's confirmation: switch global OFF and clear the marker. It needs the marker a restore left, so a screen that calls it by mistake cannot turn global off by itself.
 * The record is changed atomically and BEFORE the marker is cleared, so a failure in between leaves a marker that can be confirmed again (idempotent), never a lost one.
 */
export async function confirmPendingGlobalOff(ports: RestorePorts): Promise<ConfirmOutcome> {
  const pending = await ports.readPending();
  if (pending.state === 'absent') return 'no-pending';
  if (pending.state === 'unreadable') return 'pending-unreadable';
  const changed = await ports.updateSuppression<boolean>((held) => (held.state === 'ok' ? { write: confirmGlobalOff(held.value), result: true } : { result: false }));
  if (!changed) return 'record-unreadable';
  await ports.clearPending();
  return 'confirmed';
}
