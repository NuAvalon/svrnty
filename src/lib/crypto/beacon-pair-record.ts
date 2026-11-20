// src/lib/crypto/beacon-pair-record.ts: how a pair's record is merged and committed, as plain functions that take the store and the clock as arguments.
//
// These were closures inside createBeaconClient. They are moved here UNCHANGED so that something that has no client (the contact's key replacement, which
// must queue the old key's withdraws without any network and whatever the wire switch says) can queue and commit them by the very same rules a Remove does:
// a compare-and-swap on `version`, a merge that unions the append-only fields, and row states that only ever move forward.
// The clock is passed as a FUNCTION and read exactly where the closures read it (a test clock that advances on every read pins that count).
import * as wire from './beacon-wire.mjs';
import type { BeaconStorePort, MatchClock, PairRecord, RowRecord, RowTombstone, TapIntent } from './beacon-client';

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- the wire module is untyped .mjs
const epochAtMs = (ms: number): number => Math.floor(ms / 1000 / (wire as any).EPOCH_SECONDS);

/** v3 L6b/G3: writes to a pair's record are serialised — compare-and-swap on `version`. The merge
 * unions the append-only fields; row states are MONOTONE (standing -> withdrawn -> released),
 * so a stale copy can never move a row backward — merge per row by rank, not "ours is newer". */
const ROW_RANK: Record<RowRecord['state'], number> = {
  unknown: 0, standing: 1, matched: 2, unreachable: 2, withdrawn: 3, spent: 3,
};

export function dropRowAt(rec: PairRecord, row: RowRecord, nowMs: number): void {
  rec.rows = rec.rows.filter((r) => r !== row);
  // tombstone epoch = the row's epoch, floored at now: an already-closed row still needs its
  // tombstone to LIVE long enough to guard the merge (R8 prunes it once two epochs close).
  (rec.deletedRows ??= []).push({ id: row.rowId, epoch: String(Math.max(Number(row.epoch), epochAtMs(nowMs))) });
}

/** A clock is valid only while its stamped gen equals the current tap.gen — a copy from a lower
 * generation cannot write it back (L14). */
const validClock = (c: MatchClock | null | undefined, tap: TapIntent | undefined): MatchClock | null =>
  c && tap && c.gen === tap.gen ? c : null;

/** L14 generation merge: tap-derived fields belong to a generation — the winner supplies BOTH the
 * tap and the match clock. A remaining tie: trust differs -> false wins (L13c); equal -> ours. */
export function mergeTap(ours: PairRecord, cur: PairRecord): { tap?: TapIntent; clock: MatchClock | null } {
  const ot = ours.tap, ct = cur.tap;
  if (!ot && !ct) return { clock: null };
  if (!ct) return { tap: ot, clock: validClock(ours.firstMatchEpoch, ot) };
  if (!ot) return { tap: ct, clock: validClock(cur.firstMatchEpoch, ct) };
  if (ot.gen !== ct.gen) {
    const win = ot.gen > ct.gen ? ours : cur;
    return { tap: win.tap, clock: validClock(win.firstMatchEpoch, win.tap) };
  }
  // L14d: equal gen + equal trust — the clock is ours if it is valid for that gen, else the
  // STORED one if it is. A copy read before the first match must not wipe the recorded clock.
  if (ot.trust === ct.trust)
    return { tap: ot, clock: validClock(ours.firstMatchEpoch, ot) ?? validClock(cur.firstMatchEpoch, ct) };
  return { tap: { gen: ot.gen, trust: false }, clock: null };                                 // tie: false wins
}

/** `resched`: rows the drain rescheduled after its own failed attempt, with the entry it READ.
 * Unchanged since that read -> the drain's entry (its backoff stands). Changed by another writer
 * (a Remove re-queue, a stop path) -> that writer's due time stands and attempts never drop. */
export function mergeRecAt(cur: PairRecord | undefined, ours: PairRecord, now: () => number,
  resched?: Map<string, { attempts: number; nextAt: number }>): PairRecord {
  if (!cur) return ours;
  // L14c(a): a row/withdraw id in EITHER side's tombstones is dropped from BOTH sides' lists.
  const del = new Set([...(cur.deletedRows ?? []), ...(ours.deletedRows ?? [])].map((t) => t.id));
  const rows = new Map(cur.rows.filter((r) => !del.has(r.rowId)).map((r) => [r.rowId, r]));
  for (const r of ours.rows.filter((r) => !del.has(r.rowId))) {
    const prior = rows.get(r.rowId);
    if (!prior || ROW_RANK[r.state] >= ROW_RANK[prior.state]) rows.set(r.rowId, r);
  }
  const delW = new Set([...(cur.deletedWithdraws ?? []), ...(ours.deletedWithdraws ?? [])].map((t) => t.id));
  const wds = new Map(cur.pendingWithdraws.filter((w) => !delW.has(w.rowId)).map((w) => [w.rowId, w]));
  for (const w of ours.pendingWithdraws.filter((w) => !delW.has(w.rowId))) {
    // K at merge: an entry only ever gets more urgent / more retried — whichever copy holds the
    // earlier due time or the higher attempts wins the row.
    const ex = wds.get(w.rowId);
    const seen = resched?.get(w.rowId);
    if (!ex) wds.set(w.rowId, w);
    else if (seen) wds.set(w.rowId, ex.attempts === seen.attempts && ex.nextAt === seen.nextAt
      ? w : { rowId: w.rowId, attempts: Math.max(ex.attempts, w.attempts), nextAt: ex.nextAt });
    else wds.set(w.rowId, { rowId: w.rowId, attempts: Math.max(ex.attempts, w.attempts), nextAt: Math.min(ex.nextAt, w.nextAt) });
  }
  const { tap, clock } = mergeTap(ours, cur);
  const dedup = (a: RowTombstone[] = [], b: RowTombstone[] = []) =>
    [...new Map([...a, ...b].map((t) => [t.id, t])).values()];
  // R8/L16: the higher closedFloor wins, CAPPED at the local clock — the floor is derived state,
  // never a source of time. A forward clock excursion that once wrote a high floor must not pin
  // it: real epochs below a stale floor would be erased on every merge (spent re-deposited,
  // final refusals retried every renew).
  const floor = Math.min(
    Math.max(Number(cur.closedFloor ?? 0), Number(ours.closedFloor ?? 0)),
    epochAtMs(now()) - 2,
  );
  const kept = (e: string) => Number(e) >= floor;
  return {
    ...ours,
    observedMatch: cur.observedMatch || ours.observedMatch,
    tap,
    firstMatchEpoch: clock,
    spentEpochs: [...new Set([...cur.spentEpochs, ...ours.spentEpochs])].filter(kept),
    refusedEpochs: [...new Set([...(cur.refusedEpochs ?? []), ...(ours.refusedEpochs ?? [])])].filter(kept),
    rows: [...rows.values()],
    pendingWithdraws: [...wds.values()],
    deletedRows: dedup(cur.deletedRows, ours.deletedRows).filter((t) => kept(t.epoch)),
    deletedWithdraws: dedup(cur.deletedWithdraws, ours.deletedWithdraws).filter((t) => kept(t.epoch)),
    closedFloor: floor > 0 ? String(floor) : undefined,
  };
}

/** G11: the store port requires `cas` — commit either wins a compare-and-swap or fails loudly;
 * never a plain-put fallback, and after 8 lost swaps it throws. A save that failed BEFORE a
 * deposit leaves means nothing is sent (callers map it to 'busy' with 0 requests). */
export async function commitRecord(
  store: BeaconStorePort, now: () => number, rec: PairRecord,
  resched?: Map<string, { attempts: number; nextAt: number }>,
): Promise<void> {
  for (let i = 0; i < 8; i++) {
    const cur = await store.get(rec.pairId);
    const base = cur?.version ?? 0;
    const next = mergeRecAt(cur, rec, now, resched);
    next.version = base + 1;
    if (await store.cas(rec.pairId, base, next)) {
      Object.assign(rec, next);
      return;
    }
  }
  throw new Error(`beacon commit: CAS lost 8 attempts for ${rec.pairId}`);
}

/** L6e: the withdraws a Remove queues are due NOW — backoff applies from the first RETRY, never
 * the first attempt. Queues made by a deposit path after a send keep their backoff. */
export function queueWithdrawNowAt(rec: PairRecord, rowId: string, nowMs: number): void {
  const ex = rec.pendingWithdraws.find((w) => w.rowId === rowId);
  if (ex) { ex.nextAt = nowMs; } else rec.pendingWithdraws.push({ rowId, attempts: 0, nextAt: nowMs });
}
