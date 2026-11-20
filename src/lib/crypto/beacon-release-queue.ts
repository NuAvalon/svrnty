// src/lib/crypto/beacon-release-queue.ts: queue the withdraw of every row of a pair, as plain functions of the pair's ports. No client, no network, no wire switch.
//
// A Remove and a contact's key replacement both have to do this FIRST, before anything else changes: put a durable queue entry on every row the relay may still
// match, and drop (and release the seed of) every row it can no longer match. Both call these two functions, so they cannot drift. It is a TIGHTENING: a local
// write that sends nothing, so it must run whatever the wire switch says (the same rule as the Remove's local latch). What sends the withdraws is the drain,
// later, from the client.
//
//  - queueWithdraws mutates the record and nothing else: it PLANS first (the one step that can fail for a reason outside the record: the seed map is
//    unreadable, the key the rows were deposited under cannot be named) and only then touches a row or a seed, so a throw leaves the record and the seed map
//    exactly as they were.
//  - queueUnqueuedLiveRows is the sweep after a commit: the commit merges in rows a concurrent deposit wrote, they have no queue entry, and the drain walks only the
//    queue, so they are queued here and committed again, until a pass adds nothing.
import { relayDead } from './beacon-relay-margin';
import { commitRecord, dropRowAt, queueWithdrawNowAt } from './beacon-pair-record';
import type { BeaconSecretsPort, BeaconStorePort, PairRecord } from './beacon-client';

/**
 * #956 S1b: the language's own bug errors. A store or IO failure is none of these, so a best-effort step may retry it quietly, but a bug is REPORTED and never swallowed
 * (a bare catch once turned a ReferenceError into a silent no-op heal). The ONE definition: the client's hold and heal and the key replacement's sweep all use it.
 */
export const isBugError = (e: unknown): boolean => e instanceof TypeError || e instanceof ReferenceError || e instanceof SyntaxError || e instanceof RangeError;

export interface ReleaseQueueDeps {
  secrets: Pick<BeaconSecretsPort, 'releaseRow' | 'planPairRows' | 'rowsAreUnderHeldKey'>;
  store: BeaconStorePort;
  now: () => number;
}

/** A row in these states has no withdraw to send: it was already withdrawn, spent, or never reachable. */
const settled = (state: PairRecord['rows'][number]['state']): boolean => state === 'withdrawn' || state === 'spent' || state === 'unreachable';

export async function queueWithdraws(rec: PairRecord, d: ReleaseQueueDeps): Promise<void> {
  // Rows the sealed store holds a seed for but the record may not list (an orphan: a crash between minting a seed and saving the record, after a deposit may
  // already have left). They join the record as rows whose answer is unknown ('unknown' withdraws too, and its seed is kept until confirmed), and the sweep
  // queues them with the rest. The record's merge keeps ONE row per id (a recorded row's state is never overwritten by a plan entry) and drops a tombstoned
  // one, so nothing here needs to; test O4-12c pins both. Never dropped here: a seed dropped now would leave a row that may be standing at the relay with
  // nothing to sign its withdraw. PLANNED FIRST, so that if it throws nothing below has happened.
  const planned = d.secrets.planPairRows ? await d.secrets.planPairRows(rec.pairId) : [];
  for (const row of rec.rows) {
    // 'unknown' rows withdraw too (L2c/L10): the seed is kept until confirmed or closed.
    if (settled(row.state)) continue;
    if (relayDead(row.epoch, d.now())) {                            // the relay can no longer match the epoch (its clock + the skew margin): drop + release (L11)
      dropRowAt(rec, row, d.now());
      await d.secrets.releaseRow(row.rowId);
      continue;
    }
    queueWithdrawNowAt(rec, row.rowId, d.now());                    // L6e: durable queue entry, due NOW
  }
  for (const t of planned) {
    if (relayDead(t.epoch, d.now())) continue;                      // a planned row the relay can no longer match is ignored (the margin applies here too)
    rec.rows.push({ rowId: t.rowId, epoch: t.epoch, H_e: t.H_e, N: t.N, state: 'unknown' });
  }
}

/**
 * L6d: retire every live row of the MERGED record. The caller's own commit merges in rows a concurrent deposit wrote — they have no queue entry, and the drain
 * walks only the queue. Bounded passes (the 8-swap rule): queue every live unqueued row of the merged record, commit again if any were added, repeat until a pass
 * adds nothing. `stillMine` is asked before every pass with the STORED record: it says whether the pair is still in the state this caller put it in (a Remove: the
 * tap is still trust-false at the generation it wrote; a newer tap owns the pair and its rows are never queued). `only`, when given, is asked about each
 * unqueued live row and only a row it answers true for is queued (a key replacement uses it to queue only rows under the OLD key).
 */
export async function queueUnqueuedLiveRows(
  rec: PairRecord, d: ReleaseQueueDeps, stillMine: (stored: PairRecord | undefined) => boolean, only?: (row: PairRecord['rows'][number]) => Promise<boolean>,
): Promise<void> {
  for (let i = 0; i < 8; i++) {
    const cur = await d.store.get(rec.pairId);
    if (!stillMine(cur)) break;
    let added = false;
    for (const row of rec.rows) {
      if (settled(row.state)) continue;
      if (relayDead(row.epoch, d.now())) continue;                  // only a row the relay can still match is queued
      if (rec.pendingWithdraws.some((w) => w.rowId === row.rowId)) continue;
      if (only && !(await only(row))) continue;
      queueWithdrawNowAt(rec, row.rowId, d.now());
      added = true;
    }
    if (!added) break;
    await commitRecord(d.store, d.now, rec);                        // merge pulls in rows that landed since
  }
}
