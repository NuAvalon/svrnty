// src/lib/trust/beacon-key-replace.ts — #956 S1b: replacing the beacon key a contact holds, release-FIRST.
//
// A newer signed card from a contact carries a newer beacon key. The rows this device deposited under the OLD key can still be matched at the relay until their
// withdraw is confirmed (or their epoch can no longer be matched), and the old key is the only thing that can name them. So the order is fixed:
//
//   1. read whether the pair was confirmed (the answer is only true BEFORE the key changes);
//   2. PLAN and queue the withdraw of every row of the pair, while the old key still names them. If the plan cannot be made, the replace is REFUSED: nothing was
//      queued, nothing was released, the key is unchanged (beacon-release-queue.ts plans first, so a throw touches nothing);
//   3. COMMIT the queue, then queue anything a concurrent deposit landed meanwhile. "Released" means the queue is COMMITTED, not drained;
//   4. only then write the new key, as a compare-and-set on the old key and generation, so a concurrent change aborts it.
//
// THE IN-BETWEEN STATE is named and safe: a crash after step 3, or a step 4 that aborts or fails, leaves the queue COMMITTED and the key UNCHANGED. The drain
// then withdraws rows of the key this device still holds, and nothing is deposited under a stale key. The worst case is a match missed until the next renew; it is
// not a leak. The queue is therefore NEVER rolled back once the key write was attempted: undoing it after the key moved would strand the old rows at the relay.
//
// BOUNDS, stated so nobody has to rediscover them:
//   - The HOLD that keeps the new key from depositing beside the old one (beacon-client.ts, heldByOlderKey) ends when each old row's withdraw is confirmed or the
//     relay can no longer match its epoch (the epoch's end, the grace window and the one-hour skew margin), so against a relay that never answers it lasts up to
//     about one week plus that hour. It does not end on a timer of its own and it is not a new stored field.
//   - What this change prevents is the two generations being MATCHABLE at the same time. It does NOT hide that they are adjacent: across epochs, timing can still
//     correlate the old generation's last rows with the new generation's first ones, because the new key's first deposit lands at a later epoch than the old key's
//     last. An observer of the relay may infer that one pair's rows stopped under one key and began under another.
//   - A device clock fast by more than the relay's one-hour skew margin can still act early on a row or a seed (beacon-relay-margin.ts).
//   - A replacement leaves the pair UNCONFIRMED: the confirmation belongs to the key it was made for. Until the in-person confirm exists nothing can restore it.
// It is a TIGHTENING (a local write that sends nothing), so it runs whatever the wire switch says, like a Remove's local latch: it takes no switch and no client.
// The contact record and the pair record use different compare-and-swap protocols, so this ORDER is the only crash-safe way to move from one to the other.
import { commitRecord } from '../crypto/beacon-pair-record';
import { queueUnqueuedLiveRows, queueWithdraws, type ReleaseQueueDeps } from '../crypto/beacon-release-queue';
import type { PairConfirmedPort, PairRecord } from '../crypto/beacon-client';

export interface HeldKey { publicKey: string; generation: number }

export interface KeyReplaceDeps extends ReleaseQueueDeps {
  /** the pair this contact's key belongs to */
  pairId: string;
  /** was the pair confirmed, at the generation held now? Read BEFORE anything changes. */
  confirmed: PairConfirmedPort;
  /** the compare-and-set write of the contact's key: applies only while the held key is still `expected`; false = it moved, nothing was written */
  writeKey(expected: HeldKey, next: HeldKey): Promise<boolean>;
}

export type KeyReplaceOutcome =
  /** the key was replaced. `wasConfirmed` is whether the pair was confirmed BEFORE (the confirmation no longer applies). */
  | { kind: 'replaced'; wasConfirmed: boolean }
  /** the saved key is UNCHANGED. The withdraw queue may already be committed (that is safe, see the header). Both a plan that could not be made and a key write
   *  that did not happen come here: the person is told the same thing, that what is saved for the contact is unchanged. */
  | { kind: 'refused' };

const fresh = (pairId: string): PairRecord => ({ pairId, observedMatch: false, spentEpochs: [], refusedEpochs: [], rows: [], pendingWithdraws: [] });

export async function replaceHeldBeaconKey(deps: KeyReplaceDeps, held: HeldKey, next: HeldKey): Promise<KeyReplaceOutcome> {
  // 1. only true before the key changes. A read that fails is "unknown", and unknown must not claim a confirmation that may never have existed.
  let wasConfirmed = false;
  try { wasConfirmed = (await deps.confirmed.isConfirmed(deps.pairId)) === true; } catch { wasConfirmed = false; }

  // 2. plan + queue, in memory, while the old key still names the rows. A throw here touches nothing.
  const stored = await deps.store.get(deps.pairId).catch(() => 'unreadable' as const);
  if (stored === 'unreadable') return { kind: 'refused' };
  const rec = stored ?? fresh(deps.pairId);
  try { await queueWithdraws(rec, deps); } catch { return { kind: 'refused' }; }

  // 3. commit the queue (nothing to write if there is no record and nothing was queued), then catch rows a concurrent deposit landed meanwhile.
  try {
    if (stored || rec.rows.length > 0 || rec.pendingWithdraws.length > 0) {
      await commitRecord(deps.store, deps.now, rec);
      await queueUnqueuedLiveRows(rec, deps, () => true);
    }
  } catch { return { kind: 'refused' }; }

  // 4. only now the key. From here the queue is never undone, whatever happens.
  let applied = false;
  try { applied = await deps.writeKey(held, next); } catch { applied = false; }
  return applied ? { kind: 'replaced', wasConfirmed } : { kind: 'refused' };
}
