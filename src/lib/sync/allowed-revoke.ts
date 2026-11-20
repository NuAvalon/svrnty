// src/lib/sync/allowed-revoke.ts — #959: send the DELETEs the satellite's allowed-senders list is OWED. Pure orchestration over injected I/O; the signed requests are allowed-sync.ts's.
//
// WHAT IS OWED is DERIVED FROM THE RELAY'S OWN LIST (listAllowedSenders), not from any local record and not from the consent before a change: every sender the relay lists whose consent
// no longer allows a row (a fingerprint that is not in the book at all counts as not allowed) is owed a DELETE. That covers a row left by an earlier failed DELETE, a contact that was
// removed or blocked long ago, a restore onto a new device, and a contact this device never had; and it can never name a peer the relay does not list, so a contact that never had a row
// sends nothing. There is nothing to seed and nothing to lose.
//
// A FAILED GET IS NOT AN EMPTY LIST. 'unknown' (403, 5xx, network, a damaged body) means "try again next tick": nothing is revoked, nothing is declared done, no state is touched.
// 410 is the ONE exception: the relay keeps no list (#540), so nothing is owed, and this session stops asking (and logs once). Retire this with #540; the revoke check moves client-side.
//
// PACING: ONE GET per drain, the DELETEs spaced, and a refused DELETE backs off (30 s doubling to 1 h) per peer: the relay's rate bucket is shared per IP. The backoff is an in-memory
// schedule only; the durable guarantee is that the relay's list keeps naming the peer until a DELETE is confirmed. It never throws, and it never sends blind: a book that cannot be read
// means nothing is revoked this time.
import { allowedRowShouldExist, type AllowedListResult, type PeerConsent } from './allowed-sync';

export const REVOKE_BACKOFF_MIN_MS = 30_000;
export const REVOKE_BACKOFF_MAX_MS = 60 * 60 * 1000;
export const REVOKE_SPACING_MS = 250;
/** at most this many revokes per drain: the rest stay listed (so still owed) and go out on the next one, so a hostile list cannot hold a tab signing for hours */
export const REVOKE_MAX_PER_DRAIN = 25;
/** calls that arrive within this window share ONE drain (so an import-merge of N contacts is one GET), and drains for one owner start at least this far apart */
export const DRAIN_BATCH_MS = 300;
export const DRAIN_MIN_GAP_MS = 2000;

export interface AllowedRevokeIo {
  /** the relay's own list (listAllowedSenders): ONE call per drain */
  list(): Promise<AllowedListResult>;
  /** the signed DELETE for one peer (through reconcileAllowedForPeer, the only path to removeAllowedSender): true only for a confirmed one */
  deleteRow(senderFp: string): Promise<boolean>;
}

export interface AllowedRevokeDeps {
  /** the owner's book: peer fingerprint -> consent NOW. A peer that is not in the map is GONE (it has no consent). Throws if the book cannot be read. */
  consents(ownerFp: string): Promise<Map<string, PeerConsent>>;
  /** is the book WHOLE? "Not in the book = gone" is only true of a whole book: when this says no (the integrity flag is 'corrupt'), or cannot be asked, a listed peer that is absent from the book is NOT revoked. Default: whole. */
  bookComplete?(ownerFp: string): Promise<boolean>;
  now?: () => number;
  /** the pause between DELETEs (default: a real timer of REVOKE_SPACING_MS) */
  sleep?: (ms: number) => Promise<void>;
  /** the wait before a batch starts (default: a real timer) */
  delay?: (ms: number) => Promise<void>;
  /** where the once-per-session "the relay keeps no list" note goes (default: console.warn) */
  log?: (message: string) => void;
}

export interface DrainResult {
  listed: 'ok' | 'gone' | 'unknown' | 'stopped';
  attempted: number;
  revoked: number;
  failed: number;
  /** what happened to each owed peer, keyed by its LOWER-CASE fingerprint: 'deleted', 'failed', 'waiting' (inside its backoff window) or 'deferred' (past the per-drain cap) */
  outcomes: Map<string, 'deleted' | 'failed' | 'waiting' | 'deferred'>;
}

// in-memory, per session
interface Batch { override: Map<string, PeerConsent>; waiters: Array<(r: DrainResult) => void>; io: AllowedRevokeIo; deps: AllowedRevokeDeps }
const backoff = new Map<string, { fails: number; nextAt: number }>();
const stopped = new Set<string>();   // owners whose relay answered 410: no more GETs this session
const batches = new Map<string, Batch>();       // the NEXT batch per owner, not started yet
const lastStart = new Map<string, number>();
const tails = new Map<string, Promise<void>>();  // drains for one owner run one at a time
export function resetRevokeState(): void { backoff.clear(); stopped.clear(); batches.clear(); lastStart.clear(); tails.clear(); }
const keyOf = (ownerFp: string, fp: string) => `${ownerFp}:${fp}`;
const delayFor = (fails: number) => Math.min(REVOKE_BACKOFF_MIN_MS * 2 ** Math.max(0, fails - 1), REVOKE_BACKOFF_MAX_MS);
const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * One drain: ask the relay who it lists, and send a DELETE for every listed sender whose consent no longer allows a row. `override` carries consents a CALLER has just made (the post-change
 * record it was handed), which are authoritative over the book read for those peers. Returns what happened; never throws.
 */
export async function drainAllowedRevokes(
  ownerFp: string,
  io: AllowedRevokeIo,
  deps: AllowedRevokeDeps,
  override?: ReadonlyMap<string, PeerConsent>,
): Promise<DrainResult> {
  const out: DrainResult = { listed: 'unknown', attempted: 0, revoked: 0, failed: 0, outcomes: new Map() };
  try {
    if (stopped.has(ownerFp)) { out.listed = 'stopped'; return out; }
    const now = deps.now ?? Date.now;
    const listed = await io.list();                                                  // ONE GET per drain
    if (listed.status === 'gone') {
      stopped.add(ownerFp);
      (deps.log ?? ((m) => console.warn(m)))('[psi] the satellite keeps no allowed list any more (410): nothing is owed, no further checks this session');
      out.listed = 'gone';
      return out;
    }
    if (listed.status !== 'ok') return out;                                          // unknown: try again next tick, nothing touched
    out.listed = 'ok';
    // fingerprints are compared in lower case (the satellite lists them as it was given them); a DELETE goes out with the RELAY'S OWN string
    const book = new Map<string, PeerConsent>();
    for (const [fp, c] of await deps.consents(ownerFp)) book.set(fp.toLowerCase(), c);   // throws => nothing is sent blind (caught below)
    for (const [fp, c] of override ?? []) book.set(fp.toLowerCase(), c);
    let complete = true;
    try { complete = deps.bookComplete ? await deps.bookComplete(ownerFp) : true; } catch { complete = false; }   // an integrity flag that cannot be read counts as damaged
    const sleep = deps.sleep ?? realSleep;
    for (const fp of listed.fps) {
      const key = fp.toLowerCase();
      const c = book.get(key);
      if (c && allowedRowShouldExist(c)) continue;                                   // still allowed: its row stays
      if (!c && !complete) continue;                                                 // a damaged book does not say who is gone: only contacts it still holds are revoked
      const k = keyOf(ownerFp, key);
      const b = backoff.get(k);
      if (b && now() < b.nextAt) { out.outcomes.set(key, 'waiting'); continue; }     // inside its window
      if (out.attempted >= REVOKE_MAX_PER_DRAIN) { out.outcomes.set(key, 'deferred'); continue; }   // past the cap: still listed, so still owed
      if (out.attempted > 0) await sleep(REVOKE_SPACING_MS);                         // spaced, no pause before the first
      out.attempted++;
      let ok = false;
      try { ok = await io.deleteRow(fp); } catch { ok = false; }
      if (ok) { out.revoked++; backoff.delete(k); out.outcomes.set(key, 'deleted'); continue; }
      out.failed++; out.outcomes.set(key, 'failed');
      const fails = (backoff.get(k)?.fails ?? 0) + 1;
      backoff.set(k, { fails, nextAt: now() + delayFor(fails) });
    }
  } catch {
    out.listed = out.listed === 'ok' ? 'unknown' : out.listed;                      // an unreadable book: nothing was (or will be) sent blind
  }
  return out;
}

/**
 * BURST CONTROL. Every caller (a consent-change hook, the app-open check, the know-layer tick) asks through here: calls that arrive within DRAIN_BATCH_MS share ONE drain (one GET, however
 * many calls), the consent each call just made is merged into that batch (authoritative for its own peer), drains for one owner never overlap, and one starts at least DRAIN_MIN_GAP_MS
 * after the last. Every caller gets the shared result, and is ALWAYS answered: a drain or a timer that fails answers 'unknown' instead of leaving a caller waiting. The first caller's I/O
 * serves the whole batch (it is the same identity and the same relay for every caller of one owner).
 */
export function requestDrain(ownerFp: string, io: AllowedRevokeIo, deps: AllowedRevokeDeps, override?: ReadonlyMap<string, PeerConsent>): Promise<DrainResult> {
  let b = batches.get(ownerFp);
  if (!b) {
    const batch: Batch = { override: new Map(), waiters: [], io, deps };
    b = batch; batches.set(ownerFp, batch);
    const prev = tails.get(ownerFp) ?? Promise.resolve();
    tails.set(ownerFp, prev.then(async () => {
      let result: DrainResult = { listed: 'unknown', attempted: 0, revoked: 0, failed: 0, outcomes: new Map() };
      try {
        const now = deps.now ?? Date.now;
        const wait = Math.max(DRAIN_BATCH_MS, (lastStart.get(ownerFp) ?? Number.NEGATIVE_INFINITY) + DRAIN_MIN_GAP_MS - now());
        await (deps.delay ?? ((ms) => new Promise<void>((r) => setTimeout(r, ms))))(wait);
        batches.delete(ownerFp);                                                  // requests from here on form the NEXT batch
        lastStart.set(ownerFp, now());
        result = await drainAllowedRevokes(ownerFp, batch.io, batch.deps, batch.override);
      } catch { batches.delete(ownerFp); /* answered below with 'unknown' */ }
      for (const w of batch.waiters) w(result);
    }));
  }
  for (const [fp, c] of override ?? []) b.override.set(fp, c);
  return new Promise((resolve) => b!.waiters.push(resolve));
}
