// src/lib/crypto/beacon-client.ts
// #588 trust beacon, CLIENT piece A (the HTTP client + tap/latch orchestration). Dark: nothing imports this module yet.
//
// Wire facts (one implementation): the deposit body comes ONLY from the prover's serializeDeposit; epoch/grace constants
// and MAX_DEPOSIT_BYTES are IMPORTED from beacon-wire.mjs, never re-defined. The centurion answers fixed JSON bytes at
// HTTP 200 — the status line carries nothing, the body is the answer.
//
// Hard rules honored here:
//  - fetch and the base URL are injected; production wiring pins the SAME-ORIGIN '/api/trust'. No card, contact, or
//    config value can set it. Every request: POST, a STRING body (exactly one Content-Length, never chunked),
//    redirect:'error', credentials:'omit', cache:'no-store', an AbortController timeout.
//  - Anything that is not the fixed answer bytes — extra keys, wrong content-type, non-JSON, body over 1 KiB, a
//    non-200 the contract does not name — is the typed 'unreadable' result and never carries the body anywhere.
//  - 'refused' is never retried in place. 429 / 503 / network failure / timeout is the ONE retryable class: 'busy'.
//  - No request body is ever logged or persisted (v1 s3.3); this module has no logging at all.
//  - The raw poll/withdraw answer NEVER leaves this file: matchState(pairId) is the only consumer-facing match view
//    and it applies the latch (v2 L4). Transport ops below are module-private on purpose.
//  - Secrets never rest here: x and each row's one-time seed live behind the injected ports (sealed store).
//
// The latch (v2 s2): removal is instant and local. removeAtTap writes the latch FIRST, then does network. The latch is
// read immediately before every deposit fetch (a tap mid-proof ends with nothing sent) and after every poll/withdraw
// answer, before it is applied. A latched pair is skipped by every scheduled action. matchState is fail-closed.
import * as wire from './beacon-wire.mjs';
import { buildDeposit, signAuth, scheduleRedeposit, type DepositKeys, type Point, type Signals } from './beacon-prover';

/* eslint-disable @typescript-eslint/no-explicit-any */

// ---- centurion refusal reasons (the fixed set it can emit; anything else is unreadable) ----
export type RefusalReason =
  | 'wire' | 'epoch' | 'vkey' | 'proof' | 'usage' | 'internal' | 'timeout' | 'rate' | 'full' | 'auth'
  | 'point:pi_a:identity' | 'point:pi_a:off-curve' | 'point:pi_c:identity' | 'point:pi_c:off-curve'
  | 'point:pi_b:identity' | 'point:pi_b:off-curve' | 'point:pi_b:not-in-subgroup';
const REASONS: ReadonlySet<string> = new Set([
  'wire', 'epoch', 'vkey', 'proof', 'usage', 'internal', 'timeout', 'rate', 'full', 'auth',
  'point:pi_a:identity', 'point:pi_a:off-curve', 'point:pi_c:identity', 'point:pi_c:off-curve',
  'point:pi_b:identity', 'point:pi_b:off-curve', 'point:pi_b:not-in-subgroup',
]);

const REFUSED_STATUSES = new Set(['accepted', 'already', 'match', 'none', 'withdrawn']);
const MAX_ANSWER_BYTES = 1024;          // every centurion answer is far smaller; more = unreadable
const DEFAULT_BASE_URL = '/api/trust';  // the fixed same-origin base; injected for tests only
const DEFAULT_TIMEOUT_MS = 10_000;

// ---- ports (piece A owns no storage and sees no secrets) ----

/** The durable "this pair is removed" record, owned by the vault side. local = my Remove/Block; remote = an un-trust note.
 * kindOf carries the latch KIND: 'removed' behaves as L3/L5 describe (every scheduled action skips the pair); 'frozen'
 * keeps renewal deposits and polls on schedule and hides the match from local consumers only. 'removed' dominates:
 * if either source is 'removed', the pair is 'removed'. isLatched(p) === (kindOf(p) !== null). */
export interface LatchPort {
  isLatched(pairId: string): Promise<boolean>;
  /** L6c: `source` narrows the answer to one side — 'local' sees only my Remove/Block, 'remote' only
   * the peer's un-trust. With no source the meaning is unchanged: 'removed' if either side removed. */
  kindOf(pairId: string, source?: 'local' | 'remote'): Promise<'removed' | 'frozen' | null>;
  setLatched(pairId: string, source: 'local' | 'remote'): Promise<void>;
  clearLatched(pairId: string, source: 'local' | 'remote'): Promise<void>;
}
/** After a seed-only restore the owner must re-confirm each pair before any request may be made for it (v2 L7). */
export interface PairConfirmedPort {
  isConfirmed(pairId: string): Promise<boolean>;
}
/** One deposited row's PUBLIC record: canonical decimal strings only, no secret material.
 * 'unknown' = the deposit answer was lost after the write-ahead save (L10); the row keeps its
 * pinned one-time pubkey so the retry re-deposits the SAME K. 'unreachable' = an 'already' to a
 * freshly minted K — the held row lives under a key this client does not have (L10b): never
 * polled, never withdrawn, retired by L11. */
export interface RowRecord {
  rowId: string;
  epoch: string;
  H_e: string;
  N: string;
  state: 'standing' | 'matched' | 'withdrawn' | 'spent' | 'unknown' | 'unreachable';
  /** hex one-time pubkey, pinned at the write-ahead save (L10) — the retry's SAME K. */
  oneTimePk?: string;
}
export interface PendingWithdraw { rowId: string; attempts: number; nextAt: number }
/** L13 TAP INTENT: written durably BEFORE the first proof; `renew` runs only while trust===true.
 * absent means no intent — a confirmed pair with no tap deposits NOTHING and builds no proof. */
export interface TapIntent { gen: number; trust: boolean }
/** The match clock is stored with the generation it was observed under; it is valid only while
 * its gen equals the current tap.gen — a copy from a lower generation cannot write it back (L14). */
export interface MatchClock { epoch: string; gen: number }
/** L14c: tombstones carry the dropped row's epoch so R8's "prune once the epoch is two closed" has
 * an epoch to prune by. */
export interface RowTombstone { id: string; epoch: string }
export interface PairRecord {
  pairId: string;
  /** lifetime fact for the note layer: a poll ever answered match OR a withdraw answered match (v2 s3). */
  observedMatch: boolean;
  /** the durable tap intent (L13). trustAtTap bumps the generation only when trust was not already
   * true (L13b); removeAtTap and the failed-tap restore write trust:false under a new gen. */
  tap?: TapIntent;
  /** the epoch of the row whose match answer was FIRST observed, stamped with the generation that
   * observed it; CLEARED by a 'removed' latch and by Remove's pre-network commit (L6b), unchanged
   * by 'frozen'. matchSince() serves it. null is the tombstone: it wins the merge over any stale
   * clock — a delete would only resurrect the old clock under `ours ?? cur`. */
  firstMatchEpoch?: MatchClock | null;
  /** epochs whose (slot,N) is spent — a 'withdrawn' deposit answer; never re-deposited (v1 s2). */
  spentEpochs: string[];
  /** L12b: epochs with a recorded FINAL refusal (NO_RETRY / point:* / locally-impossible body) —
   * no retry in that epoch, owed again at the next. Owed is DERIVED from state; no flag. */
  refusedEpochs: string[];
  rows: RowRecord[];
  pendingWithdraws: PendingWithdraw[];
  /** rows this writer deliberately dropped (refused-drop / L11 close) — without it the merge's row
   * union would resurrect them from the other writer's stale copy. {id,epoch} for R8's prune. */
  deletedRows?: RowTombstone[];
  /** rows whose pendingWithdraw entries this writer retired — same merge-resurrection guard. */
  deletedWithdraws?: RowTombstone[];
  /** R8 prune watermark: epochs strictly below this are closed past keeping — spentEpochs,
   * refusedEpochs and tombstones prune under it (L11). Monotone across the merge: the higher
   * floor wins and unioned lists are filtered by it, so a stale copy can't resurrect a pruned
   * epoch (union alone would). */
  closedFloor?: string;
  /** write-serialisation version (v3 L6b): bumped on every committed write; CAS stores refuse a stale base. */
  version?: number;
}
export interface BeaconStorePort {
  get(pairId: string): Promise<PairRecord | undefined>;
  put(rec: PairRecord): Promise<void>;
  /** v3 L6b/G11: atomic compare-and-swap — write `next` only if the stored record still carries
   * `expectedVersion`. Two open tabs share the durable store, so a client-side queue can't
   * serialise them. REQUIRED: commit wins a CAS or fails loudly; there is no plain-put fallback. */
  cas(pairId: string, expectedVersion: number, next: PairRecord): Promise<boolean>;
  pairs(): Promise<PairRecord[]>;
}
/** The sealed-store facet: x and one-time seeds never leave it. */
export interface BeaconSecretsPort {
  depositSecrets(pairId: string): Promise<{ x: bigint; counterpartY: Point } | undefined>;
  /** mint a one-time row (its seed stays sealed); the pubkey goes into the proof's K. */
  newRow(pairId: string, epoch: bigint): Promise<{ rowId: string; oneTimePk: Uint8Array }>;
  /** the row's one-time Ed25519: the pubkey the deposit carried + a signer bound to the sealed seed. */
  rowAuth(rowId: string): Promise<{ pk: Uint8Array; sign: (msg: Uint8Array) => Promise<Uint8Array> } | undefined>;
  /** the seed is kept until the withdraw is CONFIRMED or the epoch has closed; this is the release. */
  releaseRow(rowId: string): Promise<void>;
}
export interface BeaconProverPort {
  buildDeposit(keys: DepositKeys): Promise<{ body: string; signals: Signals }>;
  signAuth(
    op: 'poll' | 'withdraw', H_e: bigint, N: bigint, nonce: Uint8Array,
    sign: (msg: Uint8Array) => Promise<Uint8Array>,
  ): Promise<Uint8Array>;
  scheduleRedeposit(o: { epochStartMs: number; epochSeconds?: number; graceSeconds?: number; rand?: () => number }): number;
}
type FetchLike = (url: string, init: any) => Promise<{ status: number; headers: { get(k: string): string | null }; text(): Promise<string> }>;
export interface BeaconClientDeps {
  fetch: FetchLike;
  /** the fixed same-origin base — '/api/trust' in production. Nothing external may set it. */
  baseUrl?: string;
  latch: LatchPort;
  confirmed: PairConfirmedPort;
  store: BeaconStorePort;
  secrets: BeaconSecretsPort;
  prover: BeaconProverPort;
  now?: () => number;
  requestTimeoutMs?: number;
  /** retry spacing for the durable pending-withdraw queue, attempt-indexed. */
  backoffMs?: (attempt: number) => number;
}

// ---- typed results: the ONLY shapes that cross the wire boundary ----
type Answer =
  | { kind: 'accepted' } | { kind: 'already' } | { kind: 'match' } | { kind: 'none' } | { kind: 'withdrawn' }
  | { kind: 'nonce'; nonce: string }
  | { kind: 'refused'; reason: RefusalReason }
  | { kind: 'busy' } | { kind: 'unreadable' };
export type TrustResult =
  | { kind: 'deposited' } | { kind: 'spent' } | { kind: 'pending' } | { kind: 'failed' }
  | { kind: 'busy' } | { kind: 'latched' } | { kind: 'unconfirmed' } | { kind: 'unsent' }
  /** G9/L10b: the held row lives under a key this client does not have — it cannot light for this
   * client until the epoch closes. NOT 'deposited': it is false to the person. */
  | { kind: 'unreachable' };
export interface BeaconClient {
  trustAtTap(pairId: string): Promise<TrustResult>;
  removeAtTap(pairId: string): Promise<{ observedMatch: boolean }>;
  matchState(pairId: string): Promise<'match' | 'none'>;
  /** read-only (v3 A2): the epoch INDEX at which MATCH was first observed for the pair, or null.
   * A 'removed' latch clears it (Remove + re-Trust restarts the clock); a 'frozen' latch does
   * NOT hide it. No request on the wire. Builders may read it only after matchState='match'. */
  matchSince(pairId: string): Promise<number | null>;
  renew(pairId: string): Promise<void>;
  pollNow(pairId: string): Promise<void>;
  nextRenewalAt(pairId: string): Promise<number | undefined>;
  drainPendingWithdraws(): Promise<void>;
}

const fresh = (pairId: string): PairRecord =>
  ({ pairId, observedMatch: false, spentEpochs: [], refusedEpochs: [], rows: [], pendingWithdraws: [] });

export function createBeaconClient(deps: BeaconClientDeps): BeaconClient {
  const base = (deps.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, '');
  const now = deps.now ?? (() => Date.now());
  const timeoutMs = deps.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS;
  const backoff = deps.backoffMs ?? ((a) => Math.min(60_000, 1000 * 2 ** a));
  const w: any = wire;
  const EPOCH_SECONDS: number = w.EPOCH_SECONDS, GRACE_SECONDS: number = w.GRACE_SECONDS, MAX_DEPOSIT_BYTES: number = w.MAX_DEPOSIT_BYTES;

  const epochAt = (ms: number) => Math.floor(ms / 1000 / EPOCH_SECONDS);
  /** Epochs the server considers open (mirrors open_epochs): cur, cur-1 in the first 600 s, cur+1 in the last. */
  const visibleEpochs = (ms: number): Set<string> => {
    const cur = epochAt(ms), start = cur * EPOCH_SECONDS * 1000, out = new Set([String(cur)]);
    if (ms < start + GRACE_SECONDS * 1000) out.add(String(cur - 1));
    if (ms > start + EPOCH_SECONDS * 1000 - GRACE_SECONDS * 1000) out.add(String(cur + 1));
    return out;
  };
  /** Epochs a deposit may be made for: cur, plus cur+1 inside the last-600 s window (v2 s0). */
  const depositableEpochs = (ms: number): bigint[] => {
    const cur = epochAt(ms), out = [BigInt(cur)];
    if (ms > cur * EPOCH_SECONDS * 1000 + (EPOCH_SECONDS - GRACE_SECONDS) * 1000) out.push(BigInt(cur + 1));
    return out;
  };

  const getRec = async (pairId: string) => {
    const r = (await deps.store.get(pairId)) ?? fresh(pairId);
    r.refusedEpochs ??= [];
    return r;
  };

  /** v3 L6b/G3: writes to a pair's record are serialised — compare-and-swap on `version`. The merge
   * unions the append-only fields; row states are MONOTONE (standing -> withdrawn -> released),
   * so a stale copy can never move a row backward — merge per row by rank, not "ours is newer". */
  const ROW_RANK: Record<RowRecord['state'], number> = {
    unknown: 0, standing: 1, matched: 2, unreachable: 2, withdrawn: 3, spent: 3,
  };
  const dropRow = (rec: PairRecord, row: RowRecord): void => {
    rec.rows = rec.rows.filter((r) => r !== row);
    // tombstone epoch = the row's epoch, floored at now: an already-closed row still needs its
    // tombstone to LIVE long enough to guard the merge (R8 prunes it once two epochs close).
    (rec.deletedRows ??= []).push({ id: row.rowId, epoch: String(Math.max(Number(row.epoch), epochAt(now()))) });
  };
  /** A clock is valid only while its stamped gen equals the current tap.gen — a copy from a lower
   * generation cannot write it back (L14). */
  const validClock = (c: MatchClock | null | undefined, tap: TapIntent | undefined): MatchClock | null =>
    c && tap && c.gen === tap.gen ? c : null;
  /** L14 generation merge: tap-derived fields belong to a generation — the winner supplies BOTH the
   * tap and the match clock. A remaining tie: trust differs -> false wins (L13c); equal -> ours. */
  const mergeTap = (ours: PairRecord, cur: PairRecord): { tap?: TapIntent; clock: MatchClock | null } => {
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
  };
  /** `resched`: rows the drain rescheduled after its own failed attempt, with the entry it READ.
   * Unchanged since that read -> the drain's entry (its backoff stands). Changed by another writer
   * (a Remove re-queue, a stop path) -> that writer's due time stands and attempts never drop. */
  const mergeRec = (cur: PairRecord | undefined, ours: PairRecord,
    resched?: Map<string, { attempts: number; nextAt: number }>): PairRecord => {
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
      epochAt(now()) - 2,
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
  };
  /** G11: the store port requires `cas` — commit either wins a compare-and-swap or fails loudly;
   * never a plain-put fallback, and after 8 lost swaps it throws. A save that failed BEFORE a
   * deposit leaves means nothing is sent (callers map it to 'busy' with 0 requests). */
  const commit = async (rec: PairRecord, resched?: Map<string, { attempts: number; nextAt: number }>): Promise<void> => {
    for (let i = 0; i < 8; i++) {
      const cur = await deps.store.get(rec.pairId);
      const base = cur?.version ?? 0;
      const next = mergeRec(cur, rec, resched);
      next.version = base + 1;
      if (await deps.store.cas(rec.pairId, base, next)) {
        Object.assign(rec, next);
        return;
      }
    }
    throw new Error(`beacon commit: CAS lost 8 attempts for ${rec.pairId}`);
  };

  /** L13c: a tap-intent write is its own compare-and-swap — the generation is computed from the
   * STORED record inside every attempt (`stored gen + 1`), never from the copy read at call start.
   * trust:false also clears the match clock in the same write (Remove's tombstone, L6b); a clock
   * that no longer matches the new generation is normalized away.
   * L15: `expectGen` is the durable generation the caller read at call start — the write applies
   * only while the stored gen is still that gen. If it moved, a tap this client cannot order
   * against landed; the caller gets the STORED record back once and decides from that one read. */
  const commitIntent = async (
    rec: PairRecord, trust: boolean, expectGen?: number,
  ): Promise<{ ok: true } | { moved: PairRecord }> => {
    for (let i = 0; i < 8; i++) {
      const cur = await deps.store.get(rec.pairId);
      if (expectGen !== undefined && (cur?.tap?.gen ?? 0) !== expectGen)
        return { moved: cur ?? rec };                                 // a tap we cannot order against landed
      const base = cur?.version ?? 0;
      const next = mergeRec(cur, rec);
      next.tap = { gen: (cur?.tap?.gen ?? 0) + 1, trust };
      next.firstMatchEpoch =
        trust ? (next.firstMatchEpoch && next.firstMatchEpoch.gen === next.tap.gen ? next.firstMatchEpoch : null)
              : null;
      next.version = base + 1;
      if (await deps.store.cas(rec.pairId, base, next)) {
        Object.assign(rec, next);
        return { ok: true };
      }
    }
    throw new Error(`beacon intent-commit: CAS lost 8 attempts for ${rec.pairId}`);
  };

  /** L13e-3: the failed-tap restore is a compare-and-swap ON THE GENERATION — it applies only while
   * the stored gen is still the one THIS tap wrote (`intentGen`); a newer tap owns the pair and the
   * restore does nothing. It only ever runs for a FIRST tap and always restores to FALSE. */
  const restoreIntent = async (pairId: string, intentGen: number): Promise<void> => {
    for (let i = 0; i < 8; i++) {
      const cur = await deps.store.get(pairId);
      if (!cur || cur.tap?.gen !== intentGen || cur.tap.trust !== true) return;   // a newer tap owns the pair
      const next = { ...cur, tap: { gen: intentGen + 1, trust: false }, firstMatchEpoch: null, version: cur.version ?? 0 };
      next.version = (cur.version ?? 0) + 1;
      if (await deps.store.cas(pairId, cur.version ?? 0, next)) return;
    }
    // L13g: a failed restore throws — like commit/commitIntent, loud never silent. Told `busy`
    // while the intent stays true, a later renew would deposit what they were told did not happen.
    throw new Error(`beacon intent-restore: CAS lost 8 attempts for ${pairId}`);
  };

  /** Latch gates: 'removed' stops every wire action for the pair (L3); 'frozen' only masks the local match view —
   * deposits, polls and honest row bookkeeping keep running on schedule. */
  const removed = (pairId: string) => deps.latch.kindOf(pairId).then((k) => k === 'removed');

  /** Call order per pair: the LAST tap issued owns the pair's fate. A trust tap clears its local latch only while it
   * is still the latest call — otherwise a Remove issued a tick later would have its latch write silently undone.
   * Cheap same-tab fast path only (L15): a second tab has its own map — the durable generation is the guarantee. */
  const lastCall = new Map<string, number>();
  let callSeq = 0;
  /** L6c: pairs with a removeAtTap in flight IN THIS CLIENT — the repair must not bump gen twice in the
   * window between setLatched and the L6b commit. */
  const removing = new Set<string>();

  // ---- transport (module-private: the raw answer must not leave this file, v2 L4) ----

  /** v3: per-op answer vocabulary — a status valid for one op is 'unreadable' at another's step
   * (a 'withdrawn' at the nonce step releases nothing). The {kind}-tagged union stays closed per
   * op but is a tagged object, not a bare status, so a later contract can grow the poll answer
   * with proof + signals without changing this shape. */
  const OP_STATUS: Record<string, ReadonlySet<string>> = {
    nonce: new Set(['nonce']),
    deposit: new Set(['accepted', 'already', 'withdrawn']),
    poll: new Set(['none', 'match']),
    withdraw: new Set(['withdrawn', 'match']),
  };

  async function post(op: 'deposit' | 'nonce' | 'poll' | 'withdraw', body: string): Promise<Answer> {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);          // covers reading the body too (v3)
    let res;
    try {
      res = await deps.fetch(`${base}/beacon/${op}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
        redirect: 'error',
        credentials: 'omit',
        cache: 'no-store',
        signal: ctrl.signal,
      });
      if (res.status === 429 || res.status === 503) return { kind: 'busy' };
      if (res.status !== 200) return { kind: 'unreadable' };
      const ct = res.headers.get('content-type');
      if (!ct || !ct.includes('application/json')) return { kind: 'unreadable' };
      const text = await res.text();
      if (text.length > MAX_ANSWER_BYTES) return { kind: 'unreadable' };
      let o: any;
      try { o = JSON.parse(text); } catch { return { kind: 'unreadable' }; }
      if (o === null || typeof o !== 'object' || Array.isArray(o)) return { kind: 'unreadable' };
      const keys = Object.keys(o).sort();
      if (op === 'nonce' && keys.length === 1 && keys[0] === 'nonce' && typeof o.nonce === 'string' && /^[0-9a-f]{64}$/.test(o.nonce)) {
        return { kind: 'nonce', nonce: o.nonce };
      }
      if (keys.length === 1 && keys[0] === 'status' && REFUSED_STATUSES.has(o.status)) {
        // per-op vocabulary gate: a foreign-op status is unreadable HERE, never an answer
        if (!OP_STATUS[op].has(o.status)) return { kind: 'unreadable' };
        return { kind: o.status } as Answer;
      }
      if (keys.length === 2 && o.status === 'refused' && typeof o.reason === 'string' && REASONS.has(o.reason)) {
        return { kind: 'refused', reason: o.reason as RefusalReason };
      }
      return { kind: 'unreadable' };
    } catch {
      return { kind: 'busy' };                                    // network failure / abort: the one retryable class
    } finally {
      clearTimeout(t);
    }
  }

  const NO_RETRY = new Set(['wire', 'vkey', 'proof', 'usage']);   // + every 'point:*' — the client produced a bad body
  const transient = (a: Answer) =>
    a.kind === 'busy' || a.kind === 'unreadable' ||
    (a.kind === 'refused' && ['full', 'rate', 'internal', 'timeout', 'epoch'].includes(a.reason));
  const hexToBytes = (h: string) => Uint8Array.from(h.match(/../g)!.map((b) => parseInt(b, 16)));
  const bytesToHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

  /** one nonce per call, fetched just before signing, never cached; refused auth -> ONE fresh nonce, retried ONCE. */
  async function authed(op: 'poll' | 'withdraw', row: RowRecord): Promise<Answer> {
    const auth = await deps.secrets.rowAuth(row.rowId);
    if (!auth) return { kind: 'unreadable' };
    const H_e = BigInt(row.H_e), N = BigInt(row.N);
    for (let attempt = 0; attempt < 2; attempt++) {
      const n = await post('nonce', JSON.stringify({ op, H_e: row.H_e, N: row.N }));
      if (n.kind !== 'nonce') return n;
      const nonce = hexToBytes(n.nonce);
      const sig = await deps.prover.signAuth(op, H_e, N, nonce, auth.sign);
      const body = JSON.stringify({
        H_e: row.H_e, N: row.N,
        pk: bytesToHex(auth.pk), sig: bytesToHex(sig), nonce: n.nonce,
      });
      const a = await post(op, body);
      if (!(a.kind === 'refused' && a.reason === 'auth') || attempt === 1) return a;
    }
    return { kind: 'unreadable' };
  }

  // ONE buildDeposit at a time (the shared snarkjs curve): every proof queues behind this mutex.
  let proveChain: Promise<unknown> = Promise.resolve();
  const mutexed = <T>(fn: () => Promise<T>): Promise<T> => {
    const r = proveChain.then(fn);
    proveChain = r.then(() => undefined, () => undefined);
    return r;
  };

  /** Deposit outcomes richer than the wire answer — mapped to TrustResult at the tap. */
  type DepositOutcome =
    | 'spent-epoch'            // (slot,N) spent for this epoch — owed never (G5)
    | 'refused-epoch'          // a FINAL refusal is recorded for this epoch (L12b) — owed next epoch
    | 'covered'                // a standing/matched row covers the epoch
    | 'covered-unreachable'    // only an 'unreachable' row covers it — no re-mint (L8c/G8)
    | 'unsent'                 // no secrets or the proof threw — derived-owed retries it later
    | 'unsaved'                // the write-ahead save lost CAS 8x — nothing was sent (G11)
    | 'latched'                // the latch was seen before the fetch left (G6)
    | 'already-fresh';         // 'already' to a FRESH mint — unreachable (G9)

  /** L12: owed is DERIVED from state — deposit for one epoch unless it is spent, finally-refused
   * for the epoch, or already covered (standing/matched; an 'unreachable' row covers too, L8c).
   * A row left 'unknown' is retried with its pinned K (L10). NO_RETRY/point:* answers land in
   * refusedEpochs — per (pair,epoch), owed again next epoch; no flag can stick (G4).
   * L2c: the latch is re-read before the fetch leaves AND after it returns, before it is applied.
   * G6: a latch seen BEFORE the fetch leaves drops a fresh mint + releases its seed and queues NO
   * withdraw — a withdraw is queued only for a stored 'unknown' row (an earlier call may have
   * sent it) or when the fetch returned. */
  async function depositEpoch(rec: PairRecord, epoch: bigint): Promise<Answer | DepositOutcome> {
    const e = String(epoch);
    if (rec.spentEpochs.includes(e)) return 'spent-epoch';
    if ((rec.refusedEpochs ?? []).includes(e)) return 'refused-epoch';
    const cover = rec.rows.filter((r) => r.epoch === e);
    // L8d: a row with an UNCONFIRMED queued withdraw does not cover its epoch — it spends it.
    // A same-epoch remake after a removal is not possible; the tap reads 'spent', renewal is
    // owed at the NEXT epoch, and the queue's own confirmation lands the epoch in spentEpochs.
    if (cover.some((r) => rec.pendingWithdraws.some((w) => w.rowId === r.rowId))) return 'spent-epoch';
    if (cover.some((r) => r.state === 'standing' || r.state === 'matched')) return 'covered';
    if (cover.length > 0 && cover.every((r) => r.state === 'unreachable')) return 'covered-unreachable';
    const sec = await deps.secrets.depositSecrets(rec.pairId);
    if (!sec) return 'unsent';
    // pinned-K: an 'unknown' row for this epoch is the retry's row — same K, new proof.
    let row = rec.rows.find((r) => r.epoch === e && r.state === 'unknown');
    let freshMint = false;
    if (!row) {
      const mint = await deps.secrets.newRow(rec.pairId, epoch);
      row = { rowId: mint.rowId, epoch: e, H_e: '', N: '', state: 'unknown', oneTimePk: bytesToHex(mint.oneTimePk) };
      freshMint = true;
    }
    let built: { body: string; signals: Signals };
    try {
      built = await mutexed(() =>
        deps.prover.buildDeposit({ x: sec.x, counterpartY: sec.counterpartY, epoch, oneTimePk: hexToBytes(row!.oneTimePk!) }));
    } catch {
      if (freshMint) {                                                // proof died before the write-ahead save — free the fresh mint
        dropRow(rec, row);
        await deps.secrets.releaseRow(row!.rowId);
      }
      return 'unsent';
    }
    row.H_e = String(built.signals.H_e);
    row.N = String(built.signals.N);
    if (built.body.length > MAX_DEPOSIT_BYTES || new TextEncoder().encode(built.body).length > MAX_DEPOSIT_BYTES) {
      if (!(rec.refusedEpochs ??= []).includes(e)) rec.refusedEpochs.push(e);  // deterministic bad body: always repeats
      if (freshMint) {                                                        // L10c: drop only a fresh mint —
        dropRow(rec, row);
        await deps.secrets.releaseRow(row.rowId);
      }                                                                       // a possibly-sent row keeps its seed
      try { await commit(rec); } catch { return 'unsaved'; }
      return { kind: 'refused', reason: 'wire' };                     // locally indistinguishable: never send it
    }
    // L10 write-ahead + L15d BEFORE: the 'unknown' row is durable BEFORE the fetch leaves (seed
    // stays sealed), and the commit's MERGE RESULT is checked in the same step — a Remove's commit
    // that landed between the intent write and here stops the send: row not recorded, 0 requests.
    // G11: if this save fails, NOTHING is sent — the tap reports 'busy' with 0 requests.
    // R6: a failed write-ahead save means the minted seed is released at once, never held forever.
    if (freshMint) rec.rows.push(row);
    try {
      const w = await commitWriteAhead(rec);
      if ('stopped' in w) {                                         // L15d: merged tap/latch says stop
        if (freshMint) { dropRow(rec, row); await deps.secrets.releaseRow(row.rowId); }
        return 'latched';
      }
    } catch {
      if (freshMint) { dropRow(rec, row); await deps.secrets.releaseRow(row.rowId); }
      return 'unsaved';
    }
    if (await removed(rec.pairId)) {                                  // G6: latch seen before the fetch leaves —
      if (freshMint) {                                                // drop the fresh mint + release its seed; NO withdraw
        dropRow(rec, row);
        await deps.secrets.releaseRow(row.rowId);
      } else {
        queueWithdraw(rec, row.rowId, 0);                             // stored 'unknown': an earlier call may have sent it
      }
      try { await commit(rec); } catch { return 'unsaved'; }
      return 'latched';
    }
    const a = await post('deposit', built.body);
    // L2c + L15d AFTER: re-read the latch AND the stored tap BEFORE recording or acting on the
    // answer — a Remove's commit can land after the BEFORE check and before the answer arrives;
    // without this, the row stands with tap false and nothing queued. On stop the tap is 'latched'.
    const latchedNow = await removed(rec.pairId);
    const storedTap = (await deps.store.get(rec.pairId))?.tap;
    const stopped = latchedNow || storedTap?.trust !== true;
    if (a.kind === 'accepted' || a.kind === 'already') {
      if (a.kind === 'already' && freshMint) {
        // L10b: the server keeps the FIRST K — 'already' to a fresh mint means the held row is
        // under a key we don't have. 'unreachable': never polled, never withdrawn, no un-trust note.
        row.state = 'unreachable';
        await commit(rec);
        return 'already-fresh';
      }
      row.state = 'standing';
      if (stopped) {
        // L6b: the durable queue entry commits BEFORE the withdraw fetch leaves.
        queueWithdraw(rec, row.rowId, 0);
        await commit(rec);
        if ((await withdrawRow(rec, row)) === 'done') unqueueWithdraw(rec, row.rowId, row.epoch);
        return 'latched';
      }
      await commit(rec);
      return a;
    }
    if (a.kind === 'withdrawn') {
      if (!rec.spentEpochs.includes(e)) rec.spentEpochs.push(e);      // (slot,N) spent for the epoch: no retry
      dropRow(rec, row);
      await deps.secrets.releaseRow(row.rowId);
      await commit(rec);
      return stopped ? 'latched' : a;
    }
    if (a.kind === 'refused') {
      // L10c: drop + release on `refused` ONLY IF this very call minted the row and the refusal
      // answered that same first fetch. A stored 'unknown' row is a RETRY — an earlier send may
      // have landed: it STAYS 'unknown' with its seed on any other answer, resolving or closing.
      const final = NO_RETRY.has(a.reason) || a.reason.startsWith('point:');
      if (final && !(rec.refusedEpochs ??= []).includes(e)) rec.refusedEpochs.push(e);  // L12b: owed next epoch
      if (freshMint) {
        dropRow(rec, row);
        await deps.secrets.releaseRow(row.rowId);
        await commit(rec);
        return stopped ? 'latched' : a;
      }
      // a pinned retry refused: keep row + seed; a final refusal is recorded above and the row
      // retires at epoch close (L11). Remove mid-flight still owes the withdraw the send may need.
      if (stopped) queueWithdraw(rec, row.rowId, 0);
      await commit(rec);
      return stopped ? 'latched' : a;
    }
    // UNKNOWN (busy / unreadable / HTTP timeout / 429 / 503): the deposit may have landed —
    // keep the row 'unknown' and its seed; the retry re-deposits the SAME K.
    if (stopped) queueWithdraw(rec, row.rowId, 0);                    // Remove mid-flight: withdraw queued (L2c)
    await commit(rec);
    return stopped ? 'latched' : a;
  }

  async function withdrawRow(rec: PairRecord, row: RowRecord): Promise<'done' | 'queued'> {
    const a = await authed('withdraw', row);
    if (a.kind === 'withdrawn') {
      row.state = 'withdrawn';
      if (!rec.spentEpochs.includes(row.epoch)) rec.spentEpochs.push(row.epoch);   // own confirmed withdraw spends (slot,N)
      await deps.secrets.releaseRow(row.rowId);                       // confirmed: the seed may go
      return 'done';
    }
    if (a.kind === 'match') {
      row.state = 'matched';                                          // inert, NOT an error; the match counts (v2 s3)
      rec.observedMatch = true;
      // v3 A2: a withdraw answered match DURING a Remove must not re-set the cleared clock.
      // L14: the clock is stamped with the generation that observed it.
      const gen = rec.tap?.gen ?? 0;
      if ((!rec.firstMatchEpoch || rec.firstMatchEpoch.gen !== gen) && !(await removed(rec.pairId)))
        rec.firstMatchEpoch = { epoch: row.epoch, gen };
      await deps.secrets.releaseRow(row.rowId);                       // confirmed: the seed may go
      return 'done';
    }
    return 'queued';                                                  // refused-after-retry / busy / unreadable
  }

  /** v3 L11: a row whose epoch closed (not visible, at least one epoch old) is released + deleted.
   * observedMatch is a lifetime fact and survives; spentEpochs prunes entries older than two
   * epochs. 'unreachable' rows retire here too. */
  async function closeEpochs(rec: PairRecord): Promise<boolean> {
    const live = visibleEpochs(now());
    const cur = epochAt(now());
    let dirty = false;
    for (const row of [...rec.rows]) {
      if (!live.has(row.epoch) && Number(row.epoch) <= cur - 1) {
        dropRow(rec, row);
        await deps.secrets.releaseRow(row.rowId);
        dirty = true;
      }
    }
    const cutoff = cur - 2;                                              // G10: numeric compare, never string
    const spent = rec.spentEpochs.filter((e) => Number(e) >= cutoff);
    const refused = (rec.refusedEpochs ?? []).filter((e) => Number(e) >= cutoff);
    if (spent.length !== rec.spentEpochs.length) { rec.spentEpochs = spent; dirty = true; }
    if (refused.length !== (rec.refusedEpochs ?? []).length) { rec.refusedEpochs = refused; dirty = true; }
    // R8/L14c(b): tombstones prune once their row's epoch is two closed — same cutoff, numeric.
    const dr = (rec.deletedRows ?? []).filter((t) => Number(t.epoch) >= cutoff);
    const dw = (rec.deletedWithdraws ?? []).filter((t) => Number(t.epoch) >= cutoff);
    if (dr.length !== (rec.deletedRows ?? []).length) { rec.deletedRows = dr; dirty = true; }
    if (dw.length !== (rec.deletedWithdraws ?? []).length) { rec.deletedWithdraws = dw; dirty = true; }
    // watermark the prune so the merge never resurrects what we retired (union would, alone)
    if (Number(rec.closedFloor ?? 0) < cutoff) { rec.closedFloor = String(cutoff); dirty = true; }
    return dirty;
  }

  /** K: an existing entry only ever gets MORE urgent / more retried — a competing queue-write
   * (depositEpoch's stop paths) never postpones a due entry and never resets its attempts. The
   * drain's own retry reschedule (drainPendingWithdraws) writes nextAt/attempts directly — it is
   * the queue's scheduler, not a competing writer. */
  const queueWithdraw = (rec: PairRecord, rowId: string, attempts: number) => {
    const due = now() + backoff(attempts);
    const ex = rec.pendingWithdraws.find((w) => w.rowId === rowId);
    if (ex) { ex.attempts = Math.max(ex.attempts, attempts); ex.nextAt = Math.min(ex.nextAt, due); }
    else rec.pendingWithdraws.push({ rowId, attempts, nextAt: due });
  };
  /** L6e: the withdraws a Remove queues are due NOW — backoff applies from the first RETRY, never
   * the first attempt. Queues made by a deposit path after a send keep their backoff. */
  const queueWithdrawNow = (rec: PairRecord, rowId: string): void => {
    const ex = rec.pendingWithdraws.find((w) => w.rowId === rowId);
    if (ex) { ex.nextAt = now(); } else rec.pendingWithdraws.push({ rowId, attempts: 0, nextAt: now() });
  };
  const unqueueWithdraw = (rec: PairRecord, rowId: string, epoch: string): void => {
    rec.pendingWithdraws = rec.pendingWithdraws.filter((x) => x.rowId !== rowId);
    (rec.deletedWithdraws ??= []).push({ id: rowId, epoch: String(Math.max(Number(epoch), epochAt(now()))) });
  };

  /** L6b/L6c: the ONE Remove commit — intent false under gen+1, clock tombstoned, a queued withdraw
   * per live row, closed rows dropped and released. removeAtTap and the half-done-Remove repair
   * share it; it commits BEFORE any withdraw fetch leaves. */
  const removeCommitBody = async (rec: PairRecord): Promise<void> => {
    rec.firstMatchEpoch = null;                                       // G2 TOMBSTONE: wins the merge over any stale clock
    rec.tap = { gen: (rec.tap?.gen ?? 0) + 1, trust: false };         // L13: intent false under a new gen
    const live = visibleEpochs(now());
    for (const row of rec.rows) {
      // 'unknown' rows withdraw too (L2c/L10): the seed is kept until confirmed or closed.
      if (row.state === 'withdrawn' || row.state === 'spent' || row.state === 'unreachable') continue;
      if (!live.has(row.epoch)) {                                     // epoch closed: drop + release (L11)
        dropRow(rec, row);
        await deps.secrets.releaseRow(row.rowId);
        continue;
      }
      queueWithdrawNow(rec, row.rowId);                               // L6e: durable queue entry, due NOW
    }
    await commitIntent(rec, false);
    // L6d: a Remove retires every live row of the MERGED record. Its own commit merges in rows a
    // concurrent deposit wrote — they have no queue entry, and the drain walks only the queue.
    // Bounded passes (the 8-swap rule): queue every live unqueued row of the merged record, commit
    // again if any were added, repeat until a pass adds nothing. Each pass — and the latch
    // re-assert — applies only while the merged tap is still THIS Remove's (trust false at the
    // generation this commit wrote); a newer tap owns the pair and its rows are never queued.
    const myGen = rec.tap?.gen;
    for (let i = 0; i < 8; i++) {
      const cur = await deps.store.get(rec.pairId);
      if (cur?.tap?.gen !== myGen || cur.tap.trust !== false) break;      // a newer tap holds it
      let added = false;
      for (const row of rec.rows) {
        if (row.state === 'withdrawn' || row.state === 'spent' || row.state === 'unreachable') continue;
        if (!live.has(row.epoch)) continue;
        if (rec.pendingWithdraws.some((w) => w.rowId === row.rowId)) continue;
        queueWithdrawNow(rec, row.rowId);
        added = true;
      }
      if (!added) break;
      await commit(rec);                                                // merge pulls in rows that landed since
    }
    // L6d: re-assert the LOCAL latch if it is gone — a Trust that cleared it but lost the commit
    // race must leave the pair visibly 'removed' so L6c can still see (and repair) it. Same
    // generation guard: beside a NEWER trust-true tap, a latch here would read as a half-done
    // Remove and undo that Trust.
    const last = await deps.store.get(rec.pairId);
    if (last?.tap?.gen === myGen && last.tap.trust === false &&
        (await deps.latch.kindOf(rec.pairId, 'local')) !== 'removed')
      await deps.latch.setLatched(rec.pairId, 'local');
  };

  /** L15d BEFORE: the write-ahead commit of a deposit row is a compare-and-swap whose MERGE RESULT
   * is checked in that same step — never an earlier separate read. "stop" = a 'removed' latch
   * (either source, read alongside) OR the merged tap is not trust-true (a higher generation or a
   * false-wins tie holds the intent — mergeTap already embodies both). On stop: the row is not
   * recorded, nothing is sent, the caller returns 'latched'. */
  const commitWriteAhead = async (rec: PairRecord): Promise<{ ok: true } | { stopped: true }> => {
    if (await removed(rec.pairId)) return { stopped: true };
    for (let i = 0; i < 8; i++) {
      const cur = await deps.store.get(rec.pairId);
      const base = cur?.version ?? 0;
      const next = mergeRec(cur, rec);
      if (next.tap?.trust !== true) return { stopped: true };         // the MERGE RESULT decides
      next.version = base + 1;
      if (await deps.store.cas(rec.pairId, base, next)) {
        Object.assign(rec, next);
        return { ok: true };
      }
    }
    throw new Error(`beacon write-ahead: CAS lost 8 attempts for ${rec.pairId}`);
  };

  /** The Remove queue drain: a confirmed withdraw removes its entry (idempotent on the server). */
  const drainQueuedWithdraws = async (rec: PairRecord): Promise<void> => {
    const live = visibleEpochs(now());
    const cur = epochAt(now());
    for (const w of [...rec.pendingWithdraws]) {
      const row = rec.rows.find((r) => r.rowId === w.rowId);
      if (!row || (!live.has(row.epoch) && Number(row.epoch) <= cur - 1)) {
        unqueueWithdraw(rec, w.rowId, row?.epoch ?? String(cur));
        if (row) await deps.secrets.releaseRow(row.rowId);
        continue;
      }
      if ((await withdrawRow(rec, row)) === 'done') unqueueWithdraw(rec, row.rowId, row.epoch);
    }
  };

  /** L6c: a half-done Remove — the LOCAL latch is 'removed' AND tap.trust is still true. The commit
   * in removeAtTap never landed (crash, or 8 lost swaps); the queued withdraws were never written.
   * Repair with the SAME single commit, then the caller's normal drain retires the queue.
   * A REMOTE 'removed' never triggers it and never changes tap (L14b: clock cleared, trust
   * unchanged, no withdraw queued). Skipped while a removeAtTap for the pair is in flight HERE —
   * the setLatched→commit window must not bump gen twice. */
  const repairHalfDoneRemove = async (pairId: string): Promise<boolean> => {
    if (removing.has(pairId)) return false;
    if ((await deps.latch.kindOf(pairId, 'local')) !== 'removed') return false;
    const rec = await deps.store.get(pairId);
    if (!rec || rec.tap?.trust !== true) return false;
    await removeCommitBody(rec);
    return true;
  };
  return {
    /** v2 s1: the first deposit happens AT THE TAP. Clears the LOCAL latch only (L5); a remote latch still blocks. */
    async trustAtTap(pairId) {
      const mine = ++callSeq;
      lastCall.set(pairId, mine);                                       // synchronous, before the first await
      // L15: capture the DURABLE generation as the FIRST await — the intent write applies only
      // while the stored gen is still g0; if it moved, a tap this client cannot order against won.
      const g0 = (await deps.store.get(pairId))?.tap?.gen ?? 0;
      if (!(await deps.confirmed.isConfirmed(pairId))) return { kind: 'unconfirmed' };   // L7: fail closed
      if (lastCall.get(pairId) !== mine) return { kind: 'latched' };    // a newer tap owns this pair now — step aside
      // v3 L5: the tap clears a 'removed' LOCAL latch only — 'frozen' ends only by explicit Unfreeze.
      let clearedLocal = false;                                         // L15: yield must un-do our own clear
      if ((await deps.latch.kindOf(pairId)) === 'removed') {
        await deps.latch.clearLatched(pairId, 'local');
        clearedLocal = true;
      }
      if (await removed(pairId)) return { kind: 'latched' };            // a 'removed' latch stands ('frozen' does not block)
      const rec = await getRec(pairId);
      // L13 TAP INTENT, written durably BEFORE the first proof (L13d: after the checks above — an
      // 'unconfirmed' or 'latched' tap writes nothing). L13b: a repeat tap on a trusted pair writes
      // nothing — the generation and the match clock are left untouched. L13c: the generation is
      // computed from the STORED record inside the compare-and-swap.
      const firstTap = rec.tap?.trust !== true;
      let intentGen: number | undefined;
      let wroteIntent = false;
      if (firstTap) {
        rec.tap = { gen: (rec.tap?.gen ?? 0) + 1, trust: true };
        let w: { ok: true } | { moved: PairRecord };
        try {
          w = await commitIntent(rec, true, g0);                        // L15: applies only while gen is still g0
        } catch {
          return { kind: 'busy' };                                    // the intent write failed — nothing left
        }
        if ('moved' in w) {
          // L15: a tap this client cannot order against landed between the read and the write.
          // Decide EVERYTHING from this one stored record — no second `get`.
          if (w.moved.tap?.trust !== true) {
            if (clearedLocal) await deps.latch.setLatched(pairId, 'local');  // un-do our own latch clear
            return { kind: 'latched' };                                    // yield to the Remove — 0 requests
          }
          // stored trust TRUE: another Trust won — continue as an ordinary repeat tap (L13b):
          // no intent write, do NOT restore the latch, report the real result, never 'latched'.
          Object.assign(rec, w.moved);
        } else {
          intentGen = rec.tap!.gen;                                     // the generation THIS tap wrote
          wroteIntent = true;
        }
      }
      const touched = depositableEpochs(now());
      // R7: the tap's result starts NEUTRAL — 'deposited' needs a wire answer or a covering row;
      // a proof that outlives its epoch never reports 'covered' it didn't earn.
      let saw: Answer | DepositOutcome = 'pending';
      for (const epoch of touched) {
        const a = await depositEpoch(rec, epoch);
        if (epoch === BigInt(epochAt(now()))) saw = a;
      }
      let commitFailed = false;
      try {
        await commit(rec);
      } catch (err) {
        if (typeof saw !== 'string') throw err;                       // the wire answered — fail loudly
        commitFailed = true;                                          // nothing reached the wire — 'busy'
      }
      // L13e (part 3): the intent STANDS whenever anything could be on the server — look across
      // EVERY epoch the loop touched for a row that is unknown, standing, matched or unreachable.
      // The DURABLE record decides: an unsaved in-memory row never left the device.
      const stored = (await deps.store.get(pairId)) ?? rec;
      const touchedSet = new Set(touched.map(String));
      const liveRow = stored.rows.some((r) =>
        touchedSet.has(r.epoch) &&
        (r.state === 'unknown' || r.state === 'standing' || r.state === 'matched' || r.state === 'unreachable'));
      const result = (): TrustResult => {
        if (saw === 'covered') return { kind: 'deposited' };          // a standing/matched row covers the epoch
        if (saw === 'covered-unreachable' || saw === 'already-fresh') return { kind: 'unreachable' };
        if (saw === 'spent-epoch') return { kind: 'spent' };          // spent incl. L8d queued-withdraw epochs
        if (saw === 'latched') return { kind: 'latched' };            // Remove mid-proof — nothing sent
        if (saw.kind === 'accepted' || saw.kind === 'already') return { kind: 'deposited' };
        if (saw.kind === 'withdrawn') return { kind: 'spent' };
        if (liveRow) return { kind: 'pending' };                      // L13e-2: a fetch LEFT — pending even when the
        //                                                            // final commit failed after that fetch (delta7)
        if (saw === 'refused-epoch') return { kind: 'failed' };       // a final refusal stands for this epoch
        if (saw === 'unsent') return { kind: 'unsent' };              // proof threw / no secrets — nothing sent
        if (saw === 'unsaved') return { kind: 'busy' };               // write-ahead lost CAS — 'busy' ONLY if nothing left
        if (commitFailed) return { kind: 'busy' };                    // nothing reached the wire AND the save lost
        if (saw.kind === 'refused' && (NO_RETRY.has(saw.reason) || saw.reason.startsWith('point:'))) return { kind: 'failed' };
        if (saw.kind === 'busy' || saw.kind === 'unreadable') return { kind: 'pending' };  // the fetch LEFT (L13e-2)
        return { kind: 'pending' };                                   // unknown/transient: owed, retried pinned-K
      };
      const out = result();
      // L15d: on either stop the tap is 'latched' — restore the LOCAL latch if THIS call cleared
      // it, decided from the same stored read that resolved the state ('removed' visibility must
      // outlive a lost race); never while the stored trust is true — a Trust that landed keeps its
      // cleared latch.
      if (out.kind === 'latched' && clearedLocal && stored.tap?.trust !== true)
        await deps.latch.setLatched(pairId, 'local');
      // L13e: a FIRST tap the person was told failed with nothing possibly on the server restores
      // the intent to FALSE under a new gen — only while the stored gen is still this tap's (L13e-3).
      const RESTORABLE = new Set(['busy', 'unsent', 'failed', 'latched']);
      if (wroteIntent && !liveRow && intentGen !== undefined && RESTORABLE.has(out.kind))
        await restoreIntent(pairId, intentGen);
      return out;
    },

    /** v2 s2: latch FIRST and durably, then network. Returns observedMatch for the note layer (v2 s3).
     * L6b: Remove makes ONE durable commit BEFORE its first withdraw fetch, holding the intent
     * {gen+1, trust:false}, the cleared match clock, and a queued withdraw for every covered row —
     * an app closed mid-Remove leaves the rows withdrawable, never standing-with-nothing-queued.
     * Bound: this closes the CRASH window only; until a withdraw lands the server holds the row. */
    async removeAtTap(pairId) {
      lastCall.set(pairId, ++callSeq);                                  // synchronous, before the first await
      removing.add(pairId);                                             // L6c: in-flight marker — the repair must not double-commit
      try {
        await deps.latch.setLatched(pairId, 'local');                   // L1: first and durably, before any network
        const rec = await getRec(pairId);
        await removeCommitBody(rec);                                    // ONE durable commit BEFORE the first fetch
        await drainQueuedWithdraws(rec);                                // confirmed withdraws retire their entries
        await commit(rec);
        return { observedMatch: rec.observedMatch };
      } finally {
        removing.delete(pairId);
      }
    },

    /** v2 L4: the ONE consumer-facing match view — latch applied (either kind), closed epochs faded. Consumers: the
     * UI label, the send gate, receipts, the re-deposit scheduler, the circle-set builder, the tag-block builder. */
    async matchState(pairId) {
      if (!(await deps.confirmed.isConfirmed(pairId))) return 'none';
      const kind = await deps.latch.kindOf(pairId);
      if (kind !== null) return 'none';                                 // reads never write (G7); the clock tombstone is durable from Remove
      const rec = await deps.store.get(pairId);
      if (!rec) return 'none';
      const live = visibleEpochs(now());
      return rec.rows.some((r) => r.state === 'matched' && live.has(r.epoch)) ? 'match' : 'none';
    },

    /** v3 A2: the epoch INDEX the match was first observed, or null. A 'removed' latch hides AND
     * cleared it (removeAtTap deleted the stored epoch — re-Trust restarts the clock); 'frozen'
     * does not hide it. Local read only (no wire request). */
    async matchSince(pairId) {
      if (!(await deps.confirmed.isConfirmed(pairId))) return null;
      if ((await deps.latch.kindOf(pairId)) === 'removed') return null; // reads never write (G7)
      const rec = await deps.store.get(pairId);
      const e = rec?.firstMatchEpoch;
      // L14: the clock is valid only while its stamped gen equals the current tap.gen.
      return e && rec?.tap && e.gen === rec.tap.gen ? Number(e.epoch) : null;
    },

    /** the scheduled action (v1 s3.4 + v2 L3): owed deposits, then poll, then the withdraw queue. */
    async renew(pairId) {
      if (!(await deps.confirmed.isConfirmed(pairId))) return;
      if (await removed(pairId)) {
        // L6c: a half-done Remove (local latch set, intent still true) is repaired here too —
        // same commit, then the normal drain retires the queue. Remote 'removed' never triggers.
        if (await repairHalfDoneRemove(pairId)) await this.drainPendingWithdraws();
        return;                                                       // 'removed' skips; 'frozen' renews on schedule
      }
      const rec = await getRec(pairId);
      // L13: renewal runs only while the tap intent is true — a confirmed pair with no record, or a
      // record with no `tap` (or a restored trust:false), deposits NOTHING and builds no proof.
      if (rec.tap?.trust !== true) return;
      // L12: owed is derived — try EVERY depositable epoch; depositEpoch itself skips spent,
      // refused-for-epoch and covered epochs. No flag gates renewal; a matched pair renews too.
      for (const epoch of depositableEpochs(now())) {
        await depositEpoch(rec, epoch);
      }
      if (await closeEpochs(rec)) await commit(rec);
      await this.pollNow(pairId);
      await this.drainPendingWithdraws();
    },

    /** poll every standing/matched row in a live epoch. 'none' and silence are treated identically. */
    async pollNow(pairId) {
      if (!(await deps.confirmed.isConfirmed(pairId))) return;
      const rec = await deps.store.get(pairId);
      if (!rec) return;
      // L13f: a poll needs an intent — a pair whose tap.trust is not true polls nothing, so
      // observedMatch and matchState cannot be set for a pair the person never chose to trust.
      if (rec.tap?.trust !== true) return;
      const live = visibleEpochs(now());
      let dirty = false;
      for (const row of rec.rows) {
        // 'unknown' rows are pollable (L10): a match/none answer shows the row exists.
        if ((row.state !== 'standing' && row.state !== 'matched' && row.state !== 'unknown') || !live.has(row.epoch)) continue;
        if (await removed(pairId)) continue;                            // L3: 'removed' pairs are skipped ('frozen' still polls)
        const a = await authed('poll', row);
        if (await removed(pairId)) continue;                            // L2b: a tap mid-flight must not flip it back
        if (a.kind === 'match') {
          row.state = 'matched'; rec.observedMatch = true;
          const gen = rec.tap.gen;
          if (!rec.firstMatchEpoch || rec.firstMatchEpoch.gen !== gen)  // first observation under this gen
            rec.firstMatchEpoch = { epoch: row.epoch, gen };
          dirty = true;
        }
      }
      if (dirty) await commit(rec);
    },

    /** the jittered re-deposit time inside the current epoch (v1 s3.4, renewal only). */
    async nextRenewalAt() {
      const start = epochAt(now()) * EPOCH_SECONDS * 1000;
      return deps.prover.scheduleRedeposit({ epochStartMs: start, epochSeconds: EPOCH_SECONDS, graceSeconds: GRACE_SECONDS });
    },

    /** L6 + v3 L11: retry durable pending withdraws; confirmed (withdrawn|match) or epoch-closed
     * -> released. Runs for latched pairs too — renew returns early on a latch, so the scheduler
     * keeps calling this to retire queues. */
    async drainPendingWithdraws() {
      const live = visibleEpochs(now());
      const cur = epochAt(now());
      for (const stored of await deps.store.pairs()) {
        // L6c: repair a half-done Remove before touching the pair's queue — same single commit,
        // then THIS drain retires the entries it queued.
        if (await repairHalfDoneRemove(stored.pairId)) { /* committed inside repair; rec reload below */ }
        const rec = (await deps.store.get(stored.pairId)) ?? stored;      // refresh after a repair
        let dirty = false;
        const resched = new Map<string, { attempts: number; nextAt: number }>();
        // G2/G7: a 'removed' latch observed on a WRITE path tombstones the match clock —
        // covers latches set outside removeAtTap (remote un-trust notes). Reads never do it.
        // L14b: clearing the clock bumps the generation (trust unchanged) so a stale copy
        // cannot write the old clock back under the tie rule.
        if ((await removed(rec.pairId)) && rec.firstMatchEpoch != null) {
          rec.firstMatchEpoch = null;
          rec.tap = { gen: (rec.tap?.gen ?? 0) + 1, trust: rec.tap?.trust ?? false };
          dirty = true;
        }
        for (const w of [...rec.pendingWithdraws]) {
          dirty = true;
          const row = rec.rows.find((r) => r.rowId === w.rowId);
          if (!row || (!live.has(row.epoch) && Number(row.epoch) <= cur - 1)) {   // epoch closed: drop + release (L11)
            unqueueWithdraw(rec, w.rowId, row?.epoch ?? String(cur));
            if (row) await deps.secrets.releaseRow(row.rowId);
            dirty = true;
            continue;
          }
          if (w.nextAt > now()) continue;
          const before = rec.observedMatch;
          const out = await withdrawRow(rec, row);
          dirty = dirty || out === 'done' || rec.observedMatch !== before;
          if (out === 'queued') { resched.set(w.rowId, { attempts: w.attempts, nextAt: w.nextAt }); w.attempts += 1; w.nextAt = now() + backoff(w.attempts); }   // the drain's own reschedule
          else unqueueWithdraw(rec, w.rowId, row.epoch);
        }
        if (await closeEpochs(rec)) dirty = true;
        if (dirty) await commit(rec, resched);
      }
    },
  };
}

/** Wiring helper: adapt beacon-prover.ts (files supplied by the caller; nothing here loads them). */
export function defaultProver(files: () => Promise<{ wasm: Uint8Array; zkey: Uint8Array }>): BeaconProverPort {
  return {
    buildDeposit: async (keys) => {
      const f = await files();
      const body = await buildDeposit(keys, f);
      return { body, signals: wire.parseDeposit(body).signals };
    },
    signAuth: (op, H_e, N, nonce, sign) => signAuth(op, H_e, N, nonce, sign),
    scheduleRedeposit: (o) => scheduleRedeposit(o),
  };
}
