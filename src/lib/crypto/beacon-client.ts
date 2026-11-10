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
  kindOf(pairId: string): Promise<'removed' | 'frozen' | null>;
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
export interface PairRecord {
  pairId: string;
  /** lifetime fact for the note layer: a poll ever answered match OR a withdraw answered match (v2 s3). */
  observedMatch: boolean;
  /** the epoch of the row whose match answer was FIRST observed; CLEARED by a 'removed' latch (v3 A2 —
   * a Remove then a re-Trust restarts the clock), unchanged by 'frozen'. matchSince() serves it. */
  firstMatchEpoch?: string;
  /** epochs whose (slot,N) is spent — a 'withdrawn' deposit answer; never re-deposited (v1 s2). */
  spentEpochs: string[];
  /** a deposit is owed: the tap wanted one and a transient answer kept it out (retried at renewal). */
  pendingDeposit: boolean;
  rows: RowRecord[];
  pendingWithdraws: PendingWithdraw[];
  /** rowIds this writer deliberately dropped (refused-drop / L11 close) — without it the L6b
   * merge's row union would resurrect them from the other writer's stale copy. */
  deletedRows?: string[];
  /** rowIds whose pendingWithdraw entries this writer retired — same merge-resurrection guard. */
  deletedWithdraws?: string[];
  /** write-serialisation version (v3 L6b): bumped on every committed write; CAS stores refuse a stale base. */
  version?: number;
}
export interface BeaconStorePort {
  get(pairId: string): Promise<PairRecord | undefined>;
  put(rec: PairRecord): Promise<void>;
  /** v3 L6b: atomic compare-and-swap — write `next` only if the stored record still carries
   * `expectedVersion`. Two open tabs share the durable store, so a client-side queue can't
   * serialise them; stores that can't CAS may omit this and get merge-then-put instead. */
  cas?(pairId: string, expectedVersion: number, next: PairRecord): Promise<boolean>;
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
  | { kind: 'busy' } | { kind: 'latched' } | { kind: 'unconfirmed' } | { kind: 'unsent' };
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
  ({ pairId, observedMatch: false, spentEpochs: [], pendingDeposit: false, rows: [], pendingWithdraws: [] });

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

  const getRec = async (pairId: string) => (await deps.store.get(pairId)) ?? fresh(pairId);

  /** v3 L6b: writes to a pair's record are serialised — compare-and-swap on `version` when the
   * store supports it, else a merge-then-put so an older tap's save can never REPLACE a record
   * that changed after it read it (pendingWithdraws written by removeAtTap survive). The merge
   * unions the append-only fields and keeps our newest row states. */
  const dropRow = (rec: PairRecord, row: RowRecord): void => {
    rec.rows = rec.rows.filter((r) => r !== row);
    (rec.deletedRows ??= []).push(row.rowId);
  };
  const mergeRec = (cur: PairRecord | undefined, ours: PairRecord): PairRecord => {
    if (!cur) return ours;
    const del = new Set(ours.deletedRows ?? []);
    const rows = new Map(cur.rows.filter((r) => !del.has(r.rowId)).map((r) => [r.rowId, r]));
    for (const r of ours.rows) rows.set(r.rowId, r);                 // our view is newer per row
    const delW = new Set(ours.deletedWithdraws ?? []);
    const wds = new Map(cur.pendingWithdraws.filter((w) => !delW.has(w.rowId)).map((w) => [w.rowId, w]));
    for (const w of ours.pendingWithdraws) wds.set(w.rowId, w);
    return {
      ...ours,
      observedMatch: cur.observedMatch || ours.observedMatch,
      firstMatchEpoch: ours.firstMatchEpoch ?? cur.firstMatchEpoch,
      spentEpochs: [...new Set([...cur.spentEpochs, ...ours.spentEpochs])],
      pendingDeposit: cur.pendingDeposit || ours.pendingDeposit,
      rows: [...rows.values()],
      pendingWithdraws: [...wds.values()],
      deletedRows: [...new Set([...(cur.deletedRows ?? []), ...(ours.deletedRows ?? [])])],
      deletedWithdraws: [...new Set([...(cur.deletedWithdraws ?? []), ...(ours.deletedWithdraws ?? [])])],
    };
  };
  const commit = async (rec: PairRecord): Promise<void> => {
    if (deps.store.cas) {
      for (let i = 0; i < 8; i++) {
        const cur = await deps.store.get(rec.pairId);
        const base = cur?.version ?? 0;
        const next = mergeRec(cur, rec);
        next.version = base + 1;
        if (await deps.store.cas(rec.pairId, base, next)) {
          Object.assign(rec, next);
          return;
        }
      }
    }
    const cur = await deps.store.get(rec.pairId);
    const merged = mergeRec(cur, rec);
    merged.version = (cur?.version ?? 0) + 1;
    await deps.store.put(merged);
    Object.assign(rec, merged);
  };

  /** Latch gates: 'removed' stops every wire action for the pair (L3); 'frozen' only masks the local match view —
   * deposits, polls and honest row bookkeeping keep running on schedule. */
  const removed = (pairId: string) => deps.latch.kindOf(pairId).then((k) => k === 'removed');

  /** Call order per pair: the LAST tap issued owns the pair's fate. A trust tap clears its local latch only while it
   * is still the latest call — otherwise a Remove issued a tick later would have its latch write silently undone. */
  const lastCall = new Map<string, number>();
  let callSeq = 0;

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

  /** deposit for one epoch if no row covers it and it isn't spent.
   * v3 L10: the 'unknown' row (rowId + pinned oneTimePk + derived H_e/N) is saved durably BEFORE
   * the deposit fetch leaves — a lost answer never loses the row. Only a refused body means
   * not-stored (drop + release); every other outcome is UNKNOWN and retries with the SAME K.
   * v3 L2c: after the fetch returns the latch is re-read BEFORE recording — a Remove mid-flight
   * ends with a withdraw sent or durably queued. Returns the wire answer, or a sentinel. */
  async function depositEpoch(rec: PairRecord, epoch: bigint): Promise<Answer | 'skipped' | 'unsent' | 'latched'> {
    const e = String(epoch);
    if (rec.spentEpochs.includes(e)) return 'skipped';
    if (rec.rows.some((r) => r.epoch === e && (r.state === 'standing' || r.state === 'matched'))) return 'skipped';
    const sec = await deps.secrets.depositSecrets(rec.pairId);
    if (!sec) { rec.pendingDeposit = true; return 'unsent'; }
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
      rec.pendingDeposit = true;
      return 'unsent';
    }
    row.H_e = String(built.signals.H_e);
    row.N = String(built.signals.N);
    if (built.body.length > MAX_DEPOSIT_BYTES || new TextEncoder().encode(built.body).length > MAX_DEPOSIT_BYTES) {
      dropRow(rec, row);
      if (freshMint) await deps.secrets.releaseRow(row.rowId);
      return { kind: 'refused', reason: 'wire' };                     // locally indistinguishable: never send it
    }
    // L10 write-ahead: the 'unknown' row is durable BEFORE the fetch leaves (seed stays sealed).
    if (freshMint) rec.rows.push(row);
    await commit(rec);
    if (await removed(rec.pairId)) {                                  // v2 L2a: a tap mid-proof sends nothing — but L2c queues the withdraw
      queueWithdraw(rec, row.rowId, 0);
      await commit(rec);
      return 'latched';
    }
    const a = await post('deposit', built.body);
    // L2c: re-read the latch BEFORE recording or acting on the answer.
    const latchedNow = await removed(rec.pairId);
    if (a.kind === 'accepted' || a.kind === 'already') {
      if (a.kind === 'already' && freshMint) {
        // L10b: the server keeps the FIRST K — 'already' to a fresh mint means the held row is
        // under a key we don't have. 'unreachable': never polled, never withdrawn, no un-trust note.
        row.state = 'unreachable';
        rec.pendingDeposit = false;
        await commit(rec);
        return a;
      }
      row.state = 'standing';
      rec.pendingDeposit = false;
      if (latchedNow) {
        if ((await withdrawRow(rec, row)) === 'queued') queueWithdraw(rec, row.rowId, 0);
      }
      await commit(rec);
      return a;
    }
    if (a.kind === 'withdrawn') {
      if (!rec.spentEpochs.includes(e)) rec.spentEpochs.push(e);      // (slot,N) spent for the epoch: no retry
      rec.pendingDeposit = false;
      dropRow(rec, row);
      await deps.secrets.releaseRow(row.rowId);
      await commit(rec);
      return a;
    }
    if (a.kind === 'refused') {
      // a refused body (incl. the verifier's own 'timeout') means nothing was stored: drop + release.
      dropRow(rec, row);
      await deps.secrets.releaseRow(row.rowId);
      rec.pendingDeposit = !(NO_RETRY.has(a.reason) || a.reason.startsWith('point:'));
      await commit(rec);
      return a;
    }
    // UNKNOWN (busy / unreadable / HTTP timeout / 429 / 503): the deposit may have landed —
    // keep the row 'unknown' and its seed; the retry re-deposits the SAME K.
    rec.pendingDeposit = true;
    if (latchedNow) queueWithdraw(rec, row.rowId, 0);                 // Remove mid-flight: withdraw queued (L2c)
    await commit(rec);
    return a;
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
      if (!rec.firstMatchEpoch && !(await removed(rec.pairId))) rec.firstMatchEpoch = row.epoch;
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
    const cutoff = String(cur - 2);
    const spent = rec.spentEpochs.filter((e) => e >= cutoff);
    if (spent.length !== rec.spentEpochs.length) { rec.spentEpochs = spent; dirty = true; }
    return dirty;
  }

  const queueWithdraw = (rec: PairRecord, rowId: string, attempts: number) => {
    const due = now() + backoff(attempts);
    const ex = rec.pendingWithdraws.find((w) => w.rowId === rowId);
    if (ex) { ex.attempts = attempts; ex.nextAt = due; } else rec.pendingWithdraws.push({ rowId, attempts, nextAt: due });
  };
  const unqueueWithdraw = (rec: PairRecord, rowId: string): void => {
    rec.pendingWithdraws = rec.pendingWithdraws.filter((x) => x.rowId !== rowId);
    (rec.deletedWithdraws ??= []).push(rowId);
  };
  /** v3 A2: a 'removed' latch clears the match clock wherever it is observed — local Remove
   * (removeAtTap) or a remote un-trust note seen on a read. Delete on sight. */
  const clearClockIfRemoved = async (pairId: string, rec?: PairRecord) => {
    if (!(await removed(pairId))) return;
    const r = rec ?? await deps.store.get(pairId);
    if (r?.firstMatchEpoch !== undefined) { delete r.firstMatchEpoch; await deps.store.put(r); }
  };

  return {
    /** v2 s1: the first deposit happens AT THE TAP. Clears the LOCAL latch only (L5); a remote latch still blocks. */
    async trustAtTap(pairId) {
      const mine = ++callSeq;
      lastCall.set(pairId, mine);                                       // synchronous, before the first await
      if (!(await deps.confirmed.isConfirmed(pairId))) return { kind: 'unconfirmed' };   // L7: fail closed
      if (lastCall.get(pairId) !== mine) return { kind: 'latched' };    // a newer tap owns this pair now — step aside
      // v3 L5: the tap clears a 'removed' LOCAL latch only — 'frozen' ends only by explicit Unfreeze.
      if ((await deps.latch.kindOf(pairId)) === 'removed') await deps.latch.clearLatched(pairId, 'local');
      if (await removed(pairId)) return { kind: 'latched' };            // a 'removed' latch stands ('frozen' does not block)
      const rec = await getRec(pairId);
      let saw: Answer | 'skipped' | 'unsent' | 'latched' = 'skipped';
      for (const epoch of depositableEpochs(now())) {
        const a = await depositEpoch(rec, epoch);
        if (epoch === BigInt(epochAt(now()))) saw = a;
      }
      await commit(rec);
      // v3 honesty: 'deposited' only when the wire answered accepted/already — never for unsent work.
      if (saw === 'skipped') return { kind: 'deposited' };              // a standing row already covers the epoch
      if (saw === 'unsent') return { kind: 'unsent' };                  // proof threw / no secrets — nothing sent
      if (saw === 'latched') return { kind: 'latched' };                // Remove mid-proof — nothing sent, withdraw queued
      if (saw.kind === 'accepted' || saw.kind === 'already') return { kind: 'deposited' };
      if (saw.kind === 'withdrawn') return { kind: 'spent' };
      if (saw.kind === 'busy') return { kind: 'busy' };
      if (saw.kind === 'refused' && (NO_RETRY.has(saw.reason) || saw.reason.startsWith('point:'))) return { kind: 'failed' };
      return { kind: 'pending' };                                     // unknown/transient: owed, retried with the pinned K
    },

    /** v2 s2: latch FIRST and durably, then network. Returns observedMatch for the note layer (v2 s3). */
    async removeAtTap(pairId) {
      lastCall.set(pairId, ++callSeq);                                  // synchronous, before the first await
      await deps.latch.setLatched(pairId, 'local');                     // L1: first and durably, before any network
      const rec = await getRec(pairId);
      delete rec.firstMatchEpoch;                                       // v3 A2: 'removed' clears matchSince — a re-Trust restarts the clock
      const live = visibleEpochs(now());
      for (const row of rec.rows) {
        // 'unknown' rows withdraw too (L2c/L10): the seed is kept until confirmed or closed.
        if (row.state === 'withdrawn' || row.state === 'spent' || row.state === 'unreachable' || !live.has(row.epoch)) continue;
        if ((await withdrawRow(rec, row)) === 'queued') queueWithdraw(rec, row.rowId, 0);   // L6: durable, retried, seed kept
      }
      await commit(rec);
      return { observedMatch: rec.observedMatch };
    },

    /** v2 L4: the ONE consumer-facing match view — latch applied (either kind), closed epochs faded. Consumers: the
     * UI label, the send gate, receipts, the re-deposit scheduler, the circle-set builder, the tag-block builder. */
    async matchState(pairId) {
      if (!(await deps.confirmed.isConfirmed(pairId))) return 'none';
      const kind = await deps.latch.kindOf(pairId);
      if (kind === 'removed') { await clearClockIfRemoved(pairId); return 'none'; }
      if (kind !== null) return 'none';
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
      if ((await deps.latch.kindOf(pairId)) === 'removed') { await clearClockIfRemoved(pairId); return null; }
      const e = (await deps.store.get(pairId))?.firstMatchEpoch;
      return e === undefined ? null : Number(e);
    },

    /** the scheduled action (v1 s3.4 + v2 L3): owed deposits, then poll, then the withdraw queue. */
    async renew(pairId) {
      if (!(await deps.confirmed.isConfirmed(pairId))) return;
      if (await removed(pairId)) return;                                // 'removed' skips; 'frozen' renews on schedule
      const rec = await getRec(pairId);
      if (rec.pendingDeposit) {
        for (const epoch of depositableEpochs(now())) {
          if (!rec.pendingDeposit) break;
          await depositEpoch(rec, epoch);
        }
      }
      if (await closeEpochs(rec) || rec.pendingDeposit) await commit(rec);
      await this.pollNow(pairId);
      await this.drainPendingWithdraws();
    },

    /** poll every standing/matched row in a live epoch. 'none' and silence are treated identically. */
    async pollNow(pairId) {
      if (!(await deps.confirmed.isConfirmed(pairId))) return;
      const rec = await deps.store.get(pairId);
      if (!rec) return;
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
          if (!rec.firstMatchEpoch) rec.firstMatchEpoch = row.epoch;    // first observation only — the match's epoch
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
      for (const rec of await deps.store.pairs()) {
        let dirty = false;
        for (const w of [...rec.pendingWithdraws]) {
          dirty = true;
          const row = rec.rows.find((r) => r.rowId === w.rowId);
          if (!row || (!live.has(row.epoch) && Number(row.epoch) <= cur - 1)) {   // epoch closed: drop + release (L11)
            unqueueWithdraw(rec, w.rowId);
            if (row) await deps.secrets.releaseRow(row.rowId);
            dirty = true;
            continue;
          }
          if (w.nextAt > now()) continue;
          const before = rec.observedMatch;
          const out = await withdrawRow(rec, row);
          dirty = dirty || out === 'done' || rec.observedMatch !== before;
          if (out === 'queued') queueWithdraw(rec, w.rowId, w.attempts + 1);
          else unqueueWithdraw(rec, w.rowId);
        }
        if (await closeEpochs(rec)) dirty = true;
        if (dirty) await commit(rec);
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
