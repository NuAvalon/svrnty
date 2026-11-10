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

/** The durable "this pair is removed" record, owned by the vault side. local = my Remove/Block; remote = an un-trust note. */
export interface LatchPort {
  isLatched(pairId: string): Promise<boolean>;
  setLatched(pairId: string, source: 'local' | 'remote'): Promise<void>;
  clearLatched(pairId: string, source: 'local' | 'remote'): Promise<void>;
}
/** After a seed-only restore the owner must re-confirm each pair before any request may be made for it (v2 L7). */
export interface PairConfirmedPort {
  isConfirmed(pairId: string): Promise<boolean>;
}
/** One deposited row's PUBLIC record: canonical decimal strings only, no secret material. */
export interface RowRecord {
  rowId: string;
  epoch: string;
  H_e: string;
  N: string;
  state: 'standing' | 'matched' | 'withdrawn' | 'spent';
}
export interface PendingWithdraw { rowId: string; attempts: number; nextAt: number }
export interface PairRecord {
  pairId: string;
  /** lifetime fact for the note layer: a poll ever answered match OR a withdraw answered match (v2 s3). */
  observedMatch: boolean;
  /** epochs whose (slot,N) is spent — a 'withdrawn' deposit answer; never re-deposited (v1 s2). */
  spentEpochs: string[];
  /** a deposit is owed: the tap wanted one and a transient answer kept it out (retried at renewal). */
  pendingDeposit: boolean;
  rows: RowRecord[];
  pendingWithdraws: PendingWithdraw[];
}
export interface BeaconStorePort {
  get(pairId: string): Promise<PairRecord | undefined>;
  put(rec: PairRecord): Promise<void>;
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
  | { kind: 'busy' } | { kind: 'latched' } | { kind: 'unconfirmed' };
export interface BeaconClient {
  trustAtTap(pairId: string): Promise<TrustResult>;
  removeAtTap(pairId: string): Promise<{ observedMatch: boolean }>;
  matchState(pairId: string): Promise<'match' | 'none'>;
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

  /** Call order per pair: the LAST tap issued owns the pair's fate. A trust tap clears its local latch only while it
   * is still the latest call — otherwise a Remove issued a tick later would have its latch write silently undone. */
  const lastCall = new Map<string, number>();
  let callSeq = 0;

  // ---- transport (module-private: the raw answer must not leave this file, v2 L4) ----

  async function post(op: 'deposit' | 'nonce' | 'poll' | 'withdraw', body: string): Promise<Answer> {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
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
    } catch {
      return { kind: 'busy' };                                    // network failure / abort: the one retryable class
    } finally {
      clearTimeout(t);
    }
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
      return { kind: o.status } as Answer;
    }
    if (keys.length === 2 && o.status === 'refused' && typeof o.reason === 'string' && REASONS.has(o.reason)) {
      return { kind: 'refused', reason: o.reason as RefusalReason };
    }
    return { kind: 'unreadable' };
  }

  const NO_RETRY = new Set(['wire', 'vkey', 'proof', 'usage']);   // + every 'point:*' — the client produced a bad body
  const transient = (a: Answer) =>
    a.kind === 'busy' || a.kind === 'unreadable' ||
    (a.kind === 'refused' && ['full', 'rate', 'internal', 'timeout', 'epoch'].includes(a.reason));

  /** one nonce per call, fetched just before signing, never cached; refused auth -> ONE fresh nonce, retried ONCE. */
  async function authed(op: 'poll' | 'withdraw', row: RowRecord): Promise<Answer> {
    const auth = await deps.secrets.rowAuth(row.rowId);
    if (!auth) return { kind: 'unreadable' };
    const H_e = BigInt(row.H_e), N = BigInt(row.N);
    for (let attempt = 0; attempt < 2; attempt++) {
      const n = await post('nonce', JSON.stringify({ op, H_e: row.H_e, N: row.N }));
      if (n.kind !== 'nonce') return n;
      const nonce = Uint8Array.from(Buffer.from(n.nonce, 'hex'));
      const sig = await deps.prover.signAuth(op, H_e, N, nonce, auth.sign);
      const body = JSON.stringify({
        H_e: row.H_e, N: row.N,
        pk: Buffer.from(auth.pk).toString('hex'), sig: Buffer.from(sig).toString('hex'), nonce: n.nonce,
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

  /** deposit for one epoch if no row covers it and it isn't spent. Returns the wire answer or null if skipped/failed-to-start. */
  async function depositEpoch(rec: PairRecord, epoch: bigint): Promise<Answer | 'skipped'> {
    const e = String(epoch);
    if (rec.spentEpochs.includes(e)) return 'skipped';
    if (rec.rows.some((r) => r.epoch === e && (r.state === 'standing' || r.state === 'matched'))) return 'skipped';
    const sec = await deps.secrets.depositSecrets(rec.pairId);
    if (!sec) { rec.pendingDeposit = true; return 'skipped'; }
    const row = await deps.secrets.newRow(rec.pairId, epoch);
    let built: { body: string; signals: Signals };
    try {
      built = await mutexed(() =>
        deps.prover.buildDeposit({ x: sec.x, counterpartY: sec.counterpartY, epoch, oneTimePk: row.oneTimePk }));
    } catch {
      await deps.secrets.releaseRow(row.rowId);                       // a failed proof frees the unused one-time key
      rec.pendingDeposit = true;
      return 'skipped';
    }
    if (built.body.length > MAX_DEPOSIT_BYTES || new TextEncoder().encode(built.body).length > MAX_DEPOSIT_BYTES) {
      await deps.secrets.releaseRow(row.rowId);
      return { kind: 'refused', reason: 'wire' };                     // locally indistinguishable: never send it
    }
    if (await deps.latch.isLatched(rec.pairId)) {                     // v2 L2a: a tap mid-proof ends with nothing sent
      await deps.secrets.releaseRow(row.rowId);
      return 'skipped';
    }
    const a = await post('deposit', built.body);
    if (a.kind === 'accepted' || a.kind === 'already') {
      rec.rows.push({ rowId: row.rowId, epoch: e, H_e: String(built.signals.H_e), N: String(built.signals.N), state: 'standing' });
      rec.pendingDeposit = false;
    } else if (a.kind === 'withdrawn') {
      if (!rec.spentEpochs.includes(e)) rec.spentEpochs.push(e);      // (slot,N) spent for the epoch: no retry
      rec.pendingDeposit = false;
      await deps.secrets.releaseRow(row.rowId);
    } else if (a.kind === 'refused' && (NO_RETRY.has(a.reason) || a.reason.startsWith('point:'))) {
      rec.pendingDeposit = false;                                     // stop, fixed error: never retry the same body
      await deps.secrets.releaseRow(row.rowId);
    } else if (transient(a)) {
      rec.pendingDeposit = true;                                      // owed: renewal retries (re-proves, fresh K)
      await deps.secrets.releaseRow(row.rowId);
    }
    return a;
  }

  async function withdrawRow(rec: PairRecord, row: RowRecord): Promise<'done' | 'queued'> {
    const a = await authed('withdraw', row);
    await deps.latch.isLatched(rec.pairId);                           // L2b: the latch is re-read before the answer is applied
    if (a.kind === 'withdrawn') {
      row.state = 'withdrawn';
      await deps.secrets.releaseRow(row.rowId);                       // confirmed: the seed may go
      return 'done';
    }
    if (a.kind === 'match') {
      row.state = 'matched';                                          // inert, NOT an error; the match counts (v2 s3)
      rec.observedMatch = true;
      await deps.secrets.releaseRow(row.rowId);                       // confirmed: the seed may go
      return 'done';
    }
    return 'queued';                                                  // refused-after-retry / busy / unreadable
  }

  const queueWithdraw = (rec: PairRecord, rowId: string, attempts: number) => {
    const due = now() + backoff(attempts);
    const ex = rec.pendingWithdraws.find((w) => w.rowId === rowId);
    if (ex) { ex.attempts = attempts; ex.nextAt = due; } else rec.pendingWithdraws.push({ rowId, attempts, nextAt: due });
  };

  return {
    /** v2 s1: the first deposit happens AT THE TAP. Clears the LOCAL latch only (L5); a remote latch still blocks. */
    async trustAtTap(pairId) {
      const mine = ++callSeq;
      lastCall.set(pairId, mine);                                       // synchronous, before the first await
      if (!(await deps.confirmed.isConfirmed(pairId))) return { kind: 'unconfirmed' };   // L7: fail closed
      if (lastCall.get(pairId) !== mine) return { kind: 'latched' };    // a newer tap owns this pair now — step aside
      await deps.latch.clearLatched(pairId, 'local');
      if (await deps.latch.isLatched(pairId)) return { kind: 'latched' };                 // remote latch stands
      const rec = await getRec(pairId);
      let saw: Answer | 'skipped' = 'skipped';
      for (const epoch of depositableEpochs(now())) {
        const a = await depositEpoch(rec, epoch);
        if (epoch === BigInt(epochAt(now()))) saw = a;
      }
      await deps.store.put(rec);
      if (saw === 'skipped') return { kind: 'deposited' };
      if (saw.kind === 'accepted' || saw.kind === 'already') return { kind: 'deposited' };
      if (saw.kind === 'withdrawn') return { kind: 'spent' };
      if (saw.kind === 'busy') return { kind: 'busy' };
      if (saw.kind === 'refused' && (NO_RETRY.has(saw.reason) || saw.reason.startsWith('point:'))) return { kind: 'failed' };
      return { kind: 'pending' };                                     // transient refusal / unreadable: owed, retry later
    },

    /** v2 s2: latch FIRST and durably, then network. Returns observedMatch for the note layer (v2 s3). */
    async removeAtTap(pairId) {
      lastCall.set(pairId, ++callSeq);                                  // synchronous, before the first await
      await deps.latch.setLatched(pairId, 'local');                     // L1: first and durably, before any network
      const rec = await getRec(pairId);
      const live = visibleEpochs(now());
      for (const row of rec.rows) {
        if (row.state === 'withdrawn' || row.state === 'spent' || !live.has(row.epoch)) continue;
        if ((await withdrawRow(rec, row)) === 'queued') queueWithdraw(rec, row.rowId, 0);   // L6: durable, retried, seed kept
      }
      await deps.store.put(rec);
      return { observedMatch: rec.observedMatch };
    },

    /** v2 L4: the ONE consumer-facing match view — latch applied, closed epochs faded. */
    async matchState(pairId) {
      if (!(await deps.confirmed.isConfirmed(pairId))) return 'none';
      if (await deps.latch.isLatched(pairId)) return 'none';
      const rec = await deps.store.get(pairId);
      if (!rec) return 'none';
      const live = visibleEpochs(now());
      return rec.rows.some((r) => r.state === 'matched' && live.has(r.epoch)) ? 'match' : 'none';
    },

    /** the scheduled action (v1 s3.4 + v2 L3): owed deposits, then poll, then the withdraw queue. */
    async renew(pairId) {
      if (!(await deps.confirmed.isConfirmed(pairId))) return;
      if (await deps.latch.isLatched(pairId)) return;
      const rec = await getRec(pairId);
      if (rec.pendingDeposit) {
        for (const epoch of depositableEpochs(now())) {
          if (!rec.pendingDeposit) break;
          await depositEpoch(rec, epoch);
        }
        await deps.store.put(rec);
      }
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
        if ((row.state !== 'standing' && row.state !== 'matched') || !live.has(row.epoch)) continue;
        if (await deps.latch.isLatched(pairId)) continue;               // L3: latched pairs are skipped
        const a = await authed('poll', row);
        if (await deps.latch.isLatched(pairId)) continue;               // L2b: a tap mid-flight must not flip it back
        if (a.kind === 'match') { row.state = 'matched'; rec.observedMatch = true; dirty = true; }
      }
      if (dirty) await deps.store.put(rec);
    },

    /** the jittered re-deposit time inside the current epoch (v1 s3.4, renewal only). */
    async nextRenewalAt() {
      const start = epochAt(now()) * EPOCH_SECONDS * 1000;
      return deps.prover.scheduleRedeposit({ epochStartMs: start, epochSeconds: EPOCH_SECONDS, graceSeconds: GRACE_SECONDS });
    },

    /** L6: retry durable pending withdraws; confirmed (withdrawn|match) or epoch-closed -> released. */
    async drainPendingWithdraws() {
      const live = visibleEpochs(now());
      for (const rec of await deps.store.pairs()) {
        let dirty = false;
        for (const w of [...rec.pendingWithdraws]) {
          dirty = true;
          const row = rec.rows.find((r) => r.rowId === w.rowId);
          if (!row || !live.has(row.epoch)) {                          // epoch closed: drop + release (L6)
            rec.pendingWithdraws = rec.pendingWithdraws.filter((x) => x.rowId !== w.rowId);
            if (row) await deps.secrets.releaseRow(row.rowId);
            dirty = true;
            continue;
          }
          if (w.nextAt > now()) continue;
          const before = rec.observedMatch;
          const out = await withdrawRow(rec, row);
          dirty = dirty || out === 'done' || rec.observedMatch !== before;
          if (out === 'queued') queueWithdraw(rec, w.rowId, w.attempts + 1);
          else rec.pendingWithdraws = rec.pendingWithdraws.filter((x) => x.rowId !== w.rowId);
        }
        if (dirty) await deps.store.put(rec);
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
