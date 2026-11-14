// src/lib/trust/beacon-ports.ts — #822 (a) S1a: the persistence ports the beacon client needs (the pair-record store with compare-and-swap, and the latch).
/**
 * DARK: only client-store.ts imports this module (createBeaconPorts, which nothing calls yet). It adapts two ports of createBeaconClient (BeaconStorePort, LatchPort) over two INJECTED things, so the logic is
 * unit-tested without IndexedDB and the real implementations (a settings-row KV over the app's IndexedDB, a sealer over the session key) are glue:
 *  - BeaconKV: get / swap / keys over opaque strings. `swap` is the one atomic write (compare the stored string with what was read, then replace or delete).
 *  - Sealer: encrypts a value under an AAD, opens it again, and THROWS on any doubt (tag, shape, wrong AAD).
 *
 * Rules (the client's own contract, beacon-client.ts):
 *  - A pair record says WHO I tapped to trust, so it is sealed at rest like the lens grant book, with an AAD that binds owner AND pairId: a blob
 *    moved onto another pair's key, or another owner's, does not open.
 *  - Every write is a compare-and-swap on the record's version (absent = 0; next.version must be expected + 1). `put` is NOT supported: there is no
 *    plain-overwrite path, and the client never calls it.
 *  - FAIL-CLOSED reads. An unreadable record (open fails, wrong shape, wrong pairId) makes get / cas / pairs THROW: it is never read as "absent",
 *    because the caller would then write a fresh record over it. The latch is the opposite direction: ANY doubt reads as 'removed', the most
 *    restrictive answer, so a broken latch can only stop requests, never allow one.
 *  - 'frozen' has no writer in this port (LatchPort.setLatched means Remove/Block); it is readable so a future freeze feature can use the same rows.
 */
import type { BeaconStorePort, LatchPort, PairRecord } from '../crypto/beacon-client';

export interface BeaconKV {
  /** undefined = absent. A read FAILURE throws; it is never reported as absent. */
  get(key: string): Promise<string | undefined>;
  /** Atomically: if the stored value still equals `expected` (undefined = the key must be absent), replace it with `next` (undefined = delete). Returns whether it wrote. */
  swap(key: string, expected: string | undefined, next: string | undefined): Promise<boolean>;
  /** Keys that start with `prefix`. */
  keys(prefix: string): Promise<string[]>;
}

export interface Sealer {
  seal(aad: string, value: unknown): Promise<string>;
  /** Throws on a bad tag, a wrong AAD or a malformed blob. Never returns a partial value. */
  open(aad: string, blob: string): Promise<unknown>;
}

const ID = /^[A-Za-z0-9._-]{1,128}$/; // no ':' so a key prefix can never be confused with another owner's
const need = (what: string, v: string): string => {
  if (typeof v !== 'string' || !ID.test(v)) throw new Error(`beacon ports: bad ${what}`);
  return v;
};

const PAIR_PREFIX = 'beacon_pair:';
const LATCH_PREFIX = 'beacon_latch:';
const MAX_SWAP_ATTEMPTS = 8;

const strs = (v: unknown): boolean => Array.isArray(v) && v.every((x) => typeof x === 'string');

/** A deliberately light shape check: enough that a record which is not ours never reaches the client, without freezing the record's inner format. */
export function isPairRecord(v: unknown, pairId?: string): v is PairRecord {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) return false;
  const r = v as Record<string, unknown>;
  if (typeof r.pairId !== 'string' || (pairId !== undefined && r.pairId !== pairId)) return false;
  if (typeof r.observedMatch !== 'boolean') return false;
  if (!strs(r.spentEpochs) || !strs(r.refusedEpochs)) return false;
  if (!Array.isArray(r.rows) || !Array.isArray(r.pendingWithdraws)) return false;
  if (r.version !== undefined && !(Number.isSafeInteger(r.version) && (r.version as number) >= 0)) return false;
  if (r.tap !== undefined) {
    const t = r.tap as Record<string, unknown> | null;
    if (t === null || typeof t !== 'object' || !Number.isSafeInteger(t.gen) || (t.gen as number) < 0 || typeof t.trust !== 'boolean') return false;
  }
  return true;
}

/** The pair-record store. `owner` scopes every key; two owners on one device never see each other. */
export function createBeaconStore(kv: BeaconKV, sealer: Sealer, owner: string): BeaconStorePort {
  need('owner', owner);
  const prefix = `${PAIR_PREFIX}${owner}:`;
  const keyOf = (pairId: string) => prefix + need('pairId', pairId);
  const aadOf = (pairId: string) => `beacon-pair:${owner}:${pairId}`;

  /** The stored raw string and its opened record, or both undefined when absent. THROWS when something is there but cannot be read. */
  async function read(pairId: string): Promise<{ raw?: string; rec?: PairRecord }> {
    const raw = await kv.get(keyOf(pairId));
    if (raw === undefined) return {};
    let opened: unknown;
    try { opened = await sealer.open(aadOf(pairId), raw); } catch { throw new Error('beacon store: a stored record cannot be read'); }
    if (!isPairRecord(opened, pairId)) throw new Error('beacon store: a stored record cannot be read');
    return { raw, rec: opened };
  }

  return {
    async get(pairId) {
      return (await read(pairId)).rec;
    },
    async put() {
      throw new Error('beacon store: plain put is not supported; every write is a compare-and-swap');
    },
    async cas(pairId, expectedVersion, next) {
      keyOf(pairId);
      if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 0) throw new Error('beacon store: bad expected version');
      if (!isPairRecord(next, pairId)) throw new Error('beacon store: the record to write is not a record for this pair');
      if (next.version !== expectedVersion + 1) throw new Error('beacon store: next.version must be expected + 1');
      const { raw, rec } = await read(pairId);
      if ((rec?.version ?? 0) !== expectedVersion) return false;
      const sealed = await sealer.seal(aadOf(pairId), next);
      return kv.swap(keyOf(pairId), raw, sealed);
    },
    async pairs() {
      const keys = (await kv.keys(prefix)).filter((k) => k.startsWith(prefix)).sort();
      const out: PairRecord[] = [];
      for (const k of keys) {
        const { rec } = await read(k.slice(prefix.length));
        if (rec) out.push(rec);
      }
      return out;
    },
  };
}

type Kind = 'removed' | 'frozen';
type Source = 'local' | 'remote';

/** The latch: one sealed row per (owner, source, pair). ANY doubt reads as 'removed'. */
export function createBeaconLatch(kv: BeaconKV, sealer: Sealer, owner: string): LatchPort {
  need('owner', owner);
  const keyOf = (source: Source, pairId: string) => `${LATCH_PREFIX}${owner}:${source}:${need('pairId', pairId)}`;
  const aadOf = (source: Source, pairId: string) => `beacon-latch:${owner}:${source}:${pairId}`;
  const row = (kind: Kind) => ({ v: 1, kind });

  /** null = no latch. 'removed' also for anything unreadable, unknown or failing: the most restrictive answer. */
  async function kindFor(pairId: string, source: Source): Promise<Kind | null> {
    try {
      const raw = await kv.get(keyOf(source, pairId));
      if (raw === undefined) return null;
      const v = (await sealer.open(aadOf(source, pairId), raw)) as { v?: unknown; kind?: unknown } | null;
      if (v && typeof v === 'object' && v.v === 1 && (v.kind === 'removed' || v.kind === 'frozen')) return v.kind;
      return 'removed';
    } catch {
      return 'removed';
    }
  }

  const kindOf: LatchPort['kindOf'] = async (pairId, source) => {
    if (source === 'local' || source === 'remote') return kindFor(pairId, source);
    const [l, r] = [await kindFor(pairId, 'local'), await kindFor(pairId, 'remote')];
    return l === 'removed' || r === 'removed' ? 'removed' : l === 'frozen' || r === 'frozen' ? 'frozen' : null;
  };

  return {
    kindOf,
    async isLatched(pairId) {
      return (await kindOf(pairId)) !== null;
    },
    async setLatched(pairId, source) {
      const key = keyOf(source, pairId);
      for (let i = 0; i < MAX_SWAP_ATTEMPTS; i++) {
        const cur = await kv.get(key);
        if (cur !== undefined && (await kindFor(pairId, source)) === 'removed') return; // already removed: idempotent, and 'frozen' is upgraded below
        if (await kv.swap(key, cur, await sealer.seal(aadOf(source, pairId), row('removed')))) return;
      }
      throw new Error('beacon latch: could not write the latch');
    },
    async clearLatched(pairId, source) {
      const key = keyOf(source, pairId);
      for (let i = 0; i < MAX_SWAP_ATTEMPTS; i++) {
        const cur = await kv.get(key);
        if (cur === undefined) return;
        if (await kv.swap(key, cur, undefined)) return;
      }
      throw new Error('beacon latch: could not clear the latch');
    },
  };
}
