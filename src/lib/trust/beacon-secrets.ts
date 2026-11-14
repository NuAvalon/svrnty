// src/lib/trust/beacon-secrets.ts
// #822 P1 (DARK; nothing imports it from a live path): the sealed-store facet the beacon client asks for secrets through (BeaconSecretsPort), and the ONE
// primitive that releases a pair's one-time seeds. Everything it touches is injected (the seed store, the beacon secret x, the counterpart's key, the clock,
// the randomness), so it is pure logic and tests run it against fakes; the binding to the real sealed store is the wiring slice that follows.
//
// What it keeps (Flint's rulings, #8744 and gate 15 v0.1):
//  - A one-time seed never leaves the sealed map. newRow hands out only the PUBLIC key; rowAuth hands out a signer, never the seed.
//  - newRow is IDEMPOTENT for a live row: the same (pair, epoch) answers the same one-time key, so a retry after a lost answer re-deposits the SAME K.
//  - releasePair is the ONE release primitive: Block, Untrust, Remove and a key rotation all call it. It releases every live row for the pair across EVERY live
//    epoch (the current one, the previous one inside the grace window, the next one inside the last window), by RECOMPUTING each epoch's (slot, nullifier)
//    (a seed entry carries no pair id, on purpose: no social graph in the map), plus any row ids the caller already knows. A seed that was minted but never
//    recorded (a crash between the two) is therefore released too. It works for a blocked pair: it never consults the latch.
//  - An unreadable seed map is a STUCK state: every operation that needs a seed fails closed, the app is told ONCE (onStuck), and the way out is an explicit
//    repair that says what it destroys. Never an automatic reset, never a silent retry loop. A LOCKED session is not stuck: unlocking is the whole remedy.
//  - A blocked pair gets nothing: secrets and new rows are refused for a pair whose latch is 'removed', so even a mint that runs early (before a restore has
//    rebuilt the latches) cannot lead to a request for it. 'frozen' keeps its renewals, as the latch's own contract says.
// Honest bound, for the copy: this protects the seeds at rest and against lost updates between tabs. It does not protect against code running in the unlocked
// session: anyone who can run code there can call the same functions.
//
// Imports nothing that touches storage (no client-store) and never logs.

import { ed25519 } from '@noble/curves/ed25519.js';
import { randomBytes as nobleRandom } from '@noble/hashes/utils.js';
import { addSeed, removeSeed, seedKey, sweepExpired, type BeaconSeeds } from '../identity/beacon-seeds';
import { expiryForEpoch } from '../identity/beacon-seed-expiry';
import { visibleEpochsAt, type BeaconSecretsPort } from '../crypto/beacon-client';
import type { Point } from '../crypto/beacon-prover';

/** The sealed seed map, as this module needs it. read/update are the STRICT ones (absent = {}, unreadable/locked throw); reset is the deliberate repair. */
export interface SeedStore {
  read(): Promise<BeaconSeeds>;
  update(mutate: (cur: BeaconSeeds) => BeaconSeeds): Promise<BeaconSeeds>;
  /** replaces whatever is stored with an empty map: destroys every held seed. Only repair() calls it. */
  reset(): Promise<void>;
}

export interface BeaconSecretsDeps {
  seeds: SeedStore;
  /** the identity's beacon secret scalar x (identity state); undefined = no beacon key yet */
  secretX(): Promise<bigint | undefined>;
  /** the VERIFIED beacon public key of this pair's counterpart; undefined = not known, so nothing can be derived for the pair */
  counterpartY(pairId: string): Promise<Point | undefined>;
  /** the pair's latch kind, if the caller has one. 'removed' = no secrets, no new rows. */
  latchKind?(pairId: string): Promise<'removed' | 'frozen' | null>;
  /** (H_e, N) for this pair at an epoch, canonical decimals. Default: the prover's pure derivation (they do not depend on the one-time key). */
  slotOf?(x: bigint, counterpartY: Point, epoch: bigint): Promise<{ H_e: string; N: string }>;
  now?(): number;
  random?(n: number): Uint8Array;
  /** called ONCE when the seed map is found unreadable (the stuck state), so the app can show it; fires again only after a repair and a new failure */
  onStuck?(): void;
}

/** What a caller sees when the seed map is unreadable. It is the stuck state, not a one-off: every seed operation throws it until repair(). */
export class SeedsStuckError extends Error {
  readonly code = 'seeds-stuck' as const;
  constructor() { super('The one-time seeds held on this device cannot be opened. Trust signals cannot be renewed until they are reset.'); this.name = 'SeedsStuckError'; }
}
/** newRow / depositSecrets could not run for a reason that is not a fault: no key yet, no verified counterpart key, a removed pair, an epoch not live. */
export class SecretsUnavailableError extends Error {
  readonly code: 'no-secrets' | 'removed' | 'epoch-not-live';
  constructor(code: SecretsUnavailableError['code']) { super(`beacon secrets unavailable: ${code}`); this.name = 'SecretsUnavailableError'; this.code = code; }
}

/** repair() runs only with exactly this value: the caller has to type out what it is agreeing to. */
export const REPAIR_CONFIRMATION = 'destroy every held one-time seed';

export interface ReleaseResult {
  /** how many seed entries were actually removed from the map */
  released: number;
  /** the live epochs that were walked (canonical decimals) */
  epochs: string[];
  /** false when the pair's secrets are unknown, so only the caller's own row ids could be released */
  recomputed: boolean;
}

export interface BeaconSecretsAdapter extends BeaconSecretsPort {
  /** THE release primitive: every live row for this pair across every live epoch (+ any row ids the caller already knows). Does not consult the latch. */
  releasePair(pairId: string, known?: { rowIds?: readonly string[] }): Promise<ReleaseResult>;
  status(): 'ok' | 'stuck';
  /** The explicit repair for the stuck state. Destroys every held one-time seed; refuses without REPAIR_CONFIRMATION. */
  repair(confirmation: string): Promise<void>;
}

const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...u));
const fromB64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const codeOf = (e: unknown): string | undefined => (e && typeof e === 'object' ? (e as { code?: string }).code : undefined);

async function defaultSlotOf(x: bigint, counterpartY: Point, epoch: bigint): Promise<{ H_e: string; N: string }> {
  const { deriveSignals } = await import('../crypto/beacon-prover'); // lazy: the curve code is heavy and this module may be imported before it is needed
  const s = await deriveSignals({ x, counterpartY, epoch, oneTimePk: new Uint8Array(32) }); // H_e and N come from (x, Y, epoch) only; the key only feeds K
  return { H_e: s.H_e.toString(), N: s.N.toString() };
}

export function createBeaconSecrets(deps: BeaconSecretsDeps): BeaconSecretsAdapter {
  const now = deps.now ?? (() => Date.now());
  const random = deps.random ?? ((n: number) => nobleRandom(n));
  const slotOf = deps.slotOf ?? defaultSlotOf;
  let stuck = false;

  /** Runs a seed-store operation. An unreadable map flips to the stuck state (and tells the app once) and throws SeedsStuckError; a locked session is rethrown as it is. */
  async function guarded<T>(op: () => Promise<T>): Promise<T> {
    try {
      const out = await op();
      stuck = false;
      return out;
    } catch (e) {
      if (codeOf(e) === 'unreadable') {
        if (!stuck) { stuck = true; try { deps.onStuck?.(); } catch { /* the app's hook must not change what the caller sees */ } }
        throw new SeedsStuckError();
      }
      throw e;
    }
  }

  async function secretsFor(pairId: string): Promise<{ x: bigint; y: Point } | undefined> {
    const x = await deps.secretX();
    const y = await deps.counterpartY(pairId);
    return x === undefined || y === undefined ? undefined : { x, y };
  }
  const removed = async (pairId: string) => (deps.latchKind ? (await deps.latchKind(pairId)) === 'removed' : false);

  return {
    async depositSecrets(pairId) {
      if (await removed(pairId)) return undefined; // a removed pair is handed nothing, whoever asks and whenever
      const s = await secretsFor(pairId);
      return s ? { x: s.x, counterpartY: s.y } : undefined;
    },

    async newRow(pairId, epoch) {
      if (await removed(pairId)) throw new SecretsUnavailableError('removed');
      if (!visibleEpochsAt(now()).has(epoch.toString())) throw new SecretsUnavailableError('epoch-not-live');
      const s = await secretsFor(pairId);
      if (!s) throw new SecretsUnavailableError('no-secrets');
      const { H_e, N } = await slotOf(s.x, s.y, epoch);
      const rowId = seedKey(H_e, N);
      let pk: Uint8Array = new Uint8Array(0);
      await guarded(() => deps.seeds.update((cur) => {
        const { kept } = sweepExpired(cur, now());
        const have = kept[rowId];
        if (have) { pk = ed25519.getPublicKey(fromB64(have.seed)); return kept; } // idempotent: the SAME one-time key for a live row
        const seed = random(32);
        pk = ed25519.getPublicKey(seed);
        return addSeed(kept, { epoch: epoch.toString(), H_e, N, seed: b64(seed), expiresAtMs: expiryForEpoch(epoch) });
      }));
      return { rowId, oneTimePk: pk };
    },

    async rowAuth(rowId) {
      const map = await guarded(() => deps.seeds.read());
      const e = map[rowId];
      if (!e || e.expiresAtMs < now()) return undefined; // an expired seed is useless and is not handed out
      const seed = fromB64(e.seed);
      return { pk: ed25519.getPublicKey(seed), sign: async (msg: Uint8Array) => ed25519.sign(msg, seed) };
    },

    async releaseRow(rowId) {
      const [H_e, N, ...rest] = rowId.split(':');
      if (rest.length > 0) throw new Error('releaseRow: not a row id');
      const key = seedKey(H_e, N); // throws on anything that is not H_e:N in canonical decimals
      void key;
      await guarded(() => deps.seeds.update((cur) => removeSeed(cur, H_e, N)));
    },

    async releasePair(pairId, known = {}) {
      const s = await secretsFor(pairId); // NOT latch-gated: releasing a blocked pair's rows is the whole point of Block
      const epochs = [...visibleEpochsAt(now())].sort((a, b) => Number(a) - Number(b));
      const keys = new Set<string>();
      if (s) for (const e of epochs) { const { H_e, N } = await slotOf(s.x, s.y, BigInt(e)); keys.add(seedKey(H_e, N)); }
      for (const id of known.rowIds ?? []) { const [H_e, N, ...rest] = id.split(':'); if (rest.length === 0) keys.add(seedKey(H_e, N)); }
      let released = 0;
      await guarded(() => deps.seeds.update((cur) => {
        released = 0;
        let next = cur;
        for (const k of keys) if (k in next) { const [H_e, N] = k.split(':'); next = removeSeed(next, H_e, N); released++; }
        return next;
      }));
      return { released, epochs, recomputed: s !== undefined };
    },

    status: () => (stuck ? 'stuck' : 'ok'),

    async repair(confirmation) {
      if (confirmation !== REPAIR_CONFIRMATION) throw new Error('repair refused: it destroys every held one-time seed and needs the explicit confirmation');
      await deps.seeds.reset();
      stuck = false;
    },
  };
}
