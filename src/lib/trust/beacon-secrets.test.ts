// The beacon secrets adapter, against fakes: what it hands out, what it keeps, how it releases, how it fails.
// Run: node --import tsx --test src/lib/trust/beacon-secrets.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { isBeaconSeeds, seedKey, type BeaconSeeds } from '../identity/beacon-seeds';
import { createBeaconSecrets, SeedsStuckError, SecretsUnavailableError, REPAIR_CONFIRMATION, type SeedStore, type BeaconSecretsDeps } from './beacon-secrets';
import type { Point } from '../crypto/beacon-prover';

// ---------- fixtures ----------
const EPOCH_MS = 604_800_000, GRACE_MS = 600_000;
const E = 3000;                                   // a "current" epoch
const startOf = (e: number) => e * EPOCH_MS;
const MID = startOf(E) + 3 * 86_400_000;           // mid-epoch: only E is live
const IN_GRACE = startOf(E) + 100_000;             // first 600 s of E: E and E-1 are live
const NEAR_END = startOf(E) + EPOCH_MS - 100_000;  // last 600 s of E: E and E+1 are live
const X = BigInt(123456789);
const YP: Point = [BigInt(11), BigInt(22)], YQ: Point = [BigInt(33), BigInt(44)];
const PAIR_P = 'pair-p', PAIR_Q = 'pair-q';
/** A deterministic stand-in for the prover's (slot, nullifier): distinct per pair and per epoch, canonical decimals, independent of the one-time key. */
const fakeSlot = async (_x: bigint, y: Point, epoch: bigint) => ({ H_e: String(10_000 + Number(y[0]) * 1000 + Number(epoch)), N: String(20_000 + Number(y[0]) * 1000 + Number(epoch)) });
const rowOf = (y: Point, e: number) => seedKey(String(10_000 + Number(y[0]) * 1000 + e), String(20_000 + Number(y[0]) * 1000 + e));

/** An in-memory seed store with the real store's contract: strict read, atomic update (the mutate result must be a valid map), explicit reset. */
function memStore(initial: BeaconSeeds = {}) {
  const st = { map: initial, broken: null as null | 'unreadable' | 'locked', updates: 0, resets: 0 };
  const fail = () => { if (st.broken) throw Object.assign(new Error(`store ${st.broken}`), { code: st.broken }); };
  const store: SeedStore = {
    async read() { fail(); return { ...st.map }; },
    async update(mutate) { fail(); const next = mutate({ ...st.map }); assert.ok(isBeaconSeeds(next), 'the adapter only ever writes a valid map'); st.map = next; st.updates++; return next; },
    async reset() { st.map = {}; st.broken = null; st.resets++; },
  };
  return { st, store };
}
function setup(opts: Partial<Omit<BeaconSecretsDeps, 'now'>> & { now?: number; map?: BeaconSeeds } = {}) {
  const { now: startAt, map: initialMap, ...over } = opts;
  const { st, store } = memStore(initialMap);
  let clock = startAt ?? MID;
  const stuckCalls = { n: 0 };
  let counter = 0;
  const deps: BeaconSecretsDeps = {
    seeds: store,
    secretX: async () => X,
    counterpartY: async (p) => (p === PAIR_P ? YP : p === PAIR_Q ? YQ : undefined),
    slotOf: fakeSlot,
    now: () => clock,
    random: (n) => Uint8Array.from({ length: n }, (_, i) => (++counter * 31 + i * 7) & 0xff), // distinct per call, deterministic
    onStuck: () => { stuckCalls.n++; },
    ...over,
  };
  return { a: createBeaconSecrets(deps), st, stuckCalls, setNow: (ms: number) => { clock = ms; } };
}
const b64d = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

// ---------- newRow ----------
test('S1 newRow mints a row: the id is H_e:N, the one-time key is the public key of the SEALED seed (checked with an independent ed25519), the expiry is epoch end + grace, and only the public key is returned', async () => {
  const { a, st } = setup();
  const r = await a.newRow(PAIR_P, BigInt(E));
  assert.equal(r.rowId, rowOf(YP, E));
  const entry = st.map[r.rowId];
  assert.ok(entry, 'the seed is in the sealed map');
  const seed = b64d(entry.seed);
  assert.equal(seed.length, 32);
  assert.deepEqual(Array.from(r.oneTimePk), Array.from(ed25519.getPublicKey(seed)), 'pk is the public key of the stored seed');
  assert.equal(entry.expiresAtMs, (E + 1) * EPOCH_MS + GRACE_MS, 'epoch end + one grace window, computed here by hand');
  assert.equal(entry.epoch, String(E));
  assert.deepEqual(Object.keys(r).sort(), ['oneTimePk', 'rowId'], 'nothing secret comes back');
  const r2 = await a.newRow(PAIR_Q, BigInt(E));
  assert.notEqual(st.map[r.rowId].seed, st.map[r2.rowId].seed, 'two rows never share a seed');
});

test('S2 newRow is IDEMPOTENT for a live row (a retry after a lost answer re-deposits the SAME K), and different pairs or epochs are different rows', async () => {
  const { a, st } = setup({ now: IN_GRACE });
  const first = await a.newRow(PAIR_P, BigInt(E));
  const again = await a.newRow(PAIR_P, BigInt(E));
  assert.equal(again.rowId, first.rowId);
  assert.deepEqual(Array.from(again.oneTimePk), Array.from(first.oneTimePk), 'the same one-time key');
  assert.equal(Object.keys(st.map).length, 1, 'no second entry');
  const prev = await a.newRow(PAIR_P, BigInt(E - 1));
  assert.notEqual(prev.rowId, first.rowId);
  assert.equal(Object.keys(st.map).length, 2);
  await a.newRow(PAIR_Q, BigInt(E));
  assert.equal(Object.keys(st.map).length, 3);
});

test('S3 newRow refuses what it must: an epoch that is not live, a removed pair, and a pair it has no secrets for; each with a typed reason, and nothing is written', async () => {
  const { a, st } = setup();                       // MID: only E is live
  for (const e of [E - 3, E - 1, E + 1, E + 5]) await assert.rejects(a.newRow(PAIR_P, BigInt(e)), (err: unknown) => err instanceof SecretsUnavailableError && err.code === 'epoch-not-live', `epoch ${e}`);
  await assert.rejects(a.newRow('no-such-pair', BigInt(E)), (err: unknown) => err instanceof SecretsUnavailableError && err.code === 'no-secrets');
  const noKey = setup({ secretX: async () => undefined });
  await assert.rejects(noKey.a.newRow(PAIR_P, BigInt(E)), (err: unknown) => err instanceof SecretsUnavailableError && err.code === 'no-secrets');
  const removedPair = setup({ latchKind: async () => 'removed' });
  await assert.rejects(removedPair.a.newRow(PAIR_P, BigInt(E)), (err: unknown) => err instanceof SecretsUnavailableError && err.code === 'removed');
  const frozen = setup({ latchKind: async () => 'frozen' });
  assert.ok((await frozen.a.newRow(PAIR_P, BigInt(E))).rowId, "'frozen' keeps its renewals");
  assert.equal(st.updates, 0, 'a refusal writes nothing');
  assert.equal(removedPair.st.updates, 0);
  // the epoch windows: just before the grace ends E-1 is live; the next epoch is live only near the end
  const edge = setup({ now: startOf(E) + GRACE_MS - 1 });
  assert.ok((await edge.a.newRow(PAIR_P, BigInt(E - 1))).rowId);
  const late = setup({ now: NEAR_END });
  assert.ok((await late.a.newRow(PAIR_P, BigInt(E + 1))).rowId);
});

// ---------- depositSecrets / rowAuth / releaseRow ----------
test('S4 depositSecrets hands out x and the counterpart key, nothing for a removed pair or an unknown one', async () => {
  const { a } = setup();
  assert.deepEqual(await a.depositSecrets(PAIR_P), { x: X, counterpartY: YP });
  assert.equal(await a.depositSecrets('no-such-pair'), undefined);
  assert.equal(await setup({ latchKind: async () => 'removed' }).a.depositSecrets(PAIR_P), undefined, 'a removed pair is handed nothing');
  assert.deepEqual(await setup({ latchKind: async () => 'frozen' }).a.depositSecrets(PAIR_P), { x: X, counterpartY: YP }, "'frozen' keeps its renewals");
  assert.equal(await setup({ secretX: async () => undefined }).a.depositSecrets(PAIR_P), undefined);
});

test('S5 rowAuth signs for exactly the row it was asked about (verified with an independent ed25519), never returns the seed, and hands out nothing for an unknown or expired row', async () => {
  const { a, st, setNow } = setup();
  const r = await a.newRow(PAIR_P, BigInt(E));
  const auth = await a.rowAuth(r.rowId);
  assert.ok(auth);
  assert.deepEqual(Array.from(auth!.pk), Array.from(r.oneTimePk));
  const msg = new TextEncoder().encode('svrnty:588:poll:v1|example');
  const sig = await auth!.sign(msg);
  assert.ok(ed25519.verify(sig, msg, r.oneTimePk), 'a valid signature under the deposit key');
  assert.ok(!ed25519.verify(sig, new TextEncoder().encode('another message'), r.oneTimePk), 'and only for that message');
  assert.ok(!JSON.stringify(Object.keys(auth!)).includes('seed'), 'no seed on the object');
  assert.equal(await a.rowAuth(rowOf(YP, E + 9)), undefined, 'unknown row');
  setNow(st.map[r.rowId].expiresAtMs + 1);
  assert.equal(await a.rowAuth(r.rowId), undefined, 'an expired seed is useless and not handed out');
});

test('S6 releaseRow removes exactly that row, tolerates a missing one, and refuses anything that is not H_e:N', async () => {
  const { a, st } = setup();
  const r1 = await a.newRow(PAIR_P, BigInt(E)), r2 = await a.newRow(PAIR_Q, BigInt(E));
  await a.releaseRow(r1.rowId);
  assert.deepEqual(Object.keys(st.map), [r2.rowId]);
  await a.releaseRow(r1.rowId);                                  // already gone: fine
  assert.deepEqual(Object.keys(st.map), [r2.rowId]);
  for (const bad of ['', 'x', '1:2:3', 'a:b', '01:2', '1:']) await assert.rejects(a.releaseRow(bad), Error, `row id ${JSON.stringify(bad)}`);
  assert.deepEqual(Object.keys(st.map), [r2.rowId], 'a refused id changes nothing');
});

// ---------- the plan a Remove withdraws from (gate 15 O4, v0.2: WITHDRAW-THEN-FORGET): it lists, it never drops ----------
const heldEntry = (y: Point, e: number, fill: number, expiresAtMs = (e + 1) * EPOCH_MS + GRACE_MS) => ({
  epoch: String(e), H_e: String(10_000 + Number(y[0]) * 1000 + e), N: String(20_000 + Number(y[0]) * 1000 + e), seed: btoa(String.fromCharCode(...new Uint8Array(32).fill(fill))), expiresAtMs,
});

test('S7 planPairRows inside the grace window lists BOTH epochs\' rows for that pair (and only that pair), and DROPS NOTHING: the map and the store are exactly as they were', async () => {
  const { a, st, setNow } = setup({ now: startOf(E) - 1 });      // last second of E-1: mint its row, as the client would
  await a.newRow(PAIR_P, BigInt(E - 1));
  await a.newRow(PAIR_Q, BigInt(E - 1));
  setNow(IN_GRACE);                                              // now inside E's grace window: E-1 and E are both live
  await a.newRow(PAIR_P, BigInt(E));
  await a.newRow(PAIR_Q, BigInt(E));
  const before = JSON.stringify(st.map), updatesBefore = st.updates;
  const plan = await a.planPairRows(PAIR_P);
  assert.deepEqual(plan, [
    { rowId: rowOf(YP, E - 1), epoch: String(E - 1), H_e: String(10_000 + 11_000 + E - 1), N: String(20_000 + 11_000 + E - 1) },
    { rowId: rowOf(YP, E), epoch: String(E), H_e: String(10_000 + 11_000 + E), N: String(20_000 + 11_000 + E) },
  ], "both live epochs, P's rows only, in epoch order");
  assert.equal(JSON.stringify(st.map), before, 'the map is untouched');
  assert.equal(st.updates, updatesBefore, 'planning writes nothing');
  assert.ok((await a.rowAuth(rowOf(YP, E - 1))) && (await a.rowAuth(rowOf(YP, E))), 'every planned row can still be SIGNED for: its seed is still there');
});

test('S8 planPairRows near the end of an epoch also lists the NEXT epoch\'s row (the client may deposit it early)', async () => {
  const { a } = setup({ now: NEAR_END });
  await a.newRow(PAIR_P, BigInt(E));
  await a.newRow(PAIR_P, BigInt(E + 1));
  const plan = await a.planPairRows(PAIR_P);
  assert.deepEqual(plan.map((t) => t.epoch), [String(E), String(E + 1)]);
});

test('S9 an ORPHAN seed (held, never recorded by any pair record) is planned like any other row; a seed for a closed epoch, for another pair, or already expired is not', async () => {
  const orphan = heldEntry(YP, E, 5), farOld = heldEntry(YP, E - 5, 6, startOf(E) + 10_000_000_000), other = heldEntry(YQ, E, 7);
  const expiredButLive = heldEntry(YP, E - 1, 8, startOf(E) - 1);   // would be a live epoch's row, but its seed has expired
  const { a, st } = setup({ now: IN_GRACE, map: { [seedKey(orphan.H_e, orphan.N)]: orphan, [seedKey(farOld.H_e, farOld.N)]: farOld, [seedKey(other.H_e, other.N)]: other, [seedKey(expiredButLive.H_e, expiredButLive.N)]: expiredButLive } });
  const plan = await a.planPairRows(PAIR_P);
  assert.deepEqual(plan.map((t) => t.rowId), [seedKey(orphan.H_e, orphan.N)], 'only the orphan: it is live, held, and unexpired');
  assert.equal(Object.keys(st.map).length, 4, 'nothing dropped, including the ones not planned');
});

test('S10 planning works for a REMOVED pair (it never consults the latch), and with no secrets it plans nothing (nothing can be recomputed)', async () => {
  const held = heldEntry(YP, E, 5);
  const { a } = setup({ latchKind: async () => 'removed', map: { [seedKey(held.H_e, held.N)]: held } });
  assert.deepEqual((await a.planPairRows(PAIR_P)).map((t) => t.rowId), [seedKey(held.H_e, held.N)], "a blocked pair's row is exactly what a Block must withdraw");
  assert.deepEqual(await setup({ secretX: async () => undefined, map: { [seedKey(held.H_e, held.N)]: held } }).a.planPairRows(PAIR_P), []);
  assert.deepEqual(await a.planPairRows('no-such-pair'), []);
});

test('S10b there is NO pair-wide delete: the adapter has no releasePair, and the only code that removes a seed is releaseRow (one row, by id)', () => {
  const { a } = setup();
  assert.ok(!('releasePair' in a), 'no pair-wide delete is exposed');
  const src = readFileSync(new URL('./beacon-secrets.ts', import.meta.url), 'utf8');
  const code = src.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
  assert.equal((code.match(/removeSeed\(/g) ?? []).length, 1, 'exactly one place removes a seed');
  assert.ok(/async releaseRow[\s\S]{0,400}removeSeed\(/.test(code), 'and it is releaseRow');
  assert.ok(!/releasePair/.test(code));
});

// ---------- the stuck state (Flint condition 3) ----------
test('S11 an unreadable map is a STUCK state: every seed operation fails closed with ONE typed error, the app is told ONCE (not per attempt), and nothing is overwritten', async () => {
  const { a, st, stuckCalls } = setup();
  const before = await a.newRow(PAIR_P, BigInt(E));
  st.broken = 'unreadable';
  const snapshot = JSON.stringify(st.map);
  for (let i = 0; i < 5; i++) await assert.rejects(a.newRow(PAIR_Q, BigInt(E)), (e: unknown) => e instanceof SeedsStuckError && (e as SeedsStuckError).code === 'seeds-stuck');
  await assert.rejects(a.rowAuth(before.rowId), SeedsStuckError);
  await assert.rejects(a.releaseRow(before.rowId), SeedsStuckError);
  await assert.rejects(a.planPairRows(PAIR_P), SeedsStuckError);
  assert.equal(stuckCalls.n, 1, 'told once, however many attempts');
  assert.equal(a.status(), 'stuck');
  assert.equal(JSON.stringify(st.map), snapshot, 'nothing was overwritten');
});

test('S12 repair is EXPLICIT: it refuses without the confirmation (and stays stuck), and with it destroys the held seeds, clears the state, and renewals work again; a new failure tells the app again', async () => {
  const { a, st, stuckCalls } = setup();
  await a.newRow(PAIR_P, BigInt(E));
  st.broken = 'unreadable';
  await assert.rejects(a.newRow(PAIR_Q, BigInt(E)), SeedsStuckError);
  for (const bad of ['', 'yes', 'DESTROY EVERY HELD ONE-TIME SEED', undefined as unknown as string]) await assert.rejects(a.repair(bad), /explicit confirmation/);
  assert.equal(st.resets, 0, 'no reset without the confirmation');
  assert.equal(a.status(), 'stuck');
  await a.repair(REPAIR_CONFIRMATION);
  assert.equal(st.resets, 1);
  assert.equal(a.status(), 'ok');
  assert.deepEqual(st.map, {}, 'the held seeds are gone: that is what the repair says it destroys');
  assert.ok((await a.newRow(PAIR_Q, BigInt(E))).rowId, 'renewals work again');
  st.broken = 'unreadable';
  await assert.rejects(a.newRow(PAIR_P, BigInt(E)), SeedsStuckError);
  assert.equal(stuckCalls.n, 2, 'a NEW failure after a repair tells the app again');
});

test('S13 a LOCKED session is not stuck: the error is passed through as it is, the app is not told, and status stays ok', async () => {
  const { a, st, stuckCalls } = setup();
  st.broken = 'locked';
  for (const op of [() => a.newRow(PAIR_P, BigInt(E)), () => a.rowAuth(rowOf(YP, E)), () => a.releaseRow(rowOf(YP, E)), () => a.planPairRows(PAIR_P)]) {
    await assert.rejects(op(), (e: unknown) => (e as { code?: string }).code === 'locked' && !(e instanceof SeedsStuckError));
  }
  assert.equal(stuckCalls.n, 0);
  assert.equal(a.status(), 'ok');
});

// ---------- hygiene ----------
test('S14 [static] the adapter touches no storage module, never logs, and the blind setters are not in it', () => {
  const src = readFileSync(new URL('./beacon-secrets.ts', import.meta.url), 'utf8');
  const code = src.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
  assert.ok(!/client-store/.test(code), 'no import of the store module');
  assert.ok(!/console\./.test(code), 'it never logs');
  assert.ok(!/setBeaconSeeds|getBeaconSeeds|txPut|indexedDB/.test(code), 'no direct storage access');
  assert.ok(/visibleEpochsAt/.test(code), 'the live-epoch rule is the client\'s own function, not a copy');
  assert.ok(!/EPOCH_SECONDS|GRACE_SECONDS/.test(code), 'no second definition of the epoch constants');
});

test('S16 a mint sweeps seeds that have expired (they are useless), and keeps the live ones', async () => {
  const expired = { epoch: String(E - 9), H_e: '5', N: '6', seed: btoa(String.fromCharCode(...new Uint8Array(32).fill(4))), expiresAtMs: startOf(E - 8) };
  const live = { epoch: String(E), H_e: '7', N: '8', seed: btoa(String.fromCharCode(...new Uint8Array(32).fill(3))), expiresAtMs: (E + 1) * EPOCH_MS + GRACE_MS };
  const { a, st } = setup({ map: { '5:6': expired, '7:8': live } });
  const r = await a.newRow(PAIR_P, BigInt(E));
  assert.deepEqual(Object.keys(st.map).sort(), ['7:8', r.rowId].sort(), 'the expired entry is gone, the live one and the new row are there');
});

// ---------- the real derivation ----------
test('S15 with the REAL prover, the slot and nullifier do not depend on the one-time key, and the default derivation gives the same row id as an independent call', async () => {
  const { deriveSignals } = await import('../crypto/beacon-prover');
  const { generateBeaconSecret, beaconPublicKey, checkBeaconPublicKey } = await import('../crypto/beacon-key');
  const x = await generateBeaconSecret(), other = await generateBeaconSecret();
  const chk = await checkBeaconPublicKey(await beaconPublicKey(other), await beaconPublicKey(x));
  assert.ok(chk.ok, 'a valid counterpart key');
  const y = (chk as { ok: true; point: Point }).point;
  const s1 = await deriveSignals({ x, counterpartY: y, epoch: BigInt(E), oneTimePk: new Uint8Array(32).fill(1) });
  const s2 = await deriveSignals({ x, counterpartY: y, epoch: BigInt(E), oneTimePk: new Uint8Array(32).fill(2) });
  assert.equal(s1.H_e, s2.H_e); assert.equal(s1.N, s2.N);
  assert.notEqual(s1.K, s2.K, 'only K depends on the one-time key');
  const { st, store } = memStore();
  const a = createBeaconSecrets({ seeds: store, secretX: async () => x, counterpartY: async () => y, now: () => MID });   // default slotOf
  const r = await a.newRow('real-pair', BigInt(E));
  assert.equal(r.rowId, seedKey(s1.H_e.toString(), s1.N.toString()));
  assert.equal(Object.keys(st.map).length, 1);
  const plan = await a.planPairRows('real-pair');
  assert.deepEqual(plan.map((t) => t.rowId), [r.rowId], 'the real derivation plans exactly the row it minted');
  assert.equal(Object.keys(st.map).length, 1, 'and drops nothing');
  await a.releaseRow(r.rowId);                                   // the confirmed path: the only way a seed leaves
  assert.deepEqual(st.map, {});
});
