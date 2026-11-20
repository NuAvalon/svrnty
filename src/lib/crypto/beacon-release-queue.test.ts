// beacon-release-queue: queue the withdraw of every row of a pair, as plain functions of the pair's ports (no client, no network, no wire switch).
// Run: npx tsx --test src/lib/crypto/beacon-release-queue.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { commitRecord } from './beacon-pair-record';
import { queueUnqueuedLiveRows, queueWithdraws, type ReleaseQueueDeps } from './beacon-release-queue';
import type { BeaconStorePort, PairRecord, RowRecord } from './beacon-client';

const WEEK_MS = 604_800_000;
const E = 3000;
const MID = E * WEEK_MS + 3_600_000;                    // an hour into epoch E: epoch E is open at the relay, epoch E-2 and older are dead
const PAIR = 'pair-1';

const memStore = (): BeaconStorePort & { data: Map<string, PairRecord>; cases: { n: number } } => {
  const data = new Map<string, PairRecord>(); const cases = { n: 0 };
  return {
    data, cases,
    get: async (id) => { const r = data.get(id); return r ? structuredClone(r) : undefined; },
    put: async (r) => { data.set(r.pairId, structuredClone(r)); },
    cas: async (id, v, next) => { cases.n++; if ((data.get(id)?.version ?? 0) !== v) return false; data.set(id, structuredClone(next)); return true; },
    pairs: async () => [...data.values()].map((r) => structuredClone(r)),
  };
};
const fresh = (rows: RowRecord[] = []): PairRecord => ({ pairId: PAIR, observedMatch: false, spentEpochs: [], refusedEpochs: [], rows, pendingWithdraws: [] });
const row = (id: string, epoch: number, state: RowRecord['state'] = 'standing'): RowRecord => ({ rowId: id, epoch: String(epoch), H_e: `h${id}`, N: `n${id}`, state });
const deps = (over: Partial<ReleaseQueueDeps['secrets']> = {}, store = memStore(), now = () => MID) => {
  const released: string[] = [];
  const d: ReleaseQueueDeps = { secrets: { releaseRow: async (id) => { released.push(id); }, ...over }, store, now };
  return { d, released, store };
};

test('RQ1 every live row is queued due NOW, a settled row is left alone, a dead row is dropped, tombstoned and its seed released', async () => {
  const { d, released } = deps();
  const rec = fresh([row('live', E), row('unknown', E, 'unknown'), row('matched', E, 'matched'), row('done', E, 'withdrawn'), row('sp', E, 'spent'), row('unr', E, 'unreachable'), row('dead', E - 2)]);
  await queueWithdraws(rec, d);
  assert.deepEqual(rec.pendingWithdraws.map((w) => w.rowId).sort(), ['live', 'matched', 'unknown'], 'live rows only (an unknown row withdraws too)');
  assert.ok(rec.pendingWithdraws.every((w) => w.attempts === 0 && w.nextAt === MID), 'due now, no backoff on the first attempt');
  assert.deepEqual(released, ['dead'], 'only the dead row\'s seed is released');
  assert.ok(!rec.rows.some((r) => r.rowId === 'dead'), 'and the dead row is dropped');
  assert.deepEqual((rec.deletedRows ?? []).map((t) => t.id), ['dead'], 'with a tombstone so a stale copy cannot bring it back');
});

test('RQ2 ATOMIC: a plan that THROWS leaves the record and the seeds exactly as they were (the plan runs before anything is touched)', async () => {
  const { d, released } = deps({ planPairRows: async () => { throw new Error('the old key cannot be named'); } });
  const rec = fresh([row('live', E), row('dead', E - 2)]);          // a loop-first order would queue 'live' and release 'dead' before the throw
  const before = JSON.stringify(rec);
  await assert.rejects(() => queueWithdraws(rec, d), /old key cannot be named/);
  assert.equal(JSON.stringify(rec), before, 'the record is untouched: nothing queued, nothing dropped');
  assert.deepEqual(released, [], 'and no seed was released');
});

test('RQ3 a planned orphan row joins the record as unknown and is queued by the sweep; a planned row of a dead epoch is ignored; no planner is fine', async () => {
  const store = memStore();
  const { d } = deps({ planPairRows: async () => [{ rowId: 'orph', epoch: String(E), H_e: 'ho', N: 'no' }, { rowId: 'old', epoch: String(E - 3), H_e: 'hx', N: 'nx' }] }, store);
  const rec = fresh([row('live', E)]);
  await queueWithdraws(rec, d);
  assert.deepEqual(rec.rows.map((r) => [r.rowId, r.state]), [['live', 'standing'], ['orph', 'unknown']], 'the dead-epoch plan entry is ignored');
  await commitRecord(store, d.now, rec);
  await queueUnqueuedLiveRows(rec, d, () => true);
  assert.deepEqual(rec.pendingWithdraws.map((w) => w.rowId).sort(), ['live', 'orph'], 'the sweep queues the orphan with the rest');
  const plain = deps();
  const r2 = fresh([row('a', E)]); await queueWithdraws(r2, plain.d);
  assert.equal(r2.pendingWithdraws.length, 1, 'no planner: the record\'s own rows are all there is');
});

test('RQ4 the sweep queues a row a concurrent deposit landed between the plan and the commit, commits again, and stops when a pass adds nothing', async () => {
  const store = memStore(); const { d } = deps({}, store);
  const rec = fresh([row('r1', E)]); store.data.set(PAIR, structuredClone({ ...rec, version: 1 }));
  rec.version = 1;
  await queueWithdraws(rec, d);                                       // r1 queued locally
  const stored = store.data.get(PAIR)!; stored.rows.push(row('r2', E)); stored.version = 2;   // a concurrent deposit lands r2 before our commit
  await commitRecord(store, d.now, rec);                              // the merge pulls r2 in, with no queue entry
  assert.deepEqual(rec.pendingWithdraws.map((w) => w.rowId), ['r1'], 'before the sweep r2 has no queue entry (the drain would never see it)');
  await queueUnqueuedLiveRows(rec, d, () => true);
  assert.deepEqual([...rec.pendingWithdraws.map((w) => w.rowId)].sort(), ['r1', 'r2']);
  assert.deepEqual([...store.data.get(PAIR)!.pendingWithdraws.map((w) => w.rowId)].sort(), ['r1', 'r2'], 'and it is COMMITTED, not only in memory');
});

test('RQ5 the sweep asks the stored record first: when the pair is no longer in the state this caller put it in, it queues nothing and writes nothing', async () => {
  const store = memStore(); const { d } = deps({}, store);
  const rec = fresh([row('r1', E)]); store.data.set(PAIR, structuredClone({ ...rec, version: 1 })); rec.version = 1;
  const casBefore = store.cases.n;
  await queueUnqueuedLiveRows(rec, d, () => false);
  assert.equal(rec.pendingWithdraws.length, 0);
  assert.equal(store.cases.n, casBefore, 'no write was attempted');
});

test('RQ6 the sweep is bounded: a store that keeps changing under it stops after 8 passes', async () => {
  const store = memStore(); const { d } = deps({}, store);
  let n = 0; const get = store.get.bind(store);
  store.get = async (id) => { const r = await get(id); if (r) r.rows.push(row(`late${n++}`, E)); return r; };   // every read shows one more unqueued row
  const rec = fresh([row('r1', E)]); store.data.set(PAIR, structuredClone({ ...rec, version: 1 })); rec.version = 1;
  await queueUnqueuedLiveRows(rec, d, () => true);
  assert.ok(n <= 17, `bounded (read ${n} times)`);
  assert.ok(n >= 8, 'it did try repeatedly');
});

test('RQ7 NO NETWORK, NO SWITCH: the queue module takes no fetch and does not import the client\'s values or the wire switch', () => {
  const src = readFileSync(join(process.cwd(), 'src/lib/crypto/beacon-release-queue.ts'), 'utf8').replace(/\/\/[^\n]*/g, '');
  assert.doesNotMatch(src, /\bfetch\b|isBeaconWireLive|claim-gates|createBeaconClient|XMLHttpRequest/);
  const imports = [...src.matchAll(/^import\s+(type\s+)?[^;]*from\s+'([^']+)'/gm)].map((m) => `${m[1] ? 'type ' : ''}${m[2]}`);
  assert.deepEqual(imports.sort(), ['./beacon-pair-record', './beacon-relay-margin', 'type ./beacon-client'].sort(), 'its only imports: the record helpers, the margin, and TYPES from the client');
});
