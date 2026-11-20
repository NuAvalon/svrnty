// beacon-key-replace: replacing a contact's beacon key, release-FIRST (plan, queue and commit the old key's withdraws; only then write the new key).
// Run: npx tsx --test src/lib/trust/beacon-key-replace.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { replaceHeldBeaconKey, type HeldKey, type KeyReplaceDeps } from './beacon-key-replace';
import type { BeaconStorePort, PairRecord, RowRecord } from '../crypto/beacon-client';

const WEEK_MS = 604_800_000;
const E = 3000;
const MID = E * WEEK_MS + 3_600_000;
const PAIR = 'pair-1';
const OLD: HeldKey = { publicKey: 'old-key', generation: 5 };
const NEW: HeldKey = { publicKey: 'new-key', generation: 6 };

const memStore = (): BeaconStorePort & { data: Map<string, PairRecord>; writes: { n: number } } => {
  const data = new Map<string, PairRecord>(); const writes = { n: 0 };
  return {
    data, writes,
    get: async (id) => { const r = data.get(id); return r ? structuredClone(r) : undefined; },
    put: async (r) => { writes.n++; data.set(r.pairId, structuredClone(r)); },
    cas: async (id, v, next) => { if ((data.get(id)?.version ?? 0) !== v) return false; writes.n++; data.set(id, structuredClone(next)); return true; },
    pairs: async () => [...data.values()].map((r) => structuredClone(r)),
  };
};
const row = (id: string, epoch: number, state: RowRecord['state'] = 'standing'): RowRecord => ({ rowId: id, epoch: String(epoch), H_e: `h${id}`, N: `n${id}`, state });
const seed = (store: ReturnType<typeof memStore>, rows: RowRecord[]) => store.data.set(PAIR, { pairId: PAIR, observedMatch: false, spentEpochs: [], refusedEpochs: [], rows, pendingWithdraws: [], version: 1 });

/** Everything observable: the order of the events, and what the store held at the instant the key was written. */
const rig = (opts: { keyApplies?: boolean | 'throw'; confirmed?: boolean | 'throw'; plan?: 'throw'; gapRows?: RowRecord[]; underOld?: (rowId: string) => boolean; postWriteReadThrows?: boolean | 'bug'; reporterThrows?: boolean } = {}) => {
  const store = memStore(); const log: string[] = []; const released: string[] = []; const reported: Array<{ where: string; err: unknown }> = [];
  let atKeyWrite: { pending: string[]; rows: string[] } | null = null;
  const over = opts;                                                  // the rig's own switches, kept apart from the dependencies they configure
  const deps: KeyReplaceDeps = {
    pairId: PAIR, store, now: () => MID,
    onUnexpected: (where, err) => { reported.push({ where, err }); if (opts.reporterThrows) throw new Error('reporter exploded'); },
    secrets: {
      releaseRow: async (id) => { released.push(id); },
      planPairRows: async () => { log.push('plan'); if (over.plan === 'throw') throw new Error('the old key cannot be named'); return []; },
      ...(over.underOld ? { rowsAreUnderHeldKey: async (_p: string, rows: ReadonlyArray<{ rowId: string }>) => rows.every((r) => over.underOld!(r.rowId)) } : {}),
    },
    confirmed: { isConfirmed: async () => { log.push('confirmed?'); if (over.confirmed === 'throw') throw new Error('locked'); return over.confirmed === true; } },
    writeKey: async (expected, next) => {
      log.push('writeKey');
      const r = store.data.get(PAIR);
      atKeyWrite = { pending: (r?.pendingWithdraws ?? []).map((w) => w.rowId).sort(), rows: (r?.rows ?? []).map((x) => x.rowId).sort() };
      assert.deepEqual(expected, OLD); assert.deepEqual(next, NEW);
      if (over.gapRows) {                                            // rows a deposit landed between the last sweep and the key write
        const g = store.data.get(PAIR)!; g.rows.push(...over.gapRows); g.version = (g.version ?? 0) + 1;
      }
      if (over.postWriteReadThrows) store.get = async () => { throw over.postWriteReadThrows === 'bug' ? new TypeError('injected bug') : new Error('the store cannot be read now'); };
      if (over.keyApplies === 'throw') throw new Error('storage failed');
      return over.keyApplies !== false;
    },
  };
  return { deps, store, log, released, reported, atKeyWrite: () => atKeyWrite };
};

test('KR1 ORDER: confirmed is read first, the plan is made, the queue is COMMITTED, and only then is the key written (the store already holds the queue at that instant)', async () => {
  const r = rig({ confirmed: true });
  seed(r.store, [row('a', E), row('b', E)]);
  const out = await replaceHeldBeaconKey(r.deps, OLD, NEW);
  assert.deepEqual(out, { kind: 'replaced', wasConfirmed: true });
  assert.deepEqual(r.log, ['confirmed?', 'plan', 'writeKey'], 'confirmed before, plan before the key');
  assert.deepEqual(r.atKeyWrite()!.pending, ['a', 'b'], 'when the key was written the queue was already committed in the store');
});

test('KR2 a plan that cannot be made REFUSES: the key is never written, nothing is queued or released, the store is untouched', async () => {
  const r = rig({ plan: 'throw' });
  seed(r.store, [row('live', E), row('dead', E - 2)]);                // a loop-first order would have queued 'live' and released 'dead'
  const before = JSON.stringify(r.store.data.get(PAIR)); const w0 = r.store.writes.n;
  const out = await replaceHeldBeaconKey(r.deps, OLD, NEW);
  assert.deepEqual(out, { kind: 'refused' });
  assert.ok(!r.log.includes('writeKey'), 'the key was never written');
  assert.equal(JSON.stringify(r.store.data.get(PAIR)), before, 'the record is exactly as it was');
  assert.equal(r.store.writes.n, w0, 'no write at all reached the store');
  assert.deepEqual(r.released, [], 'no seed was released');
});

test('KR3 THE IN-BETWEEN STATE: when the key write aborts (the key moved) the queue stays COMMITTED and is never rolled back, and the outcome is refused', async () => {
  const r = rig({ keyApplies: false });
  seed(r.store, [row('a', E)]);
  const out = await replaceHeldBeaconKey(r.deps, OLD, NEW);
  assert.deepEqual(out, { kind: 'refused' });
  assert.deepEqual(r.store.data.get(PAIR)!.pendingWithdraws.map((w) => w.rowId), ['a'], 'the queue is committed and stays: the drain withdraws the rows of the key still held');
  assert.equal(r.log.filter((l) => l === 'writeKey').length, 1, 'one attempt, no retry that could write a stale key later');
});

test('KR4 a key write that THROWS is the same as an abort: refused, queue kept', async () => {
  const r = rig({ keyApplies: 'throw' });
  seed(r.store, [row('a', E)]);
  assert.deepEqual(await replaceHeldBeaconKey(r.deps, OLD, NEW), { kind: 'refused' });
  assert.deepEqual(r.store.data.get(PAIR)!.pendingWithdraws.map((w) => w.rowId), ['a']);
});

test('KR5 wasConfirmed is read BEFORE the key write and reported: false when the pair was not confirmed; a confirmed-read that throws is "not confirmed" (never a claim that may be false)', async () => {
  const no = rig({ confirmed: false }); seed(no.store, [row('a', E)]);
  assert.deepEqual(await replaceHeldBeaconKey(no.deps, OLD, NEW), { kind: 'replaced', wasConfirmed: false });
  const bad = rig({ confirmed: 'throw' }); seed(bad.store, [row('a', E)]);
  assert.deepEqual(await replaceHeldBeaconKey(bad.deps, OLD, NEW), { kind: 'replaced', wasConfirmed: false }, 'the replace still goes ahead');
});

test('KR6 a queue that cannot be committed (the store keeps losing the compare-and-swap) REFUSES and never writes the key', async () => {
  const r = rig(); seed(r.store, [row('a', E)]);
  r.store.cas = async () => false;                                    // every swap is lost: commit throws after 8 tries
  assert.deepEqual(await replaceHeldBeaconKey(r.deps, OLD, NEW), { kind: 'refused' });
  assert.ok(!r.log.includes('writeKey'));
});

test('KR7 a contact with no record at all and nothing to queue is replaced without writing anything to the pair store first', async () => {
  const r = rig();
  const out = await replaceHeldBeaconKey(r.deps, OLD, NEW);
  assert.deepEqual(out, { kind: 'replaced', wasConfirmed: false });
  assert.equal(r.store.writes.n, 0, 'no pair record was created just to replace a key');
});

test('KR8 a row a concurrent deposit landed after the plan is queued too, before the key is written', async () => {
  const r = rig(); seed(r.store, [row('a', E)]);
  const get = r.store.get.bind(r.store); let landed = false;
  r.store.get = async (id) => {                                       // a concurrent writer's row lands in the stored record after the plan, BEFORE our commit reads it
    if (!landed && r.log.includes('plan')) { landed = true; const s = r.store.data.get(PAIR)!; s.rows.push(row('late', E)); s.version = (s.version ?? 0) + 1; }
    return get(id);
  };
  assert.deepEqual(await replaceHeldBeaconKey(r.deps, OLD, NEW), { kind: 'replaced', wasConfirmed: false });
  assert.ok(landed, 'the concurrent row did land');
  assert.deepEqual(r.atKeyWrite()!.pending, ['a', 'late'], 'both were queued before the key was written');
});

test('KR9 NO NETWORK, NO SWITCH, NO CLIENT: the module imports only the queue, the record helpers and TYPES, never rolls the queue back, and takes no wire switch', () => {
  const src = readFileSync(join(process.cwd(), 'src/lib/trust/beacon-key-replace.ts'), 'utf8').replace(/\/\/[^\n]*/g, '');
  assert.doesNotMatch(src, /\bfetch\b|isBeaconWireLive|claim-gates|createBeaconClient|createBeaconWire/);
  const imports = [...src.matchAll(/^import\s+(type\s+)?[^;]*from\s+'([^']+)'/gm)].map((m) => `${m[1] ? 'type ' : ''}${m[2]}`);
  assert.deepEqual(imports.sort(), ['../crypto/beacon-pair-record', '../crypto/beacon-release-queue', 'type ../crypto/beacon-client'].sort());
  assert.doesNotMatch(src, /pendingWithdraws\s*=|\.put\(|unqueue|delete\s/, 'nothing here undoes the queue: it is never rolled back once the key write was attempted');
});

test('KR10 the key HAS changed: if the sweep after the key write throws, the outcome is still REPLACED (never refused, which would say the saved details are unchanged)', async () => {
  const r = rig({ postWriteReadThrows: true }); seed(r.store, [row('a', E)]);
  assert.deepEqual(await replaceHeldBeaconKey(r.deps, OLD, NEW), { kind: 'replaced', wasConfirmed: false });
});

test('KR11 the sweep after the key write queues a row a deposit landed in the gap, if it is under the OLD key, and leaves a row under the NEW key alone', async () => {
  const r = rig({ gapRows: [row('gapOld', E), row('gapNew', E)], underOld: (id) => id !== 'gapNew' }); seed(r.store, [row('a', E)]);
  assert.deepEqual(await replaceHeldBeaconKey(r.deps, OLD, NEW), { kind: 'replaced', wasConfirmed: false });
  assert.deepEqual(r.store.data.get(PAIR)!.pendingWithdraws.map((w) => w.rowId).sort(), ['a', 'gapOld'], 'the old-key row from the gap is queued; the new-key row is not');
});

test('KR12 a BUG error (a TypeError) in the sweep after the key write is REPORTED and the outcome is still replaced: a swallowed bug there would leave nothing to see', async () => {
  const r = rig({ postWriteReadThrows: 'bug' }); seed(r.store, [row('a', E)]);
  assert.deepEqual(await replaceHeldBeaconKey(r.deps, OLD, NEW), { kind: 'replaced', wasConfirmed: false });
  assert.equal(r.reported.length, 1, 'reported once');
  assert.equal(r.reported[0].where, 'replace-sweep');
  assert.ok(r.reported[0].err instanceof TypeError);
});

test('KR13 an ORDINARY store error in the sweep after the key write is not reported: it is the self-heal\'s to retry quietly', async () => {
  const r = rig({ postWriteReadThrows: true }); seed(r.store, [row('a', E)]);
  assert.deepEqual(await replaceHeldBeaconKey(r.deps, OLD, NEW), { kind: 'replaced', wasConfirmed: false });
  assert.equal(r.reported.length, 0);
});

test('KR14 a reporter that THROWS changes nothing: the outcome is still replaced', async () => {
  const r = rig({ postWriteReadThrows: 'bug', reporterThrows: true }); seed(r.store, [row('a', E)]);
  assert.deepEqual(await replaceHeldBeaconKey(r.deps, OLD, NEW), { kind: 'replaced', wasConfirmed: false });
  assert.equal(r.reported.length, 1, 'it was called, and its throw went nowhere');
});
