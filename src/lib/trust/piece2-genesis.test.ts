// src/lib/trust/piece2-genesis.test.ts
// Gate for the piece-2 GENESIS-INIT spine hook. It writes the explicit empty suppression record ONLY when none is stored, as one compare-and-swap (the update Block and Unblock use).
// Refutes:
//   · an ABSENT record gets the explicit empty record (the default-discoverable baseline), exactly once,
//   · an existing record is NEVER replaced: not a populated one, not an empty one, not one that exists but cannot be read,
//   · a record that lands between the hook's read and its commit (a restore, a second tab) is kept: the decision is made again on the newer record,
//   · running it twice writes nothing the second time (idempotent),
//   · it NEVER writes under an empty/garbage fingerprint,
//   · a throwing store is SWALLOWED by runGenesisHooks (identity creation never fails on a hook): fail-closed is the consumer's null-means-suppress-all, not a throw here,
//   · registerPiece2GenesisInit installs a hook that fires in the mint flow without rejecting.
// Run: npx tsx --test src/lib/trust/piece2-genesis.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decideGenesisInit, makePiece2GenesisInit, registerPiece2GenesisInit } from './piece2-genesis.js';
import { makeUpdate, type SealedRead, type Update } from './suppression-restore.js';
import {
  registerGenesisHook,
  runGenesisHooks,
  __clearGenesisHooksForTest,
} from '../identity/identity-genesis-hooks.js';
import { isSuppressionRecord, type SuppressionRecord } from './suppression.js';

const FP = 'deadbeef'.repeat(8); // 64 hex
const X = '1'.padStart(64, '0');
const EMPTY: SuppressionRecord = { global: false, groups: [], persons: [] };
const POPULATED: SuppressionRecord = { global: true, groups: ['family'], persons: [X] };

/** One sealed record behind the REAL makeUpdate loop: a commit succeeds only if the row is still the version that was read. */
function store(initial: SealedRead<SuppressionRecord>, beforeCommit?: (s: ReturnType<typeof store>) => void) {
  const s = {
    state: initial,
    version: 0,
    writes: [] as SuppressionRecord[],
    asked: [] as string[],               // every fingerprint the hook asked an update for
    land(rec: SuppressionRecord) { s.state = { state: 'ok', value: rec }; s.version += 1; },
    update: ((fp: string): Update<SuppressionRecord> => (s.asked.push(fp), makeUpdate<SuppressionRecord>({
      read: async () => ({ token: s.version, held: s.state }),
      commit: async (token, value) => {
        beforeCommit?.(s);
        if (s.version !== token) return false;
        s.state = { state: 'ok', value };
        s.version += 1;
        s.writes.push(value);
        return true;
      },
    }))),
  };
  return s;
}

test('an ABSENT record gets the EXPLICIT empty suppression record, once (default-discoverable baseline)', async () => {
  const s = store({ state: 'absent' });
  await makePiece2GenesisInit(s.update)(FP);
  assert.equal(s.writes.length, 1, 'wrote once');
  assert.ok(isSuppressionRecord(s.writes[0]), 'well-formed record');
  assert.deepEqual(s.writes[0], EMPTY, 'empty = never-suppressed baseline');
  assert.deepEqual(s.state, { state: 'ok', value: EMPTY });
});

test('an existing POPULATED record is never replaced by empty', async () => {
  const s = store({ state: 'ok', value: POPULATED });
  await makePiece2GenesisInit(s.update)(FP);
  assert.equal(s.writes.length, 0, 'wrote nothing');
  assert.deepEqual(s.state, { state: 'ok', value: POPULATED }, 'the survivor\'s blocks are exactly as they were');
});

test('an existing EMPTY record is left alone too, and a second run writes nothing (idempotent)', async () => {
  const s = store({ state: 'absent' });
  const hook = makePiece2GenesisInit(s.update);
  await hook(FP);
  await hook(FP);
  assert.equal(s.writes.length, 1, 'the second run found the record and wrote nothing');
  const t = store({ state: 'ok', value: EMPTY });
  await makePiece2GenesisInit(t.update)(FP);
  assert.equal(t.writes.length, 0);
});

test('a record that EXISTS BUT CANNOT BE READ is left alone: it is not "absent"', async () => {
  const s = store({ state: 'unreadable' });
  await makePiece2GenesisInit(s.update)(FP);
  assert.equal(s.writes.length, 0, 'no write over an unreadable record');
  assert.deepEqual(s.state, { state: 'unreadable' });
});

test('a record that lands BETWEEN the read and the commit (a restore, a second tab) is KEPT: the decision is made again on the newer record', async () => {
  let landed = false;
  const s = store({ state: 'absent' }, (st) => { if (!landed) { landed = true; st.land(POPULATED); } });
  await makePiece2GenesisInit(s.update)(FP);
  assert.deepEqual(s.state, { state: 'ok', value: POPULATED }, 'the record that landed is what is stored');
  assert.equal(s.writes.length, 0, 'the hook wrote nothing of its own');
});

test('no-op on an empty/whitespace fingerprint (never touches the store under an empty key)', async () => {
  let calls = 0;
  const hook = makePiece2GenesisInit(() => { calls += 1; return makeUpdate<SuppressionRecord>({ read: async () => ({ token: 0, held: { state: 'absent' } }), commit: async () => true }); });
  await hook('');
  await hook('   ');
  await hook(undefined as unknown as string);
  assert.equal(calls, 0, 'never asked for an update');
});

test('the hook passes the TRIMMED fingerprint to the store', async () => {
  const s = store({ state: 'absent' });
  await makePiece2GenesisInit(s.update)(`  ${FP}  `);
  assert.deepEqual(s.asked, [FP]);
});

test('decideGenesisInit is pure: absent writes the exact empty record; a present record, readable or not, writes nothing', () => {
  assert.deepEqual(decideGenesisInit({ state: 'absent' }), { write: EMPTY, result: 'written' });
  assert.deepEqual(decideGenesisInit({ state: 'ok', value: POPULATED }), { result: 'kept-existing' });
  assert.deepEqual(decideGenesisInit({ state: 'ok', value: EMPTY }), { result: 'kept-existing' });
  assert.deepEqual(decideGenesisInit({ state: 'unreadable' }), { result: 'kept-unreadable' });
  const a = decideGenesisInit({ state: 'absent' }) as { write: SuppressionRecord };
  const b = decideGenesisInit({ state: 'absent' }) as { write: SuppressionRecord };
  assert.notEqual(a.write, b.write, 'each call builds its own record: nothing shared can be mutated');
});

test('a throwing store is SWALLOWED by runGenesisHooks (identity creation never fails on a hook)', async () => {
  __clearGenesisHooksForTest();
  let fired = '';
  registerGenesisHook(makePiece2GenesisInit((fp) => { fired = fp; throw new Error('store locked'); }));
  await assert.doesNotReject(runGenesisHooks(FP), 'runGenesisHooks swallows the throw');
  assert.equal(fired, FP, 'the hook fired (threw, was swallowed): the consumer\'s null-means-suppress-all is the fail-closed');
  __clearGenesisHooksForTest();
});

test('registerPiece2GenesisInit installs a hook that fires in the mint flow without rejecting', async () => {
  __clearGenesisHooksForTest();
  // Registers the REAL hook (wired to the IndexedDB store). With no session it throws "locked" inside the update, which runGenesisHooks swallows: a genesis run does not reject.
  registerPiece2GenesisInit();
  await assert.doesNotReject(runGenesisHooks(FP), 'registered hook fires + is swallowed on the no-session store error');
  __clearGenesisHooksForTest();
});
