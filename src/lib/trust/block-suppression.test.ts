// src/lib/trust/block-suppression.test.ts
// ADVERSARIAL gate for the piece-2 block→suppression-record POPULATE write-path (task #579, Archie do-no-harm
// gate #159479/#159668). Refutes survivor-safety properties, not "a value round-trips":
//   · §F3 FAIL-CLOSED: an UNREADABLE record (null) is NEVER overwritten — no write is made,
//     so a corrupt record's suppress-all can never be reduced to suppress-one (the survivor RE-EXPOSE),
//   · block ADDS the peer's canonical durable_id; unblock REMOVES exactly it; both idempotent,
//   · a keyless/gray contact (no fingerprint) is a no-op (nothing durable to suppress),
//   · block touches ONLY persons — global / groups / other persons are preserved (no collateral change),
//   · durable_id keying is case-insensitive / trimmed (rotation-stable canonical fp, not UUID/mailbox/route),
//   · a write failure NEVER throws to the caller (the block still holds via the record + the `blocked` flag).
// Run: npx tsx --test src/lib/trust/block-suppression.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyBlockSuppression, decideBlock, type SuppressionStoreSeam } from '@/lib/trust/block-suppression';
import { mergeByTightening } from '@/lib/trust/suppression-carry';
import { makeUpdate, type SealedRead } from '@/lib/trust/suppression-restore';
import { emptySuppression, type SuppressionRecord } from '@/lib/trust/suppression';

const OWNER = 'f'.repeat(64);
const PEER = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);
const RESTORED = 'c'.repeat(64);

interface World {
  rec: SuppressionRecord | null;
  unreadable: boolean;
  version: number;
}

/**
 * In-memory store seam: the REAL atomic-update loop (makeUpdate) over a versioned record, so a write that lands between the read and the commit is a real interleaving. `setCalls` counts commit
 * attempts that reach the write (so the fail-closed path can be shown NEVER to write); `beforeCommit` is where a concurrent writer lands.
 */
function makeStore(initial: SuppressionRecord | null, opts: { unreadable?: boolean; beforeCommit?: (w: World) => void } = {}): {
  store: SuppressionStoreSeam;
  setCalls: () => number;
  reads: () => number;
  current: () => SuppressionRecord | null;
  setThrows: (on: boolean) => void;
  world: World;
} {
  const world: World = { rec: initial, unreadable: opts.unreadable === true, version: 0 };
  let calls = 0;
  let reads = 0;
  let throwOnSet = false;
  const held = (): SealedRead<SuppressionRecord> => (world.unreadable ? { state: 'unreadable' } : world.rec === null ? { state: 'absent' } : { state: 'ok', value: world.rec });
  return {
    store: {
      updateSuppression: () =>
        makeUpdate<SuppressionRecord>({
          read: async () => { reads += 1; return { token: world.version, held: held() }; },
          commit: async (token, value) => {
            opts.beforeCommit?.(world);
            if (world.version !== token) return false; // another write landed first: the loop decides again on the newer record
            calls += 1;
            if (throwOnSet) throw new Error('session locked (simulated)');
            world.rec = value;
            world.version += 1;
            return true;
          },
        }),
    },
    setCalls: () => calls,
    reads: () => reads,
    current: () => world.rec,
    setThrows: (on: boolean) => {
      throwOnSet = on;
    },
    world,
  };
}

test('block ADDS the peer durable_id to the record', async () => {
  const m = makeStore(emptySuppression());
  const r = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.equal(r.wrote, true);
  assert.equal(r.outcome, 'added');
  assert.deepEqual(m.current()?.persons, [PEER]);
  assert.equal(m.setCalls(), 1);
});

test('block is IDEMPOTENT — re-blocking an already-suppressed person does not re-write', async () => {
  const m = makeStore({ global: false, groups: [], persons: [PEER] });
  const r = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.equal(r.wrote, false);
  assert.equal(r.outcome, 'already');
  assert.equal(m.setCalls(), 0); // no redundant write
  assert.deepEqual(m.current()?.persons, [PEER]);
});

test('unblock REMOVES exactly the peer durable_id', async () => {
  const m = makeStore({ global: false, groups: [], persons: [PEER, OTHER] });
  const r = await applyBlockSuppression(OWNER, PEER, false, m.store);
  assert.equal(r.wrote, true);
  assert.equal(r.outcome, 'removed');
  assert.deepEqual(m.current()?.persons, [OTHER]); // only PEER removed
  assert.equal(m.setCalls(), 1);
});

test('unblock of a NON-suppressed person is a no-op (no redundant write)', async () => {
  const m = makeStore({ global: false, groups: [], persons: [OTHER] });
  const r = await applyBlockSuppression(OWNER, PEER, false, m.store);
  assert.equal(r.wrote, false);
  assert.equal(r.outcome, 'already');
  assert.equal(m.setCalls(), 0);
  assert.deepEqual(m.current()?.persons, [OTHER]);
});

test('★ §F3 FAIL-CLOSED: an UNREADABLE record (null) is NEVER overwritten — no reduce-to-suppress-one', async () => {
  const m = makeStore(null); // locked / decrypt-fail / malformed / absent
  const r = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.equal(r.wrote, false);
  assert.equal(r.outcome, 'skipped-fail-closed');
  assert.equal(m.setCalls(), 0); // THE survivor-safety assertion: we never write over an unreadable record
  assert.equal(m.current(), null);
});

test('§F3 fail-closed also holds for UNBLOCK on a null record (never materializes a reduced record)', async () => {
  const m = makeStore(null);
  const r = await applyBlockSuppression(OWNER, PEER, false, m.store);
  assert.equal(r.wrote, false);
  assert.equal(r.outcome, 'skipped-fail-closed');
  assert.equal(m.setCalls(), 0);
});

test('keyless/gray contact (no fingerprint) is a no-op — no store access at all', async () => {
  const keyless: Array<string | undefined | null> = ['', '   ', undefined, null];
  for (const bad of keyless) {
    const m = makeStore(emptySuppression());
    const r = await applyBlockSuppression(OWNER, bad, true, m.store);
    assert.equal(r.wrote, false);
    assert.equal(r.outcome, 'no-durable-id');
    assert.equal(m.setCalls(), 0);
  }
});

test('block touches ONLY persons — global + groups + other persons preserved', async () => {
  const m = makeStore({ global: true, groups: ['g1', 'g2'], persons: [OTHER] });
  await applyBlockSuppression(OWNER, PEER, true, m.store);
  const rec = m.current()!;
  assert.equal(rec.global, true);
  assert.deepEqual(rec.groups, ['g1', 'g2']);
  assert.deepEqual(rec.persons.sort(), [OTHER, PEER].sort());
});

test('durable_id keying is case-insensitive + trimmed (canonical fp, not a raw UUID)', async () => {
  const m = makeStore(emptySuppression());
  await applyBlockSuppression(OWNER, `  ${PEER.toUpperCase()}  `, true, m.store);
  assert.deepEqual(m.current()?.persons, [PEER]); // normalized to lowercase + trimmed
  // re-block the lowercase form → idempotent (same canonical id)
  const r2 = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.equal(r2.outcome, 'already');
  assert.equal(m.setCalls(), 1); // only the first write happened
});

test('a write failure NEVER throws to the caller (block still holds via record + blocked flag)', async () => {
  const m = makeStore(emptySuppression());
  m.setThrows(true);
  const r = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.equal(r.wrote, false);
  assert.equal(r.outcome, 'skipped-error'); // swallowed, not thrown
});

test('an UNREADABLE (not merely absent) record is never overwritten either', async () => {
  const m = makeStore(emptySuppression(), { unreadable: true });
  for (const blocked of [true, false]) {
    const r = await applyBlockSuppression(OWNER, PEER, blocked, m.store);
    assert.deepEqual(r, { wrote: false, outcome: 'skipped-fail-closed' });
  }
  assert.equal(m.setCalls(), 0);
});

// ── the lost update: a Block / Unblock decided on a record read BEFORE a restore merged its persons ──────────────────────────────────────────────
test('★ a BLOCK that read before a restore committed keeps the restored persons AND the blocked person', async () => {
  const m = makeStore({ global: false, groups: [], persons: [OTHER] }, {
    beforeCommit: (() => { let done = false; return (w: World) => { if (!done) { done = true; w.rec = mergeByTightening(w.rec!, { v: 1, global: false, groups: [], persons: [RESTORED], removed: [] }); w.version += 1; } }; })(),
  });
  const r = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.deepEqual(r, { wrote: true, outcome: 'added' });
  assert.deepEqual(m.current()?.persons.slice().sort(), [OTHER, PEER, RESTORED].sort(), 'the restored person survives and the blocked person is present');
  assert.equal(m.reads(), 2, 'decided twice: once on the stale record, once on the one the restore wrote');
});

test('★ an UNBLOCK that read before a restore committed removes only the unblocked person', async () => {
  const m = makeStore({ global: false, groups: [], persons: [PEER, OTHER] }, {
    beforeCommit: (() => { let done = false; return (w: World) => { if (!done) { done = true; w.rec = mergeByTightening(w.rec!, { v: 1, global: true, groups: ['g'], persons: [RESTORED], removed: [] }); w.version += 1; } }; })(),
  });
  const r = await applyBlockSuppression(OWNER, PEER, false, m.store);
  assert.deepEqual(r, { wrote: true, outcome: 'removed' });
  assert.deepEqual(m.current()?.persons.slice().sort(), [OTHER, RESTORED].sort());
  assert.equal(m.current()?.global, true, 'the restore\'s global and groups survive too');
  assert.deepEqual(m.current()?.groups, ['g']);
});

test('a record that becomes UNREADABLE between the read and the commit is left alone', async () => {
  const m = makeStore({ global: false, groups: [], persons: [OTHER] }, {
    beforeCommit: (() => { let done = false; return (w: World) => { if (!done) { done = true; w.unreadable = true; w.version += 1; } }; })(),
  });
  const r = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.deepEqual(r, { wrote: false, outcome: 'skipped-fail-closed' });
  assert.equal(m.setCalls(), 0);
});

test('a record that keeps changing is abandoned after the bounded attempts: swallowed, nothing written', async () => {
  const m = makeStore({ global: false, groups: [], persons: [OTHER] }, { beforeCommit: (w) => { w.version += 1; } });
  const r = await applyBlockSuppression(OWNER, PEER, true, m.store);
  assert.deepEqual(r, { wrote: false, outcome: 'skipped-error' });
  assert.equal(m.setCalls(), 0);
});

test('decideBlock: pure, and the same answer every time it runs', () => {
  const ok = (r: SuppressionRecord): SealedRead<SuppressionRecord> => ({ state: 'ok', value: r });
  const rec = { global: false, groups: [], persons: [OTHER] };
  for (const held of [{ state: 'absent' }, { state: 'unreadable' }] as SealedRead<SuppressionRecord>[]) {
    for (const blocked of [true, false]) assert.deepEqual(decideBlock(held, PEER, blocked), { result: 'skipped-fail-closed' });
  }
  assert.deepEqual(decideBlock(ok(rec), PEER, true), { write: { global: false, groups: [], persons: [OTHER, PEER] }, result: 'added' });
  assert.deepEqual(decideBlock(ok(rec), OTHER, true), { result: 'already' });
  assert.deepEqual(decideBlock(ok(rec), OTHER, false), { write: { global: false, groups: [], persons: [] }, result: 'removed' });
  assert.deepEqual(decideBlock(ok(rec), PEER, false), { result: 'already' });
  const before = JSON.stringify(rec);
  decideBlock(ok(rec), PEER, true); decideBlock(ok(rec), OTHER, false);
  assert.equal(JSON.stringify(rec), before, 'the input record is never mutated');
});
