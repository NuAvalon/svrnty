// src/lib/trust/block-latch.test.ts
// Gate: Block and Remove set the beacon LATCH, a restore rebuilds it, and a latch with no suppression entry never reaches a backup silently.
// DARK: nothing here touches the wire; every port is a fake with a call log.
//   · ORDER: Remove = record the removal -> latch -> removeContact; Block = latch -> flag -> AWAITED suppression write. A failure at step N leaves the
//     earlier steps in place (a tightening is never rolled back) and writes none of the later ones.
//   · MUST: a contact whose BLOCKED FLAG is set but who is not in the suppression record is added to it (forward repair, on start and before every export;
//     the predicate is the FLAG, never the latch, or an Unblock would be silently undone); the reverse pass latches every record/removed id that has no latch (start/unlock: crash-safe
//     restore). Repair only ever ADDS; an unreadable or absent record is never written.
//   · RESTORE: every person and every removed id is latched; one failure never stops the others, and the report says "not ok" without naming an id.
// Run: npx tsx --test src/lib/trust/block-latch.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  blockWithLatch,
  removeWithLatch,
  unblockKeepingLatch,
  repairBlockedButUnsuppressed,
  relatchFromRecord,
  rebuildLatchesFromCarry,
  relatchReport,
  RELATCH_ERROR,
} from '@/lib/trust/block-latch';
import { applyBlockSuppression } from '@/lib/trust/block-suppression';
import { makeUpdate, type SealedRead } from '@/lib/trust/suppression-restore';
import { emptySuppression, suppressPerson, type SuppressionRecord } from '@/lib/trust/suppression';

const P1 = 'a'.repeat(64);
const P2 = 'b'.repeat(64);
const P3 = 'c'.repeat(64);

/** pair id = a stable function of the durable id (the real one is an HMAC; only the mapping matters here). */
const pairOf = (id: string) => `pair-${id.slice(0, 6)}`;

interface World {
  log: string[];
  latched: Set<string>;
  frozen: Set<string>;
  failLatch: boolean;
  failFlag: boolean;
  failRemovedRecord: boolean;
  failRemoveContact: boolean;
  suppressionOutcome: 'added' | 'already' | 'removed' | 'no-durable-id' | 'skipped-fail-closed' | 'skipped-error';
  locked: boolean;
}

function world(over: Partial<World> = {}): World {
  return { log: [], latched: new Set(), frozen: new Set(), failLatch: false, failFlag: false, failRemovedRecord: false, failRemoveContact: false, suppressionOutcome: 'added', locked: false, ...over };
}

function ports(w: World) {
  return {
    pairIdFor: async (id: string) => {
      if (w.locked) throw new Error('locked');
      return pairOf(id);
    },
    latch: {
      async setLatched(pair: string, source: 'local') {
        w.log.push(`latch:${pair}:${source}`);
        if (w.failLatch) throw new Error('latch write failed');
        w.latched.add(pair);
      },
      async kindOf(pair: string) {
        return w.latched.has(pair) ? ('removed' as const) : w.frozen.has(pair) ? ('frozen' as const) : null;
      },
      async clearLatched(pair: string) {
        w.log.push(`CLEAR:${pair}`); // must never happen on Unblock
      },
    },
  };
}

// ---------------------------------------------------------------- Remove: record -> latch -> removeContact

test('R4 Remove: the order is record -> latch -> removeContact (all three, in that order)', async () => {
  const w = world();
  await removeWithLatch({
    durableId: P1,
    ...ports(w),
    recordRemoved: async (id) => { w.log.push(`record:${id.slice(0, 3)}`); },
    removeContactRecord: async () => { w.log.push('removeContact'); },
  });
  assert.deepEqual(w.log, ['record:aaa', `latch:${pairOf(P1)}:local`, 'removeContact']);
});

test('R1 Remove: the removal cannot be recorded -> nothing else is written and the Remove fails', async () => {
  const w = world({ failRemovedRecord: true });
  await assert.rejects(removeWithLatch({
    durableId: P1, ...ports(w),
    recordRemoved: async () => { w.log.push('record'); throw new Error('list full'); },
    removeContactRecord: async () => { w.log.push('removeContact'); },
  }));
  assert.deepEqual(w.log, ['record'], 'no latch, no delete');
  assert.equal(w.latched.size, 0);
});

test('R2 Remove: record OK, latch throws -> the contact is NOT deleted, the removed-list entry stays (tighter), the Remove fails', async () => {
  const w = world({ failLatch: true });
  await assert.rejects(removeWithLatch({
    durableId: P1, ...ports(w),
    recordRemoved: async () => { w.log.push('record'); },
    removeContactRecord: async () => { w.log.push('removeContact'); },
  }));
  assert.deepEqual(w.log, ['record', `latch:${pairOf(P1)}:local`]);
});

test('R3 Remove: latch OK, removeContact throws -> the latch stays (never rolled back), the Remove fails', async () => {
  const w = world({ failRemoveContact: true });
  await assert.rejects(removeWithLatch({
    durableId: P1, ...ports(w),
    recordRemoved: async () => { w.log.push('record'); },
    removeContactRecord: async () => { w.log.push('removeContact'); throw new Error('delete failed'); },
  }));
  assert.equal(w.latched.has(pairOf(P1)), true);
});

test('R0 Remove: a keyless or legacy contact (no 64-hex durable id) is simply removed: no record, no latch, and the delete is NOT refused', async () => {
  for (const id of ['', 'not-hex', 'a'.repeat(40)]) {
    const w = world();
    await removeWithLatch({
      durableId: id, ...ports(w),
      recordRemoved: async () => { w.log.push('record'); throw new Error('must not be called'); },
      removeContactRecord: async () => { w.log.push('removeContact'); },
    });
    assert.deepEqual(w.log, ['removeContact'], `id "${id}"`);
    assert.equal(w.latched.size, 0);
  }
});

// ---------------------------------------------------------------- Block: latch -> flag -> awaited suppression

function blockArgs(w: World, id: string | null = P1) {
  return {
    peerDurableId: id,
    ...ports(w),
    writeBlockFlag: async () => { w.log.push('flag'); if (w.failFlag) throw new Error('flag write failed'); },
    applySuppression: async () => { w.log.push('suppression'); return { wrote: w.suppressionOutcome === 'added', outcome: w.suppressionOutcome }; },
  };
}

test('B4 Block: the order is latch -> flag -> suppression, and the result is finished', async () => {
  const w = world();
  const r = await blockWithLatch(blockArgs(w));
  assert.deepEqual(w.log, [`latch:${pairOf(P1)}:local`, 'flag', 'suppression']);
  assert.deepEqual(r, { finished: true, suppression: 'added' });
});

test('B1 Block: the latch write throws -> neither the flag nor the suppression write happens, the Block fails', async () => {
  const w = world({ failLatch: true });
  await assert.rejects(blockWithLatch(blockArgs(w)));
  assert.deepEqual(w.log, [`latch:${pairOf(P1)}:local`]);
});

test('B2 Block: latch OK, flag throws -> the latch stays, no suppression write, the Block fails', async () => {
  const w = world({ failFlag: true });
  await assert.rejects(blockWithLatch(blockArgs(w)));
  assert.equal(w.latched.has(pairOf(P1)), true);
  assert.equal(w.log.includes('suppression'), false);
});

test('B3 Block: suppression outcome "skipped-error" (a write on a READABLE record failed) -> NOT finished (the person is told the block did not finish); the latch and flag are already in place', async () => {
  const w = world({ suppressionOutcome: 'skipped-error' });
  const r = await blockWithLatch(blockArgs(w));
  assert.equal(r.finished, false);
  assert.equal(r.suppression, 'skipped-error');
  assert.equal(w.latched.has(pairOf(P1)), true);
});

for (const outcome of ['added', 'already', 'skipped-fail-closed'] as const) {
  test(`Block: suppression outcome "${outcome}" counts as finished (${outcome === 'skipped-fail-closed' ? 'an absent or unreadable record already suppresses everyone: no false alarm on a tree whose genesis init is not wired' : 'written or already there'})`, async () => {
    const r = await blockWithLatch(blockArgs(world({ suppressionOutcome: outcome })));
    assert.equal(r.finished, true);
  });
}

test('Block: a keyless contact (no durable id) has no pair to latch: no latch write, the flag is still written, nothing durable to finish', async () => {
  const w = world({ suppressionOutcome: 'no-durable-id' });
  const r = await blockWithLatch(blockArgs(w, null));
  assert.equal(w.latched.size, 0);
  assert.equal(w.log.some((l) => l.startsWith('latch:')), false);
  assert.equal(w.log.includes('flag'), true);
  assert.equal(r.finished, true);
});

test('Block: an upper-case or padded durable id is normalised before the pair id is derived (one pair, never two)', async () => {
  const w = world();
  await blockWithLatch(blockArgs(w, `  ${P1.toUpperCase()} `));
  assert.deepEqual(w.log[0], `latch:${pairOf(P1)}:local`);
});

// ---------------------------------------------------------------- Unblock leaves the latch

test('Unblock: flag then suppression, and the latch survives (the function has no latch port in its signature; the screen is pinned by a source guard when wired)', async () => {
  const w = world();
  w.latched.add(pairOf(P1));
  const r = await unblockKeepingLatch({
    writeBlockFlag: async () => { w.log.push('flag-off'); },
    applySuppression: async () => { w.log.push('suppression-off'); return { wrote: true, outcome: 'removed' as const }; },
  });
  assert.deepEqual(w.log, ['flag-off', 'suppression-off']);
  assert.equal(w.latched.has(pairOf(P1)), true);
  assert.equal(r.suppression, 'removed');
});

// ---------------------------------------------------------------- Repair, forward pass: BLOCKED flag set, not in the record (state B3)

function suppressionStore(initial: SealedRead<SuppressionRecord>, o: { throwOnCommit?: boolean } = {}) {
  let held: SealedRead<SuppressionRecord> = initial;
  let version = 0;
  let writes = 0;
  const update = makeUpdate<SuppressionRecord>({
    async read() { return { token: version, held }; },
    async commit(token, next) {
      if (o.throwOnCommit) throw new Error('commit failed');
      if (token !== version) return false;
      held = { state: 'ok', value: next };
      version++;
      writes++;
      return true;
    },
  });
  return { update, record: () => held, writes: () => writes, persons: () => (held.state === 'ok' ? [...held.value.persons] : null) };
}

test('MUST: a contact with the blocked flag set who is NOT in the suppression record is added to it', async () => {
  const s = suppressionStore({ state: 'ok', value: emptySuppression() });
  const r = await repairBlockedButUnsuppressed({ contacts: async () => [{ durableId: P1, blocked: true }, { durableId: P2, blocked: false }], updateSuppression: s.update });
  assert.equal(r.outcome, 'repaired');
  assert.deepEqual(s.persons(), [P1]);
});

test('MUST: an UNBLOCKED contact is never added, whatever the latch says (the flag is the intent, the latch is not)', async () => {
  const s = suppressionStore({ state: 'ok', value: emptySuppression() });
  const r = await repairBlockedButUnsuppressed({ contacts: async () => [{ durableId: P1, blocked: false }], updateSuppression: s.update });
  assert.equal(r.outcome, 'nothing-to-repair');
  assert.equal(s.writes(), 0);
});

test('repair: already in the record -> 0 writes (idempotent)', async () => {
  const s = suppressionStore({ state: 'ok', value: suppressPerson(emptySuppression(), P1) });
  const r = await repairBlockedButUnsuppressed({ contacts: async () => [{ durableId: P1, blocked: true }], updateSuppression: s.update });
  assert.equal(r.outcome, 'nothing-to-repair');
  assert.equal(s.writes(), 0);
});

test('repair only ADDS: global, groups and other persons are preserved', async () => {
  const base: SuppressionRecord = { global: true, groups: ['family'], persons: [P3] };
  const s = suppressionStore({ state: 'ok', value: base });
  await repairBlockedButUnsuppressed({ contacts: async () => [{ durableId: P1, blocked: true }], updateSuppression: s.update });
  const v = (s.record() as { value: SuppressionRecord }).value;
  assert.equal(v.global, true);
  assert.deepEqual(v.groups, ['family']);
  assert.deepEqual([...v.persons].sort(), [P1, P3].sort());
});

for (const state of ['unreadable', 'absent'] as const) {
  test(`repair: a ${state.toUpperCase()} record is never written (absent reads as "suppress everyone": a person list from nothing would be looser; the left-out notice covers the backup)`, async () => {
    const s = suppressionStore({ state });
    const r = await repairBlockedButUnsuppressed({ contacts: async () => [{ durableId: P1, blocked: true }], updateSuppression: s.update });
    assert.equal(r.outcome, 'unreadable');
    assert.equal(s.writes(), 0);
  });
}

test('repair: the write throws -> outcome "error" (the export must REFUSE on this)', async () => {
  const s = suppressionStore({ state: 'ok', value: emptySuppression() }, { throwOnCommit: true });
  const r = await repairBlockedButUnsuppressed({ contacts: async () => [{ durableId: P1, blocked: true }], updateSuppression: s.update });
  assert.equal(r.outcome, 'error');
});

test('repair: the contact list cannot be read -> outcome "error", never "nothing-to-repair"', async () => {
  const s = suppressionStore({ state: 'ok', value: emptySuppression() });
  const r = await repairBlockedButUnsuppressed({ contacts: async () => { throw new Error('locked'); }, updateSuppression: s.update });
  assert.equal(r.outcome, 'error');
  assert.equal(s.writes(), 0);
});

test('repair: a blocked contact with no usable durable id is skipped (nothing durable to suppress)', async () => {
  const s = suppressionStore({ state: 'ok', value: emptySuppression() });
  const r = await repairBlockedButUnsuppressed({ contacts: async () => [{ durableId: 'zz', blocked: true }], updateSuppression: s.update });
  assert.equal(r.outcome, 'nothing-to-repair');
});

test('SCENARIO: Block, Unblock, restart (both repair passes), export -> the person is NOT in the record, and the latch is still there', async () => {
  const w = world();
  const s = suppressionStore({ state: 'ok', value: emptySuppression() });
  const store = { updateSuppression: () => s.update };
  const flag = { blocked: false };
  const OWNER = 'f'.repeat(64);
  await blockWithLatch({ peerDurableId: P1, ...ports(w), writeBlockFlag: async () => { flag.blocked = true; }, applySuppression: () => applyBlockSuppression(OWNER, P1, true, store) });
  assert.deepEqual(s.persons(), [P1], 'Block wrote the record entry');
  await unblockKeepingLatch({ writeBlockFlag: async () => { flag.blocked = false; }, applySuppression: () => applyBlockSuppression(OWNER, P1, false, store) });
  assert.deepEqual(s.persons(), [], 'Unblock removed it');
  // restart: forward pass (the contact is still in the book, unblocked, still latched), then the reverse pass over the (now empty) record
  const fwd = await repairBlockedButUnsuppressed({ contacts: async () => [{ durableId: P1, blocked: flag.blocked }], updateSuppression: s.update });
  const rev = await relatchFromRecord({ readBookIds: async () => [], readPersons: async () => s.persons(), readRemoved: async () => [], ...ports(w) });
  assert.equal(fwd.outcome, 'nothing-to-repair');
  assert.equal(rev.outcome, 'nothing-to-do');
  assert.deepEqual(s.persons(), [], 'the reversed block was NOT written back');
  assert.equal(w.latched.has(pairOf(P1)), true, 'the latch stayed (tighter)');
});

test('SCENARIO: Block with the suppression write failing, then the repair, then the export reads the person in the record', async () => {
  const w = world();
  const s = suppressionStore({ state: 'ok', value: emptySuppression() });
  const flag = { blocked: false };
  const r = await blockWithLatch({
    peerDurableId: P1, ...ports(w),
    writeBlockFlag: async () => { flag.blocked = true; },
    applySuppression: async () => ({ wrote: false, outcome: 'skipped-error' as const }), // the write did not finish
  });
  assert.equal(r.finished, false);
  assert.deepEqual(s.persons(), [], 'the record is missing the person: a backup now would silently lack the block');
  const fix = await repairBlockedButUnsuppressed({ contacts: async () => [{ durableId: P1, blocked: flag.blocked }], updateSuppression: s.update });
  assert.equal(fix.outcome, 'repaired');
  assert.deepEqual(s.persons(), [P1]);
});

test('B2 gets NO repair: latch set but the flag write failed -> not added to the record (the person was told the Block failed)', async () => {
  const s = suppressionStore({ state: 'ok', value: emptySuppression() });
  const fix = await repairBlockedButUnsuppressed({ contacts: async () => [{ durableId: P1, blocked: false }], updateSuppression: s.update });
  assert.equal(fix.outcome, 'nothing-to-repair');
});

// ---------------------------------------------------------------- Repair, reverse pass: in the record / removed list, not latched (start / unlock)

test('reverse: every record person and removed id with NO latch gets one (crash between the restore write and the rebuild)', async () => {
  const w = world();
  const r = await relatchFromRecord({ readBookIds: async () => [], readPersons: async () => [P1], readRemoved: async () => [P2], ...ports(w) });
  assert.equal(r.outcome, 'relatched');
  assert.equal(r.latched, 2);
  assert.deepEqual([...w.latched].sort(), [pairOf(P1), pairOf(P2)].sort());
});

test('reverse: an id that already has a latch is left alone (no write), including a FROZEN one (never upgraded here)', async () => {
  const w = world();
  w.latched.add(pairOf(P1));
  w.frozen.add(pairOf(P2));
  const r = await relatchFromRecord({ readBookIds: async () => [], readPersons: async () => [P1, P2, P3], readRemoved: async () => [], ...ports(w) });
  assert.equal(r.latched, 1);
  assert.deepEqual(w.log, [`latch:${pairOf(P3)}:local`]);
});

test('reverse: nothing to do when the record and the list are empty', async () => {
  const r = await relatchFromRecord({ readBookIds: async () => [], readPersons: async () => [], readRemoved: async () => [], ...ports(world()) });
  assert.equal(r.outcome, 'nothing-to-do');
});

test('reverse: one side unreadable -> the other still runs and the outcome is "partial"', async () => {
  const w = world();
  const r = await relatchFromRecord({ readBookIds: async () => [], readPersons: async () => null, readRemoved: async () => [P2], ...ports(w) });
  assert.equal(r.outcome, 'partial');
  assert.deepEqual([...w.latched], [pairOf(P2)]);
});

test('reverse: both sides unreadable (or a reader throws) -> "unreadable", nothing written', async () => {
  const w = world();
  const r = await relatchFromRecord({ readBookIds: async () => [], readPersons: async () => null, readRemoved: async () => { throw new Error('locked'); }, ...ports(w) });
  assert.equal(r.outcome, 'unreadable');
  assert.equal(w.log.length, 0);
});

test('reverse: one latch write failing does not stop the others; "partial"; the report names no id', async () => {
  const w = world();
  const p = ports(w);
  const real = p.latch.setLatched;
  p.latch.setLatched = async (pair, src) => { if (pair === pairOf(P2)) throw new Error('write failed'); return real(pair, src); };
  const r = await relatchFromRecord({ readBookIds: async () => [], readPersons: async () => [P1, P2, P3], readRemoved: async () => [], ...p });
  assert.equal(r.outcome, 'partial');
  assert.equal(r.latched, 2);
  assert.equal(JSON.stringify(r).includes(P2), false);
});

test('reverse: a locked session latches nothing and is "partial", never "nothing-to-do"', async () => {
  const w = world({ locked: true });
  const r = await relatchFromRecord({ readBookIds: async () => [], readPersons: async () => [P1], readRemoved: async () => [], ...ports(w) });
  assert.equal(r.outcome, 'partial');
  assert.equal(r.latched, 0);
});

test('reverse: a malformed id in the list is counted failed ("partial"), never latched', async () => {
  const w = world();
  const r = await relatchFromRecord({ readBookIds: async () => [], readPersons: async () => ['zz', P1], readRemoved: async () => [], ...ports(w) });
  assert.equal(r.outcome, 'partial');
  assert.deepEqual([...w.latched], [pairOf(P1)]);
});

// ---------------------------------------------------------------- The BOOK governs a present contact: the removed list is append-only

test('BOOK GOVERNS: Remove -> re-add -> Trust tap (the latch is cleared) -> restart is NOT re-latched (the removed list still names them, but they are in the book)', async () => {
  const w = world();
  // after the tap: the id is on the (append-only) removed list, the contact is back in the book, and the tap cleared its latch
  const r = await relatchFromRecord({ readPersons: async () => [], readRemoved: async () => [P1], readBookIds: async () => [P1], ...ports(w) });
  assert.equal(r.outcome, 'nothing-to-do');
  assert.equal(w.latched.size, 0);
  assert.equal(w.log.length, 0, 'no latch write at all');
});

test('BOOK GOVERNS through a restore: a removed id whose contact is in the restored book is NOT latched', async () => {
  const w = world();
  const r = await rebuildLatchesFromCarry({ persons: [], removed: [P1], bookIds: [P1], ...ports(w) });
  assert.equal(r.ok, true);
  assert.equal(r.latched, 0);
  assert.equal(w.latched.size, 0);
});

test('a removed id whose contact is NOT in the book still latches (start-up pass and restore)', async () => {
  const a = world();
  const ra = await relatchFromRecord({ readPersons: async () => [], readRemoved: async () => [P2], readBookIds: async () => [P1], ...ports(a) });
  assert.equal(ra.outcome, 'relatched');
  assert.deepEqual([...a.latched], [pairOf(P2)]);
  const b = world();
  await rebuildLatchesFromCarry({ persons: [], removed: [P2], bookIds: [P1], ...ports(b) });
  assert.deepEqual([...b.latched], [pairOf(P2)]);
});

test('a record PERSON who is in the book STILL latches (a blocked person cannot be trust-tapped; the book does not excuse a block)', async () => {
  const a = world();
  await relatchFromRecord({ readPersons: async () => [P1], readRemoved: async () => [], readBookIds: async () => [P1], ...ports(a) });
  assert.deepEqual([...a.latched], [pairOf(P1)]);
  const b = world();
  await rebuildLatchesFromCarry({ persons: [P1], removed: [], bookIds: [P1], ...ports(b) });
  assert.deepEqual([...b.latched], [pairOf(P1)]);
});

test('an id that is BOTH a record person and a removed id, and is in the book: the person wins (latched)', async () => {
  const w = world();
  await rebuildLatchesFromCarry({ persons: [P1], removed: [P1], bookIds: [P1], ...ports(w) });
  assert.deepEqual([...w.latched], [pairOf(P1)]);
});

test('an UNREADABLE book SKIPS the removed side (a read error must not re-latch a contact whose owner tapped Trust): persons still latch, the outcome is "partial", the next unlock retries', async () => {
  const w = world();
  const r = await relatchFromRecord({ readPersons: async () => [P2], readRemoved: async () => [P1], readBookIds: async () => { throw new Error('locked'); }, ...ports(w) });
  assert.equal(r.outcome, 'partial');
  assert.deepEqual([...w.latched], [pairOf(P2)], 'the person latched; the removed id did NOT');
  // the next unlock, with a readable book that holds the removed contact: still nothing latched for them
  const next = await relatchFromRecord({ readPersons: async () => [P2], readRemoved: async () => [P1], readBookIds: async () => [P1], ...ports(w) });
  assert.equal(next.outcome, 'nothing-to-do');
  assert.equal(w.latched.has(pairOf(P1)), false);
});

test('REPORT: a clean or empty pass is ok; partial, unreadable and a thrown pass are NOT ok; counts only, never an id', () => {
  assert.equal(relatchReport({ outcome: 'relatched', latched: 2, failed: 0 }).ok, true);
  assert.equal(relatchReport({ outcome: 'nothing-to-do', latched: 0, failed: 0 }).ok, true);
  assert.equal(relatchReport({ outcome: 'partial', latched: 1, failed: 1 }).ok, false);
  assert.equal(relatchReport({ outcome: 'unreadable', latched: 0, failed: 0 }).ok, false);
  assert.equal(RELATCH_ERROR.ok, false);
  assert.deepEqual(Object.keys(relatchReport({ outcome: 'partial', latched: 1, failed: 1 })).sort(), ['failed', 'latched', 'ok', 'outcome']);
});

test('REPORT through a restore: a latch write that FAILS makes the report NOT ok (and names no id)', async () => {
  const w = world();
  const p = ports(w);
  const real = p.latch.setLatched;
  p.latch.setLatched = async (pair, src) => { if (pair === pairOf(P1)) throw new Error('write failed'); return real(pair, src); };
  const r = relatchReport(await relatchFromRecord({ readPersons: async () => [P1, P2], readRemoved: async () => [], readBookIds: async () => [], ...p }));
  assert.equal(r.ok, false);
  assert.equal(r.outcome, 'partial');
  assert.equal(r.latched, 1);
  assert.equal(JSON.stringify(r).includes(P1), false);
});

// ---------------------------------------------------------------- Restore rebuild

test('restore: every person AND every removed id is latched (the union, each once)', async () => {
  const w = world();
  const r = await rebuildLatchesFromCarry({ bookIds: [], persons: [P1, P2], removed: [P2, P3], ...ports(w) });
  assert.equal(r.ok, true);
  assert.deepEqual([...w.latched].sort(), [pairOf(P1), pairOf(P2), pairOf(P3)].sort());
  assert.equal(w.log.filter((l) => l.startsWith('latch:')).length, 3);
});

test('restore: only persons are latched when the removed list is empty, and only removed ids when there are no persons', async () => {
  const a = world(); await rebuildLatchesFromCarry({ bookIds: [], persons: [P1], removed: [], ...ports(a) });
  const b = world(); await rebuildLatchesFromCarry({ bookIds: [], persons: [], removed: [P2], ...ports(b) });
  assert.deepEqual([...a.latched], [pairOf(P1)]);
  assert.deepEqual([...b.latched], [pairOf(P2)]);
});

test('restore: one latch write failing does not stop the others, the report is NOT ok, and it names no id', async () => {
  const w = world();
  const p = ports(w);
  const real = p.latch.setLatched;
  p.latch.setLatched = async (pair, src) => { if (pair === pairOf(P2)) throw new Error('write failed'); return real(pair, src); };
  const r = await rebuildLatchesFromCarry({ bookIds: [], persons: [P1, P2, P3], removed: [], ...p });
  assert.equal(r.ok, false);
  assert.equal(r.failed, 1);
  assert.equal(r.latched, 2);
  assert.equal(JSON.stringify(r).includes(P2), false, 'no durable id in the report');
});

test('restore: a locked session latches nothing and is NOT ok (never "ok, 0 latched")', async () => {
  const w = world({ locked: true });
  const r = await rebuildLatchesFromCarry({ bookIds: [], persons: [P1], removed: [], ...ports(w) });
  assert.equal(r.ok, false);
  assert.equal(w.latched.size, 0);
});

test('restore: an id that is not a durable id is refused (counted failed), never latched under a made-up pair', async () => {
  const w = world();
  const r = await rebuildLatchesFromCarry({ bookIds: [], persons: ['zz', P1], removed: [], ...ports(w) });
  assert.equal(r.ok, false);
  assert.deepEqual([...w.latched], [pairOf(P1)]);
});
