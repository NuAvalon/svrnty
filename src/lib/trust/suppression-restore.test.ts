// src/lib/trust/suppression-restore.test.ts
// ADVERSARIAL gate for what a restore does with a carried suppression record. Refutes the ways it could LOOSEN suppression or overwrite what it did not read:
//   - a fresh device gets the carried persons and groups with global ON whatever the backup said; a backup's global-off waits for the person's confirmation,
//   - a readable record is only ever tightened; an UNREADABLE one is never overwritten,
//   - every change is ONE atomic read-modify-write: a write that lands between the read and the commit is kept, never overwritten by a stale result (a control proves the harness
//     can see the loss in the old read-then-replace shape),
//   - nothing carried, or a malformed value, touches no port at all,
//   - the confirmation needs the marker the restore left and cannot half-apply,
//   - the removed list unions, refuses over the cap and never overwrites an unreadable list,
//   - the module is PURE (imports only ./suppression types and ./suppression-carry), and the unguarded replace forms are not in its port.
// Run: npx tsx --test src/lib/trust/suppression-restore.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  confirmPendingGlobalOff,
  makeUpdate,
  parsePendingGlobalOff,
  parseRemovedList,
  planRemovedAppend,
  recordRemoval,
  removalRefusal,
  restoreSuppression,
  setOwnerGlobalVisible,
  suppressionCarryStatus,
  suppressionToCarry,
  UPDATE_MAX_ATTEMPTS,
  type PendingGlobalOff,
  type RestorePorts,
  type SealedRead,
  type Update,
} from '@/lib/trust/suppression-restore';
import { CARRY_MAX_ENTRIES, mergeByTightening } from '@/lib/trust/suppression-carry';
import { isPartySuppressed, type SuppressionRecord } from '@/lib/trust/suppression';

const hex = (n: number): string => n.toString(16).padStart(64, '0');
const X = hex(1);
const Y = hex(2);
const Z = hex(4);
const OTHER = hex(3);
const AT = '2026-11-15T12:00:00.000Z';
const NOW = '2026-11-16T02:30:00.000Z'; // the device clock the store passes in
const carried = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ v: 1, global: false, groups: ['family'], persons: [X], removed: [], ...over });
const rec = (over: Partial<SuppressionRecord> = {}): SuppressionRecord => ({ global: false, groups: [], persons: [], ...over });
const suppressed = (r: SuppressionRecord | null, id: string): boolean => isPartySuppressed(r, { durableId: id });
const ids = (from: number, n: number): string[] => Array.from({ length: n }, (_, i) => hex(from + i));

interface World {
  supp: SealedRead<SuppressionRecord>;
  removed: SealedRead<string[]>;
  pending: SealedRead<PendingGlobalOff>;
  vSupp: number;
  vRemoved: number;
}
interface Opts {
  supp?: SealedRead<SuppressionRecord>;
  removed?: SealedRead<string[]>;
  pending?: SealedRead<PendingGlobalOff>;
  /** Runs between a read and its commit: a concurrent writer lands here (it bumps the version, as any write does). */
  beforeCommit?: (name: 'suppression' | 'removed', attempt: number, w: World) => void;
  failOn?: 'writePending' | 'clearPending';
}

function makePorts(o: Opts = {}): { ports: RestorePorts; w: World; log: string[] } {
  const w: World = { supp: o.supp ?? { state: 'absent' }, removed: o.removed ?? { state: 'absent' }, pending: o.pending ?? { state: 'absent' }, vSupp: 0, vRemoved: 0 };
  const log: string[] = [];
  const fail = (name: string) => { if (o.failOn === name) throw new Error(`${name} failed (simulated)`); };
  /** A store over one record: `read` hands back the state and a token (its version); `commit` succeeds only if the version is still that token. The REAL loop is makeUpdate. */
  const store = <T>(name: 'suppression' | 'removed', get: () => SealedRead<T>, set: (v: T) => void, ver: () => number, bump: () => void): Update<T> => {
    let reads = 0;
    return makeUpdate<T>({
      read: async () => { reads += 1; log.push(`${name}:read`); return { token: ver(), held: get() }; },
      commit: async (token, value) => {
        o.beforeCommit?.(name, reads, w);
        if (ver() !== token) { log.push(`${name}:conflict`); return false; }
        log.push(`${name}:write`);
        set(value);
        bump();
        return true;
      },
    });
  };
  const ports: RestorePorts = {
    updateSuppression: store<SuppressionRecord>('suppression', () => w.supp, (v) => { w.supp = { state: 'ok', value: v }; }, () => w.vSupp, () => { w.vSupp += 1; }),
    updateRemoved: store<string[]>('removed', () => w.removed, (v) => { w.removed = { state: 'ok', value: v }; }, () => w.vRemoved, () => { w.vRemoved += 1; }),
    readPending: async () => { log.push('readPending'); return w.pending; },
    writePending: async (p) => { log.push('writePending'); fail('writePending'); w.pending = { state: 'ok', value: p }; },
    clearPending: async () => { log.push('clearPending'); fail('clearPending'); w.pending = { state: 'absent' }; },
  };
  return { ports, w, log };
}
const writes = (log: string[]): string[] => log.filter((l) => /(:write|^writePending|^clearPending)$/.test(l));
const okRec = (w: World): SuppressionRecord => { assert.equal(w.supp.state, 'ok'); return (w.supp as { value: SuppressionRecord }).value; };
const okRemoved = (w: World): string[] => { assert.equal(w.removed.state, 'ok'); return (w.removed as { value: string[] }).value; };
/** A concurrent writer adds a suppression (or a removed id), as a second tab or a Remove would. */
const landSupp = (w: World, r: SuppressionRecord): void => { w.supp = { state: 'ok', value: r }; w.vSupp += 1; };
const landRemoved = (w: World, l: string[]): void => { w.removed = { state: 'ok', value: l }; w.vRemoved += 1; };
const once = (fn: (w: World) => void): NonNullable<Opts['beforeCommit']> => { let done = false; return (_n, _a, w) => { if (!done) { done = true; fn(w); } }; };

test('nothing carried, or a value the strict parser refuses, touches NO port at all', async () => {
  for (const bad of [undefined, null, 0, 'x', [], {}, carried({ v: 2 }), carried({ persons: ['nope'] }), carried({ extra: 1 }), carried({ global: 'false' })]) {
    const { ports, log } = makePorts();
    const r = await restoreSuppression(bad, { backupAt: AT, restoredAt: NOW }, ports);
    assert.deepEqual(r, { suppression: 'none-no-carried-record', pendingGlobalOff: false, removed: 'none-no-carried-record' });
    assert.deepEqual(log, [], `a port was touched for ${JSON.stringify(bad)}`);
  }
});

test('FRESH device, backup said global OFF: persons and groups written at once, global stays ON, the confirmation is left waiting', async () => {
  const { ports, w, log } = makePorts();
  const r = await restoreSuppression(carried({ global: false, persons: [X], groups: ['family'] }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.deepEqual(r, { suppression: 'written-fresh', pendingGlobalOff: true, removed: 'none-nothing-new' });
  assert.deepEqual(okRec(w), { global: true, groups: ['family'], persons: [X] });
  assert.equal(suppressed(okRec(w), X), true);
  assert.equal(suppressed(okRec(w), OTHER), true, 'still dark for everyone else until the person confirms');
  assert.deepEqual(w.pending, { state: 'ok', value: { v: 1, backup_at: AT, restored_at: NOW } });
  assert.ok(log.indexOf('suppression:write') < log.indexOf('writePending'), 'the record is written BEFORE the marker');
});

test('FRESH device, backup said global ON: written, and NO confirmation is left (nothing to wait for)', async () => {
  const { ports, w, log } = makePorts();
  const r = await restoreSuppression(carried({ global: true }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.equal(r.suppression, 'written-fresh');
  assert.equal(r.pendingGlobalOff, false);
  assert.equal(okRec(w).global, true);
  assert.equal(w.pending.state, 'absent');
  assert.ok(!log.includes('writePending'));
});

test('the confirmation: global goes OFF, the carried person stays suppressed, the marker is cleared', async () => {
  const { ports, w } = makePorts();
  await restoreSuppression(carried({ global: false, persons: [X] }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.equal(await confirmPendingGlobalOff(ports), 'confirmed');
  assert.equal(okRec(w).global, false);
  assert.equal(suppressed(okRec(w), X), true, 'x is still suppressed');
  assert.equal(suppressed(okRec(w), OTHER), false, 'discoverable to the rest after the confirm');
  assert.equal(w.pending.state, 'absent');
});

test('EXISTING readable record: global TRUE stays TRUE under a carried global false; entries only added', async () => {
  const { ports, w } = makePorts({ supp: { state: 'ok', value: rec({ global: true, persons: [Y], groups: ['a'] }) } });
  const r = await restoreSuppression(carried({ global: false, persons: [X], groups: ['family'] }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.equal(r.suppression, 'merged');
  assert.equal(r.pendingGlobalOff, false);
  assert.equal(okRec(w).global, true);
  assert.deepEqual(okRec(w).persons, [Y, X]);
  assert.deepEqual(okRec(w).groups, ['a', 'family']);
  assert.equal(w.pending.state, 'absent');
});

test('EXISTING readable record: nothing the device held is ever dropped and global never goes down (300 seeded cases)', async () => {
  let s = 777;
  const rnd = (n: number): number => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s % n; };
  const pool = ids(100, 10);
  const pick = (): string[] => pool.filter(() => rnd(2) === 0);
  for (let i = 0; i < 300; i += 1) {
    const held = rec({ global: rnd(2) === 0, persons: pick(), groups: ['a', 'b'].filter(() => rnd(2) === 0) });
    const { ports, w } = makePorts({ supp: { state: 'ok', value: held } });
    await restoreSuppression(carried({ global: rnd(2) === 0, persons: pick(), groups: ['b', 'c'].filter(() => rnd(2) === 0) }), { backupAt: AT, restoredAt: NOW }, ports);
    const out = okRec(w);
    for (const p of held.persons) assert.ok(out.persons.includes(p), `case ${i} lost a person`);
    for (const g of held.groups) assert.ok(out.groups.includes(g), `case ${i} lost a group`);
    if (held.global) assert.equal(out.global, true, `case ${i} loosened global`);
  }
});

test('an UNREADABLE record is never overwritten: no suppression write at all', async () => {
  const { ports, w, log } = makePorts({ supp: { state: 'unreadable' } });
  const r = await restoreSuppression(carried({ global: false, persons: [X] }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.equal(r.suppression, 'kept-unreadable');
  assert.equal(r.pendingGlobalOff, false);
  assert.deepEqual(w.supp, { state: 'unreadable' });
  assert.deepEqual(writes(log).filter((l) => l.startsWith('suppression') || l === 'writePending'), []);
});

// ── makeUpdate: the compare-and-swap loop itself ──────────────────────────────────────────────────────────────────────────────────────────────
/** A scripted store: each read returns the next scripted state with a fresh token; each commit answers from `verdicts` (default: refuse). */
function scripted(states: SealedRead<string>[], verdicts: boolean[] = []) {
  const calls = { reads: 0, commits: [] as { token: unknown; value: string }[] };
  const io = {
    read: async () => { const i = Math.min(calls.reads, states.length - 1); calls.reads += 1; return { token: `t${calls.reads}`, held: states[i] }; },
    commit: async (token: unknown, value: string) => { calls.commits.push({ token, value }); return verdicts[calls.commits.length - 1] ?? false; },
  };
  return { io, calls };
}

test('makeUpdate: a decision with no write returns its result and never commits', async () => {
  const { io, calls } = scripted([{ state: 'ok', value: 'a' }]);
  assert.equal(await makeUpdate<string>(io)((held) => ({ result: held.state })), 'ok');
  assert.equal(calls.reads, 1);
  assert.deepEqual(calls.commits, []);
});

test('makeUpdate: a commit is offered the token of the SAME read the decision was made on', async () => {
  const { io, calls } = scripted([{ state: 'ok', value: 'a' }], [true]);
  assert.equal(await makeUpdate<string>(io)((held) => ({ write: `${held.state === 'ok' ? held.value : '?'}+`, result: 'done' })), 'done');
  assert.deepEqual(calls.commits, [{ token: 't1', value: 'a+' }]);
});

test('makeUpdate: a lost comparison decides AGAIN on the newer record, and returns the result of the decision that committed', async () => {
  const { io, calls } = scripted([{ state: 'ok', value: 'old' }, { state: 'ok', value: 'new' }], [false, true]);
  const seen: string[] = [];
  const r = await makeUpdate<string>(io)((held) => { const v = held.state === 'ok' ? held.value : '?'; seen.push(v); return { write: `${v}+`, result: `result-of-${v}` }; });
  assert.deepEqual(seen, ['old', 'new']);
  assert.equal(r, 'result-of-new');
  assert.deepEqual(calls.commits, [{ token: 't1', value: 'old+' }, { token: 't2', value: 'new+' }], 'each commit carries its own read\'s token');
});

test('makeUpdate: bounded: the default is 5 attempts, a custom bound is honoured, and it throws with nothing committed', async () => {
  assert.equal(UPDATE_MAX_ATTEMPTS, 5);
  const five = scripted([{ state: 'ok', value: 'a' }]);
  await assert.rejects(() => makeUpdate<string>(five.io)(() => ({ write: 'x', result: 1 })), /changed too often while it was being updated; nothing was written/);
  assert.equal(five.calls.reads, 5);
  assert.equal(five.calls.commits.length, 5);
  const three = scripted([{ state: 'ok', value: 'a' }]);
  await assert.rejects(() => makeUpdate<string>(three.io, 3)(() => ({ write: 'x', result: 1 })), /nothing was written/);
  assert.equal(three.calls.commits.length, 3);
  const one = scripted([{ state: 'ok', value: 'a' }], [true]);
  assert.equal(await makeUpdate<string>(one.io, 1)(() => ({ write: 'x', result: 7 })), 7, 'a bound of 1 still commits when the first comparison holds');
});

test('makeUpdate: a write decided on an UNREADABLE record is refused before any commit, and a no-write decision on it is fine', async () => {
  const bad = scripted([{ state: 'unreadable' }], [true]);
  await assert.rejects(() => makeUpdate<string>(bad.io)(() => ({ write: 'x', result: 1 })), /Refusing to overwrite a sealed record that cannot be read/);
  assert.deepEqual(bad.calls.commits, []);
  const fine = scripted([{ state: 'unreadable' }]);
  assert.equal(await makeUpdate<string>(fine.io)((h) => ({ result: h.state })), 'unreadable');
});

test('makeUpdate: an error from the store propagates (nothing is swallowed into a retry)', async () => {
  const boom = { read: async () => { throw new Error('read failed'); }, commit: async () => true };
  await assert.rejects(() => makeUpdate<string>(boom)(() => ({ write: 'x', result: 1 })), /read failed/);
  const boom2 = { read: async () => ({ token: 1, held: { state: 'absent' } as SealedRead<string> }), commit: async () => { throw new Error('commit failed'); } };
  await assert.rejects(() => makeUpdate<string>(boom2)(() => ({ write: 'x', result: 1 })), /commit failed/);
});

// ── the lost update: every change is one atomic read-modify-write ───────────────────────────────────────────────────────────────────────────────
test('CONTROL: the old read-then-replace shape LOSES a write that lands in between (this harness can see the loss)', () => {
  const w: World = { supp: { state: 'ok', value: rec({ persons: [Y] }) }, removed: { state: 'absent' }, pending: { state: 'absent' }, vSupp: 0, vRemoved: 0 };
  const read = (w.supp as { value: SuppressionRecord }).value;      // 1. read
  const next = mergeByTightening(read, { v: 1, global: false, groups: [], persons: [X], removed: [] }); // 2. compute from that read
  landSupp(w, rec({ persons: [Y, Z] }));                              // 3. a second tab suppresses Z
  w.supp = { state: 'ok', value: next };                              // 4. replace
  assert.equal(okRec(w).persons.includes(Z), false, 'the concurrent suppression was overwritten: the loss the atomic shape must prevent');
});

test('a person suppressed in a second tab mid-restore is KEPT: the merge is decided again on the newer record', async () => {
  const { ports, w, log } = makePorts({
    supp: { state: 'ok', value: rec({ persons: [Y] }) },
    beforeCommit: once((world) => landSupp(world, rec({ persons: [Y, Z] }))),
  });
  const r = await restoreSuppression(carried({ persons: [X], groups: [] }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.equal(r.suppression, 'merged');
  assert.deepEqual(okRec(w).persons.slice().sort(), [X, Y, Z].sort(), 'the concurrent Z, the held Y and the carried X');
  assert.equal(log.filter((l) => l === 'suppression:read').length, 2, 'decided twice: once on the stale record, once on the newer');
  assert.ok(log.includes('suppression:conflict'));
});

test('a FRESH device whose record appears mid-restore is merged into, never replaced, and no marker is left', async () => {
  const { ports, w } = makePorts({ beforeCommit: once((world) => landSupp(world, rec({ global: false, persons: [Y] }))) });
  const r = await restoreSuppression(carried({ global: false, persons: [X], groups: [] }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.deepEqual(r, { suppression: 'merged', pendingGlobalOff: false, removed: 'none-nothing-new' });
  assert.deepEqual(okRec(w).persons.slice().sort(), [X, Y].sort());
  assert.equal(w.pending.state, 'absent', 'this device had its own record: nothing to wait for');
});

test('a FRESH device whose record appears mid-restore but cannot be read is left ALONE', async () => {
  const { ports, w, log } = makePorts({ beforeCommit: once((world) => { world.supp = { state: 'unreadable' }; world.vSupp += 1; }) });
  const r = await restoreSuppression(carried({ persons: [X] }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.equal(r.suppression, 'kept-unreadable');
  assert.deepEqual(w.supp, { state: 'unreadable' });
  assert.ok(!log.includes('suppression:write') && !log.includes('writePending'));
});

test('the confirmation keeps a person suppressed in a second tab between its read and its write', async () => {
  const { ports, w } = makePorts({
    supp: { state: 'ok', value: rec({ global: true, persons: [X] }) },
    pending: { state: 'ok', value: { v: 1, backup_at: AT, restored_at: NOW } },
    beforeCommit: once((world) => landSupp(world, rec({ global: true, persons: [X, Z] }))),
  });
  assert.equal(await confirmPendingGlobalOff(ports), 'confirmed');
  assert.equal(okRec(w).global, false);
  assert.deepEqual(okRec(w).persons.slice().sort(), [X, Z].sort(), 'Z, suppressed meanwhile, is still suppressed');
});

test('a Remove recorded while the removed list is being restored is KEPT', async () => {
  const { ports, w } = makePorts({
    removed: { state: 'ok', value: [Y] },
    beforeCommit: once((world) => landRemoved(world, [Y, Z])),
  });
  const r = await restoreSuppression(carried({ removed: [X] }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.equal(r.removed, 'written');
  assert.deepEqual(okRemoved(w).slice().sort(), [X, Y, Z].sort());
});

test('recordRemoval racing another Remove keeps both', async () => {
  const { ports, w } = makePorts({
    removed: { state: 'ok', value: [Y] },
    beforeCommit: once((world) => landRemoved(world, [Y, Z])),
  });
  assert.deepEqual(await recordRemoval(ports.updateRemoved, X), { kind: 'write', list: [Y, Z, X] });
  assert.deepEqual(okRemoved(w), [Y, Z, X]);
});

test('a record that keeps changing is abandoned after the bounded attempts with NOTHING written by the restore', async () => {
  let n = 0;
  const { ports, w } = makePorts({
    supp: { state: 'ok', value: rec({ persons: [Y] }) },
    beforeCommit: (name, _a, world) => { if (name === 'suppression') { n += 1; landSupp(world, rec({ persons: [Y, hex(100 + n)] })); } },
  });
  await assert.rejects(() => restoreSuppression(carried({ persons: [X] }), { backupAt: AT, restoredAt: NOW }, ports), /changed too often while it was being updated; nothing was written/);
  assert.equal(okRec(w).persons.includes(X), false, 'the restore wrote nothing of its own');
  assert.equal(w.pending.state, 'absent');
});

// ── the marker ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
test('the marker keeps only a plain ISO time; any other text becomes null', async () => {
  const bad = ['yesterday', 'x'.repeat(100), '2026-11-15', '2026-11-15T12:00:00+01:00', `${AT}\n`, ` ${AT}`, '2026-11-15T12:00:00.1234Z', 5, {}, [], null, undefined];
  for (const at of bad) {
    const { ports, w } = makePorts();
    await restoreSuppression(carried({ global: false }), { backupAt: at, restoredAt: NOW }, ports);
    assert.deepEqual(w.pending, { state: 'ok', value: { v: 1, backup_at: null, restored_at: NOW } }, JSON.stringify(at));
  }
  for (const ok of [AT, '2026-11-15T12:00:00Z', '2026-11-15T12:00:00.5Z']) {
    const { ports, w } = makePorts();
    await restoreSuppression(carried({ global: false }), { backupAt: ok, restoredAt: NOW }, ports);
    assert.deepEqual(w.pending, { state: 'ok', value: { v: 1, backup_at: ok, restored_at: NOW } });
  }
});

test('parsePendingGlobalOff: exact keys, v1, ISO time or null; everything else is unreadable', () => {
  assert.deepEqual(parsePendingGlobalOff({ v: 1, backup_at: AT, restored_at: NOW }), { v: 1, backup_at: AT, restored_at: NOW });
  assert.deepEqual(parsePendingGlobalOff({ v: 1, backup_at: null, restored_at: NOW }), { v: 1, backup_at: null, restored_at: NOW });
  for (const bad of [null, undefined, 0, 'x', [], {}, { v: 1 }, { backup_at: AT }, { v: 2, backup_at: AT, restored_at: NOW }, { v: '1', backup_at: AT, restored_at: NOW }, { v: 1, backup_at: AT, restored_at: NOW, extra: 1 }, { v: 1, backup_at: 'yesterday', restored_at: NOW }, { v: 1, backup_at: 5, restored_at: NOW }, { v: 1, backup_at: undefined, restored_at: NOW },
    { v: 1, backup_at: AT }, { v: 1, backup_at: null }, { v: 1, backup_at: AT, restored_at: null }, { v: 1, backup_at: AT, restored_at: 'today' }, { v: 1, backup_at: AT, restored_at: `${NOW}\n` }, { v: 1, backup_at: AT, restored_at: 5 }]) {
    assert.equal(parsePendingGlobalOff(bad), null, JSON.stringify(bad));
  }
});

test('parsePendingGlobalOff: an ARRAY that carries the right own properties is still refused (the keys check alone would pass it)', () => {
  const arr = Object.assign([], { v: 1, backup_at: null, restored_at: NOW });
  assert.deepEqual(Object.keys(arr), ['v', 'backup_at', 'restored_at'], 'the probe really has exactly the three keys');
  assert.equal(parsePendingGlobalOff(arr), null);
  assert.equal(parsePendingGlobalOff(Object.assign([], { v: 1, backup_at: AT, restored_at: NOW })), null);
});

test('the confirmation REFUSES without the marker, with an unreadable marker, or with an unreadable record, and writes nothing', async () => {
  const noMarker = makePorts({ supp: { state: 'ok', value: rec({ global: true, persons: [X] }) } });
  assert.equal(await confirmPendingGlobalOff(noMarker.ports), 'no-pending');
  assert.equal(okRec(noMarker.w).global, true, 'a screen calling confirm by mistake cannot turn global off');
  assert.deepEqual(writes(noMarker.log), []);

  const badMarker = makePorts({ supp: { state: 'ok', value: rec({ global: true }) }, pending: { state: 'unreadable' } });
  assert.equal(await confirmPendingGlobalOff(badMarker.ports), 'pending-unreadable');
  assert.deepEqual(writes(badMarker.log), []);

  for (const supp of [{ state: 'absent' }, { state: 'unreadable' }] as const) {
    const t = makePorts({ supp, pending: { state: 'ok', value: { v: 1, backup_at: AT, restored_at: NOW } } });
    assert.equal(await confirmPendingGlobalOff(t.ports), 'record-unreadable', supp.state);
    assert.deepEqual(writes(t.log), [], supp.state);
    assert.equal(t.w.pending.state, 'ok', 'the marker is kept');
  }
});

test('the confirmation changes the RECORD before it clears the marker, so a failure between them can be confirmed again', async () => {
  const t = makePorts({ supp: { state: 'ok', value: rec({ global: true, persons: [X] }) }, pending: { state: 'ok', value: { v: 1, backup_at: AT, restored_at: NOW } }, failOn: 'clearPending' });
  await assert.rejects(() => confirmPendingGlobalOff(t.ports), /clearPending failed/);
  assert.equal(okRec(t.w).global, false, 'the record was written first');
  assert.equal(t.w.pending.state, 'ok', 'the marker is still there');
  const again = makePorts({ supp: t.w.supp, pending: t.w.pending });
  assert.equal(await confirmPendingGlobalOff(again.ports), 'confirmed');
  assert.equal(again.w.pending.state, 'absent');
  assert.deepEqual(okRec(again.w).persons, [X]);
});

test('a failure writing the MARKER leaves the record written and dark: the person is never asked, and stays private', async () => {
  const t = makePorts({ failOn: 'writePending' });
  await assert.rejects(() => restoreSuppression(carried({ global: false, persons: [X] }), { backupAt: AT, restoredAt: NOW }, t.ports), /writePending failed/);
  assert.equal(okRec(t.w).global, true);
  assert.equal(suppressed(okRec(t.w), OTHER), true);
  assert.equal(t.w.pending.state, 'absent');
});

// ── restored_at: the DEVICE clock, never the file ─────────────────────────────────────────────────────────────────────────────────────────────
test('the marker carries restored_at from the DEVICE time the caller passes, and backup_at from the file as text', async () => {
  const { ports, w } = makePorts();
  await restoreSuppression(carried({ global: false }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.deepEqual(w.pending, { state: 'ok', value: { v: 1, backup_at: AT, restored_at: NOW } });
});

test('the file cannot set restored_at: a carried value naming it is refused whole, and a hostile backup_at changes nothing about it', async () => {
  const a = makePorts();
  const r = await restoreSuppression({ ...carried({ global: false }), restored_at: '2099-01-01T00:00:00.000Z' }, { backupAt: AT, restoredAt: NOW }, a.ports);
  assert.equal(r.suppression, 'none-no-carried-record');
  assert.equal(a.w.pending.state, 'absent');
  const b = makePorts();
  await restoreSuppression(carried({ global: false }), { backupAt: '2099-01-01T00:00:00.000Z', restoredAt: NOW }, b.ports);
  assert.deepEqual(b.w.pending, { state: 'ok', value: { v: 1, backup_at: '2099-01-01T00:00:00.000Z', restored_at: NOW } }, 'a future backup_at is kept as text (the SCREEN decides how to show it); restored_at is still the device time');
});

test('WITHOUT a valid device time no marker is written: the record is still written dark, and the person is simply never asked', async () => {
  for (const bad of [undefined, null, 0, 'now', '2026-11-16', `${NOW}\n`, {}, []]) {
    const { ports, w, log } = makePorts();
    const r = await restoreSuppression(carried({ global: false, persons: [X] }), { backupAt: AT, restoredAt: bad }, ports);
    assert.deepEqual(r, { suppression: 'written-fresh', pendingGlobalOff: false, removed: 'none-nothing-new' }, JSON.stringify(bad));
    assert.equal(okRec(w).global, true);
    assert.equal(w.pending.state, 'absent');
    assert.ok(!log.includes('writePending'));
  }
});

test('a LATER restore leaves an existing marker and its restored_at exactly as they were (the marker is about the earlier backup)', async () => {
  const earlier = { v: 1 as const, backup_at: AT, restored_at: '2026-11-10T08:00:00.000Z' };
  const { ports, w, log } = makePorts({ supp: { state: 'ok', value: rec({ global: true, persons: [X] }) }, pending: { state: 'ok', value: earlier } });
  const r = await restoreSuppression(carried({ global: false, persons: [Y] }), { backupAt: '2026-11-16T01:00:00.000Z', restoredAt: NOW }, ports);
  assert.equal(r.suppression, 'merged');
  assert.equal(r.pendingGlobalOff, false);
  assert.deepEqual(w.pending, { state: 'ok', value: earlier });
  assert.ok(!log.includes('writePending') && !log.includes('clearPending'));
});

// ── a newer "on" supersedes an older waiting "off" ──────────────────────────────────────────────────────────────────────────────────────
const EARLIER = { v: 1 as const, backup_at: AT, restored_at: '2026-11-10T08:00:00.000Z' };

test('S1 a later restore whose backup says global ON clears an earlier backup\'s waiting "off": it can no longer be confirmed', async () => {
  const { ports, w, log } = makePorts({ supp: { state: 'ok', value: rec({ global: true, persons: [X] }) }, pending: { state: 'ok', value: EARLIER } });
  const r = await restoreSuppression(carried({ global: true, persons: [Y] }), { backupAt: '2026-11-16T01:00:00.000Z', restoredAt: NOW }, ports);
  assert.equal(r.suppression, 'merged');
  assert.equal(r.pendingGlobalOff, false);
  assert.deepEqual(w.pending, { state: 'absent' });
  assert.equal(await confirmPendingGlobalOff(ports), 'no-pending', 'the older off is no longer confirmable');
  assert.equal(okRec(w).global, true);
  assert.ok(log.indexOf('clearPending') > log.lastIndexOf('suppression:write'), 'the marker is cleared AFTER the record is written');
});

test('S1 the same on a device with NO record: the fresh write happens, an old marker is cleared, and none is left', async () => {
  const { ports, w } = makePorts({ pending: { state: 'ok', value: EARLIER } });
  const r = await restoreSuppression(carried({ global: true }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.equal(r.suppression, 'written-fresh');
  assert.equal(r.pendingGlobalOff, false);
  assert.deepEqual(w.pending, { state: 'absent' });
});

test('S1 an UNREADABLE marker is cleared too (tightening), and a restore with no marker at all makes no clear call', async () => {
  const a = makePorts({ supp: { state: 'ok', value: rec({ global: true }) }, pending: { state: 'unreadable' } });
  await restoreSuppression(carried({ global: true }), { backupAt: AT, restoredAt: NOW }, a.ports);
  assert.deepEqual(a.w.pending, { state: 'absent' });
  const b = makePorts({ supp: { state: 'ok', value: rec({ global: true }) } });
  await restoreSuppression(carried({ global: true }), { backupAt: AT, restoredAt: NOW }, b.ports);
  assert.ok(!b.log.includes('clearPending'), 'nothing to clear, so no write');
});

test('S1 a backup that says global OFF still leaves an earlier marker exactly as it was (the existing rule holds)', async () => {
  const { ports, w } = makePorts({ supp: { state: 'ok', value: rec({ global: true }) }, pending: { state: 'ok', value: EARLIER } });
  await restoreSuppression(carried({ global: false }), { backupAt: AT, restoredAt: NOW }, ports);
  assert.deepEqual(w.pending, { state: 'ok', value: EARLIER });
});

test('S1 a failure clearing the marker leaves the record and the removed list WRITTEN and the marker still there (the person is asked, never loosened)', async () => {
  const { ports, w } = makePorts({ supp: { state: 'ok', value: rec({ global: true }) }, pending: { state: 'ok', value: EARLIER }, failOn: 'clearPending' });
  await assert.rejects(() => restoreSuppression(carried({ global: true, persons: [Y], removed: [Z] }), { backupAt: AT, restoredAt: NOW }, ports), /clearPending failed/);
  assert.ok(suppressed(okRec(w), Y), 'the record was written first');
  assert.deepEqual(okRemoved(w), [Z], 'and so was the removed list');
  assert.deepEqual(w.pending, { state: 'ok', value: EARLIER });
});

// ── what the export screen says ─────────────────────────────────────────────────────────────────────────────────────────────────────────
test('S2 suppressionCarryStatus: carried when the whole record can go; nothing-to-carry only when BOTH are absent (or the list is empty); everything else is left-out', () => {
  const ok = (v: SuppressionRecord): SealedRead<SuppressionRecord> => ({ state: 'ok', value: v });
  const list = (v: string[]): SealedRead<string[]> => ({ state: 'ok', value: v });
  const absent = { state: 'absent' } as const;
  const bad = { state: 'unreadable' } as const;
  assert.equal(suppressionCarryStatus(ok(rec({ persons: [X] })), absent), 'carried');
  assert.equal(suppressionCarryStatus(ok(rec()), list([Y])), 'carried');
  assert.equal(suppressionCarryStatus(absent, absent), 'nothing-to-carry');
  assert.equal(suppressionCarryStatus(absent, list([])), 'nothing-to-carry');
  assert.equal(suppressionCarryStatus(bad, absent), 'left-out', 'an unreadable record is not an absent one');
  assert.equal(suppressionCarryStatus(bad, list([])), 'left-out');
  assert.equal(suppressionCarryStatus(ok(rec({ persons: [X] })), bad), 'left-out', 'an unreadable removed list leaves everything out');
  assert.equal(suppressionCarryStatus(absent, bad), 'left-out');
  assert.equal(suppressionCarryStatus(absent, list([Y])), 'left-out', 'a Remove with no record cannot be carried');
  assert.equal(suppressionCarryStatus(ok(rec()), list(ids(100, CARRY_MAX_ENTRIES + 1))), 'left-out', 'over the cap is left out');
  assert.equal(suppressionCarryStatus(ok(rec()), list(ids(100, CARRY_MAX_ENTRIES))), 'carried', 'exactly the cap still goes');
});

test('S2 the status agrees with suppressionToCarry: carried exactly when it returns a value (400 seeded cases)', () => {
  let seed = 7;
  const next = (n: number): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
  const recs: SealedRead<SuppressionRecord>[] = [{ state: 'absent' }, { state: 'unreadable' }, { state: 'ok', value: rec({ persons: [X] }) }, { state: 'ok', value: rec({ global: true, groups: ['family'] }) }];
  const lists: SealedRead<string[]>[] = [{ state: 'absent' }, { state: 'unreadable' }, { state: 'ok', value: [] }, { state: 'ok', value: [Y] }, { state: 'ok', value: ids(1000, CARRY_MAX_ENTRIES + 1) }];
  for (let i = 0; i < 400; i++) {
    const r = recs[next(recs.length)]; const l = lists[next(lists.length)];
    const carriedValue = suppressionToCarry(r.state === 'ok' ? r.value : null, l);
    assert.equal(suppressionCarryStatus(r, l) === 'carried', carriedValue !== undefined, JSON.stringify([r.state, l.state]));
  }
});

// ── the removed list ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
test('removed: absent + carried writes the list; a readable list is unioned in order; nothing new writes nothing', async () => {
  const a = makePorts();
  assert.equal((await restoreSuppression(carried({ removed: [X, Y] }), { backupAt: AT, restoredAt: NOW }, a.ports)).removed, 'written');
  assert.deepEqual(a.w.removed, { state: 'ok', value: [X, Y] });

  const b = makePorts({ removed: { state: 'ok', value: [Y] } });
  assert.equal((await restoreSuppression(carried({ removed: [X, Y] }), { backupAt: AT, restoredAt: NOW }, b.ports)).removed, 'written');
  assert.deepEqual(b.w.removed, { state: 'ok', value: [Y, X] });

  const c = makePorts({ removed: { state: 'ok', value: [X, Y] } });
  assert.equal((await restoreSuppression(carried({ removed: [Y] }), { backupAt: AT, restoredAt: NOW }, c.ports)).removed, 'none-nothing-new');
  assert.ok(!c.log.includes('removed:write'));

  const d = makePorts();
  assert.equal((await restoreSuppression(carried({ removed: [] }), { backupAt: AT, restoredAt: NOW }, d.ports)).removed, 'none-nothing-new');
  assert.ok(!d.log.includes('removed:write'));
});

test('removed: an UNREADABLE stored list is never overwritten, and the suppression record is still handled', async () => {
  const t = makePorts({ removed: { state: 'unreadable' } });
  const r = await restoreSuppression(carried({ removed: [X] }), { backupAt: AT, restoredAt: NOW }, t.ports);
  assert.equal(r.removed, 'kept-unreadable');
  assert.equal(r.suppression, 'written-fresh');
  assert.deepEqual(t.w.removed, { state: 'unreadable' });
  assert.ok(!t.log.includes('removed:write'));
});

test('removed: an unreadable suppression record does not stop the removed list from being restored', async () => {
  const t = makePorts({ supp: { state: 'unreadable' } });
  const r = await restoreSuppression(carried({ removed: [X] }), { backupAt: AT, restoredAt: NOW }, t.ports);
  assert.equal(r.suppression, 'kept-unreadable');
  assert.equal(r.removed, 'written');
  assert.deepEqual(t.w.removed, { state: 'ok', value: [X] });
  assert.deepEqual(t.w.supp, { state: 'unreadable' });
});

test('removed: over the cap REFUSES and writes nothing; exactly the cap is fine', async () => {
  const over = makePorts({ removed: { state: 'ok', value: ids(1000, CARRY_MAX_ENTRIES) } });
  const r = await restoreSuppression(carried({ removed: [hex(1)] }), { backupAt: AT, restoredAt: NOW }, over.ports);
  assert.equal(r.removed, 'refused-too-large');
  assert.ok(!over.log.includes('removed:write'));
  assert.equal(r.suppression, 'written-fresh', 'the suppression record is unaffected by a refused list');

  const exact = makePorts({ removed: { state: 'ok', value: ids(1000, CARRY_MAX_ENTRIES - 1) } });
  assert.equal((await restoreSuppression(carried({ removed: [hex(1)] }), { backupAt: AT, restoredAt: NOW }, exact.ports)).removed, 'written');
  assert.equal(okRemoved(exact.w).length, CARRY_MAX_ENTRIES);
});

test('removed ids never enter the suppression record: a Remove is not a Block', async () => {
  const t = makePorts();
  await restoreSuppression(carried({ persons: [X], removed: [Y] }), { backupAt: AT, restoredAt: NOW }, t.ports);
  assert.deepEqual(okRec(t.w).persons, [X]);
  assert.deepEqual(t.w.removed, { state: 'ok', value: [Y] });
});

test('parseRemovedList: the strict reader for the stored list', () => {
  assert.deepEqual(parseRemovedList([]), []);
  assert.deepEqual(parseRemovedList([X, Y]), [X, Y]);
  const sparse: string[] = new Array(2); sparse[1] = X;
  const upper = hex(0xabc).toUpperCase();
  for (const bad of [null, undefined, 0, 'x', {}, [X, X], [upper], [X.slice(1)], [`${X} `], [5], [null], sparse, ids(1, CARRY_MAX_ENTRIES + 1)]) {
    assert.equal(parseRemovedList(bad), null, JSON.stringify(bad)?.slice(0, 40));
  }
  assert.equal(parseRemovedList(ids(1, CARRY_MAX_ENTRIES))?.length, CARRY_MAX_ENTRIES);
});

test('planRemovedAppend: records a Remove, and REFUSES (so the Remove fails) when it cannot be recorded', () => {
  assert.deepEqual(planRemovedAppend({ state: 'absent' }, X), { kind: 'write', list: [X] });
  assert.deepEqual(planRemovedAppend({ state: 'ok', value: [Y] }, X), { kind: 'write', list: [Y, X] });
  assert.deepEqual(planRemovedAppend({ state: 'ok', value: [X, Y] }, X), { kind: 'noop' });
  assert.deepEqual(planRemovedAppend({ state: 'unreadable' }, X), { kind: 'refuse', why: 'unreadable' });
  const upper = hex(0xabc).toUpperCase();
  for (const bad of ['', upper, X.slice(1), `${X}0`, ` ${X}`, 'not-hex', 5 as unknown as string, null as unknown as string]) {
    const helds: SealedRead<string[]>[] = [{ state: 'absent' }, { state: 'ok', value: [Y] }, { state: 'unreadable' }];
    for (const held of helds) {
      assert.deepEqual(planRemovedAppend(held, bad), { kind: 'refuse', why: 'bad-id' }, `${String(bad).slice(0, 12)} / ${held.state}`);
    }
  }
  const full = ids(1000, CARRY_MAX_ENTRIES);
  assert.deepEqual(planRemovedAppend({ state: 'ok', value: full }, X), { kind: 'refuse', why: 'too-large' });
  assert.deepEqual(planRemovedAppend({ state: 'ok', value: [...full.slice(1)] }, X), { kind: 'write', list: [...full.slice(1), X] });
  assert.deepEqual(planRemovedAppend({ state: 'ok', value: [...full, X].slice(1) }, X), { kind: 'noop' }, 'a full list that already holds the id is a no-op, not too-large');
});

test('recordRemoval: writes only when the plan is a write, and hands the plan back so the caller can fail the Remove', async () => {
  const a = makePorts();
  assert.deepEqual(await recordRemoval(a.ports.updateRemoved, X), { kind: 'write', list: [X] });
  assert.deepEqual(a.w.removed, { state: 'ok', value: [X] });
  assert.deepEqual(await recordRemoval(a.ports.updateRemoved, X), { kind: 'noop' });
  assert.equal(a.log.filter((l) => l === 'removed:write').length, 1);

  const u = makePorts({ removed: { state: 'unreadable' } });
  assert.deepEqual(await recordRemoval(u.ports.updateRemoved, X), { kind: 'refuse', why: 'unreadable' });
  assert.deepEqual(u.w.removed, { state: 'unreadable' });
  assert.ok(!u.log.includes('removed:write'));
  assert.deepEqual(await recordRemoval(u.ports.updateRemoved, 'nope'), { kind: 'refuse', why: 'bad-id' });
});

test('removalRefusal: a sentence only for a refused Remove, so the caller throws and the Remove fails; a write or a no-op is silent', () => {
  for (const why of ['bad-id', 'unreadable', 'too-large'] as const) {
    const msg = removalRefusal({ kind: 'refuse', why });
    assert.ok(msg !== null && msg.includes(why) && /no latch is written/.test(msg), why);
  }
  assert.equal(removalRefusal({ kind: 'write', list: [X] }), null);
  assert.equal(removalRefusal({ kind: 'noop' }), null);
});

test('suppressionToCarry: ALL or nothing: an unreadable removed list, or a record that cannot be carried, carries NOTHING; an absent list is an empty one', () => {
  const r = rec({ global: true, persons: [X], groups: ['family'] });
  assert.deepEqual(suppressionToCarry(r, { state: 'ok', value: [Y] }), { v: 1, global: true, groups: ['family'], persons: [X], removed: [Y] });
  assert.deepEqual(suppressionToCarry(r, { state: 'absent' }), { v: 1, global: true, groups: ['family'], persons: [X], removed: [] });
  assert.equal(suppressionToCarry(r, { state: 'unreadable' }), undefined, 'the record is not carried without the list that goes with it');
  assert.equal(suppressionToCarry(null, { state: 'ok', value: [Y] }), undefined, 'an unreadable or absent record is omitted, so a restore stays dark');
  assert.equal(suppressionToCarry(rec({ persons: ['NOT-HEX'] }), { state: 'absent' }), undefined, 'a record the strict parser would refuse is omitted, never cleaned');
  assert.equal(suppressionToCarry(r, { state: 'ok', value: ids(1, CARRY_MAX_ENTRIES + 1) }), undefined, 'an oversize list is omitted, never truncated');
});

// ── the owner's own choice (settings panel): show up / stay out ───────────────────────────────────────────────────────────────────────────────────────────
const MARKER: SealedRead<PendingGlobalOff> = { state: 'ok', value: { v: 1, backup_at: AT, restored_at: NOW } };
const listed = (): SuppressionRecord => rec({ global: true, persons: [X], groups: ['family'] });

test('OWNER show up: only global goes OFF; a blocked person and a group stay suppressed; the record is written BEFORE the marker is cleared', async () => {
  const { ports, w, log } = makePorts({ supp: { state: 'ok', value: listed() }, pending: MARKER });
  assert.equal(await setOwnerGlobalVisible(ports, true), 'set');
  assert.deepEqual(okRec(w), { global: false, groups: ['family'], persons: [X] }, 'persons and groups exactly as they were');
  assert.equal(suppressed(okRec(w), X), true, 'the blocked person stays suppressed');
  assert.equal(isPartySuppressed(okRec(w), { durableId: OTHER, groupIds: ['family'] }), true, 'and so does the group');
  assert.equal(suppressed(okRec(w), OTHER), false, 'an unlisted person is no longer suppressed by global');
  assert.deepEqual(w.pending, { state: 'absent' }, 'the waiting offer is gone');
  assert.deepEqual(writes(log), ['suppression:write', 'clearPending'], 'record first, then the marker');
});

test('OWNER stay out: the marker is cleared FIRST, then global goes ON; persons and groups untouched; a later confirm finds nothing to confirm and cannot flip them visible', async () => {
  const { ports, w, log } = makePorts({ supp: { state: 'ok', value: rec({ global: false, persons: [X], groups: ['family'] }) }, pending: MARKER });
  assert.equal(await setOwnerGlobalVisible(ports, false), 'set');
  assert.deepEqual(okRec(w), { global: true, groups: ['family'], persons: [X] });
  assert.deepEqual(w.pending, { state: 'absent' });
  assert.deepEqual(writes(log), ['clearPending', 'suppression:write'], 'marker first, then the record');
  assert.equal(await confirmPendingGlobalOff(ports), 'no-pending', 'the restore confirmation has nothing left to apply');
  assert.equal(okRec(w).global, true, 'so it cannot turn them visible against their explicit choice');
});

test('OWNER refuses an ABSENT or UNREADABLE record in BOTH directions: nothing is written, the marker is left alone', async () => {
  for (const supp of [{ state: 'absent' }, { state: 'unreadable' }] as const) {
    for (const visible of [true, false]) {
      const { ports, w, log } = makePorts({ supp, pending: MARKER });
      assert.equal(await setOwnerGlobalVisible(ports, visible), 'refused', `${supp.state} / visible=${visible}`);
      assert.deepEqual(w.supp, supp, 'the record is exactly as it was (never created, never overwritten)');
      assert.deepEqual(w.pending, MARKER, 'the marker is untouched');
      assert.deepEqual(writes(log), [], 'no write of any kind');
    }
  }
});

test('OWNER already in the chosen state: no record write, the marker is still cleared', async () => {
  for (const visible of [true, false]) {
    const { ports, w, log } = makePorts({ supp: { state: 'ok', value: rec({ global: !visible, persons: [X] }) }, pending: MARKER });
    assert.equal(await setOwnerGlobalVisible(ports, visible), 'set');
    assert.deepEqual(writes(log), ['clearPending'], 'only the marker');
    assert.deepEqual(w.pending, { state: 'absent' });
    assert.deepEqual(okRec(w), rec({ global: !visible, persons: [X] }));
  }
});

test('OWNER failure lands on the private side: show up + a failed marker clear leaves the record changed and the offer standing (re-confirmable); stay out + a failed marker clear changes NOTHING', async () => {
  const up = makePorts({ supp: { state: 'ok', value: listed() }, pending: MARKER, failOn: 'clearPending' });
  await assert.rejects(setOwnerGlobalVisible(up.ports, true), /clearPending failed/);
  assert.equal(okRec(up.w).global, false, 'show up: the record was written first');
  assert.deepEqual(up.w.pending, MARKER, 'and the offer still matches the choice');
  const later = makePorts({ supp: up.w.supp, pending: up.w.pending }); // the same stored state, on a store that is working again
  assert.equal(await confirmPendingGlobalOff(later.ports), 'confirmed', 'so it can be confirmed again, idempotently');
  assert.equal(okRec(later.w).global, false);
  assert.deepEqual(later.w.pending, { state: 'absent' });

  const out = makePorts({ supp: { state: 'ok', value: rec({ global: false, persons: [X] }) }, pending: MARKER, failOn: 'clearPending' });
  await assert.rejects(setOwnerGlobalVisible(out.ports, false), /clearPending failed/);
  assert.equal(okRec(out.w).global, false, 'stay out: the marker is cleared first, so a failure there writes nothing');
  assert.deepEqual(out.w.pending, MARKER);
});

test('OWNER a write that lands between the read and the commit is kept: the choice is decided again on the newer record (a new Block is never lost)', async () => {
  const { ports, w } = makePorts({
    supp: { state: 'ok', value: rec({ global: true, persons: [X] }) },
    pending: MARKER,
    beforeCommit: once((world) => landSupp(world, rec({ global: true, persons: [X, Y] }))),
  });
  assert.equal(await setOwnerGlobalVisible(ports, true), 'set');
  assert.deepEqual(okRec(w), { global: false, groups: [], persons: [X, Y] }, 'the newer Block on Y survived');
});

// ── static pins ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const SRC = join(process.cwd(), 'src', 'lib', 'trust', 'suppression-restore.ts');

test('PURE pin: imports only ./suppression (type) and ./suppression-carry, and touches no storage, clock or randomness', () => {
  const text = readFileSync(SRC, 'utf8');
  const imports = [...text.matchAll(/^import\s[^;]*?from\s+'([^']+)'/gm)].map((m) => m[1]);
  assert.deepEqual(imports, ['./suppression', './suppression-carry']);
  assert.match(text, /^import type \{ SuppressionRecord \} from '\.\/suppression';$/m, 'a type-only import: no runtime dependency on the store');
  const code = text.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
  for (const banned of ['Date.now', 'new Date', 'Math.random', 'crypto.', 'indexedDB', 'localStorage', 'fetch(']) assert.ok(!code.includes(banned), `uses ${banned}`);
});

test('PORT pin: the unguarded read-then-replace forms are not in the port, so they cannot be called', () => {
  const code = readFileSync(SRC, 'utf8').split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
  const port = code.slice(code.indexOf('export interface RestorePorts'), code.indexOf('}', code.indexOf('export interface RestorePorts')));
  assert.match(port, /updateSuppression: Update<SuppressionRecord>;/);
  assert.match(port, /updateRemoved: Update<string\[\]>;/);
  for (const gone of ['replaceSuppression', 'writeSuppressionIfAbsent', 'writeRemoved', 'readSuppression', 'readRemoved']) assert.ok(!port.includes(gone), `${gone} is still in the port`);
  assert.ok(!/ports\.(replace|write)(Suppression|Removed)/.test(code), 'no call to an unguarded write');
});

test('PIECE-2 pin: the module never mentions the mutual-block live gate', () => {
  assert.ok(!readFileSync(SRC, 'utf8').includes('isPiece2MutualBlockLive'));
});

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === '.next' || name.startsWith('.')) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (/\.(ts|tsx|mts|js|jsx|mjs)$/.test(name)) out.push(p);
  }
  return out;
}

test('WIRING pin: the non-test importers of suppression-restore are the identity store (the storage under it), the block path, the latch repair and the genesis hook (types only)', () => {
  const roots = ['src', 'app'].map((d) => join(process.cwd(), d)).filter((d) => { try { return statSync(d).isDirectory(); } catch { return false; } });
  assert.ok(roots.length >= 1);
  const importers = roots.flatMap((r) => walk(r)).filter((f) => !/\.test\.[a-z]+$/.test(f) && !f.endsWith('suppression-restore.ts') && /suppression-restore/.test(readFileSync(f, 'utf8')));
  assert.deepEqual(importers.map((f) => f.slice(f.indexOf('/src/') + 1)).sort(), ['src/lib/identity/client-store.ts', 'src/lib/trust/block-latch.ts', 'src/lib/trust/block-suppression.ts', 'src/lib/trust/piece2-genesis.ts', 'src/lib/trust/readd-removed.ts']);      // CHANGED ON PURPOSE: genesis takes the update's TYPES now
  const block = readFileSync(join(process.cwd(), 'src', 'lib', 'trust', 'block-suppression.ts'), 'utf8');
  assert.match(block, /^import type \{ Decision, SealedRead, Update \} from '@\/lib\/trust\/suppression-restore';$/m, 'the block path takes only TYPES from the restore module: no runtime dependency');
  // The add-back drop needs the strict list parser (a runtime value: only a canonical id can be on the list) and the types; nothing else from the restore module.
  const readd = readFileSync(join(process.cwd(), 'src', 'lib', 'trust', 'readd-removed.ts'), 'utf8');
  assert.match(readd, /^import \{ parseRemovedList, type SealedRead, type Update \} from '\.\/suppression-restore';$/m, 'the add-back drop takes only the list parser and two types from the restore module');
  const latch = readFileSync(join(process.cwd(), 'src', 'lib', 'trust', 'block-latch.ts'), 'utf8');
  assert.match(latch, /^import type \{ Update \} from '@\/lib\/trust\/suppression-restore';$/m, 'the latch repair takes only the Update TYPE from the restore module: no runtime dependency');
});
