// src/lib/trust/suppression-restore.test.ts
// ADVERSARIAL gate for what a restore does with a carried suppression record. Refutes the ways it could LOOSEN suppression or overwrite what it did not read:
//   - a fresh device gets the carried persons and groups with global ON whatever the backup said; a backup's global-off waits for the person's confirmation,
//   - a readable record is only ever tightened; an UNREADABLE one is never overwritten; a lost race falls back to a merge, never a replace,
//   - nothing carried, or a malformed value, touches no port at all,
//   - the confirmation needs the marker the restore left and cannot half-apply,
//   - the removed list unions, refuses over the cap and never overwrites an unreadable list,
//   - the module is PURE (imports only ./suppression types and ./suppression-carry) and DARK (nothing outside tests imports it).
// Run: npx tsx --test src/lib/trust/suppression-restore.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  confirmPendingGlobalOff,
  parsePendingGlobalOff,
  parseRemovedList,
  planRemovedAppend,
  restoreSuppression,
  type PendingGlobalOff,
  type RestorePorts,
  type SealedRead,
} from '@/lib/trust/suppression-restore';
import { CARRY_MAX_ENTRIES } from '@/lib/trust/suppression-carry';
import { isPartySuppressed, type SuppressionRecord } from '@/lib/trust/suppression';

const hex = (n: number): string => n.toString(16).padStart(64, '0');
const X = hex(1);
const Y = hex(2);
const OTHER = hex(3);
const AT = '2026-11-15T12:00:00.000Z';
const carried = (over: Record<string, unknown> = {}): Record<string, unknown> => ({ v: 1, global: false, groups: ['family'], persons: [X], removed: [], ...over });
const rec = (over: Partial<SuppressionRecord> = {}): SuppressionRecord => ({ global: false, groups: [], persons: [], ...over });
const suppressed = (r: SuppressionRecord | null, id: string): boolean => isPartySuppressed(r, { durableId: id });

interface World {
  supp: SealedRead<SuppressionRecord>;
  removed: SealedRead<string[]>;
  pending: SealedRead<PendingGlobalOff>;
}
interface Opts {
  supp?: SealedRead<SuppressionRecord>;
  removed?: SealedRead<string[]>;
  pending?: SealedRead<PendingGlobalOff>;
  /** The next put-if-absent loses a race: another writer's value is already there. */
  race?: SealedRead<SuppressionRecord>;
  failOn?: 'writePending' | 'clearPending' | 'replaceSuppression';
}

function makePorts(o: Opts = {}): { ports: RestorePorts; w: World; log: string[] } {
  const w: World = { supp: o.supp ?? { state: 'absent' }, removed: o.removed ?? { state: 'absent' }, pending: o.pending ?? { state: 'absent' } };
  const log: string[] = [];
  let raced = false;
  const fail = (name: string) => { if (o.failOn === name) throw new Error(`${name} failed (simulated)`); };
  const ports: RestorePorts = {
    readSuppression: async () => { log.push('readSuppression'); return w.supp; },
    writeSuppressionIfAbsent: async (r) => {
      log.push('writeSuppressionIfAbsent');
      if (o.race && !raced) { raced = true; w.supp = o.race; return false; }
      if (w.supp.state !== 'absent') return false;
      w.supp = { state: 'ok', value: r };
      return true;
    },
    replaceSuppression: async (r) => { log.push('replaceSuppression'); fail('replaceSuppression'); w.supp = { state: 'ok', value: r }; },
    readRemoved: async () => { log.push('readRemoved'); return w.removed; },
    writeRemoved: async (l) => { log.push('writeRemoved'); w.removed = { state: 'ok', value: l }; },
    readPending: async () => { log.push('readPending'); return w.pending; },
    writePending: async (p) => { log.push('writePending'); fail('writePending'); w.pending = { state: 'ok', value: p }; },
    clearPending: async () => { log.push('clearPending'); fail('clearPending'); w.pending = { state: 'absent' }; },
  };
  return { ports, w, log };
}
const writes = (log: string[]): string[] => log.filter((l) => /^(write|replace|clear)/.test(l));
const okRec = (w: World): SuppressionRecord => { assert.equal(w.supp.state, 'ok'); return (w.supp as { value: SuppressionRecord }).value; };

test('nothing carried, or a value the strict parser refuses, touches NO port at all', async () => {
  for (const bad of [undefined, null, 0, 'x', [], {}, carried({ v: 2 }), carried({ persons: ['nope'] }), carried({ extra: 1 }), carried({ global: 'false' })]) {
    const { ports, log } = makePorts();
    const r = await restoreSuppression(bad, AT, ports);
    assert.deepEqual(r, { suppression: 'none-no-carried-record', pendingGlobalOff: false, removed: 'none-no-carried-record' });
    assert.deepEqual(log, [], `a port was touched for ${JSON.stringify(bad)}`);
  }
});

test('FRESH device, backup said global OFF: persons and groups written at once, global stays ON, the confirmation is left waiting', async () => {
  const { ports, w, log } = makePorts();
  const r = await restoreSuppression(carried({ global: false, persons: [X], groups: ['family'] }), AT, ports);
  assert.deepEqual(r, { suppression: 'written-fresh', pendingGlobalOff: true, removed: 'none-nothing-new' });
  assert.deepEqual(okRec(w), { global: true, groups: ['family'], persons: [X] });
  assert.equal(suppressed(okRec(w), X), true);
  assert.equal(suppressed(okRec(w), OTHER), true, 'still dark for everyone else until the person confirms');
  assert.deepEqual(w.pending, { state: 'ok', value: { v: 1, backup_at: AT } });
  assert.ok(log.indexOf('writeSuppressionIfAbsent') < log.indexOf('writePending'), 'the record is written BEFORE the marker');
});

test('FRESH device, backup said global ON: written, and NO confirmation is left (nothing to wait for)', async () => {
  const { ports, w, log } = makePorts();
  const r = await restoreSuppression(carried({ global: true }), AT, ports);
  assert.equal(r.suppression, 'written-fresh');
  assert.equal(r.pendingGlobalOff, false);
  assert.equal(okRec(w).global, true);
  assert.equal(w.pending.state, 'absent');
  assert.ok(!log.includes('writePending'));
});

test('the confirmation: global goes OFF, the carried person stays suppressed, the marker is cleared', async () => {
  const { ports, w } = makePorts();
  await restoreSuppression(carried({ global: false, persons: [X] }), AT, ports);
  assert.equal(await confirmPendingGlobalOff(ports), 'confirmed');
  assert.equal(okRec(w).global, false);
  assert.equal(suppressed(okRec(w), X), true, 'x is still suppressed');
  assert.equal(suppressed(okRec(w), OTHER), false, 'discoverable to the rest after the confirm');
  assert.equal(w.pending.state, 'absent');
});

test('EXISTING readable record: global TRUE stays TRUE under a carried global false; entries only added', async () => {
  const { ports, w } = makePorts({ supp: { state: 'ok', value: rec({ global: true, persons: [Y], groups: ['a'] }) } });
  const r = await restoreSuppression(carried({ global: false, persons: [X], groups: ['family'] }), AT, ports);
  assert.equal(r.suppression, 'merged');
  assert.equal(r.pendingGlobalOff, false);
  assert.equal(okRec(w).global, true);
  assert.deepEqual(okRec(w).persons, [Y, X]);
  assert.deepEqual(okRec(w).groups, ['a', 'family']);
  assert.equal(w.pending.state, 'absent');
});

test('EXISTING readable record: a carried global ON turns it on; nothing the device held is ever dropped (300 seeded cases)', async () => {
  let s = 777;
  const rnd = (n: number): number => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s % n; };
  const pool = Array.from({ length: 10 }, (_, i) => hex(100 + i));
  const pick = (): string[] => pool.filter(() => rnd(2) === 0);
  for (let i = 0; i < 300; i += 1) {
    const held = rec({ global: rnd(2) === 0, persons: pick(), groups: ['a', 'b'].filter(() => rnd(2) === 0) });
    const { ports, w } = makePorts({ supp: { state: 'ok', value: held } });
    await restoreSuppression(carried({ global: rnd(2) === 0, persons: pick(), groups: ['b', 'c'].filter(() => rnd(2) === 0) }), AT, ports);
    const out = okRec(w);
    for (const p of held.persons) assert.ok(out.persons.includes(p), `case ${i} lost a person`);
    for (const g of held.groups) assert.ok(out.groups.includes(g), `case ${i} lost a group`);
    if (held.global) assert.equal(out.global, true, `case ${i} loosened global`);
  }
});

test('an UNREADABLE record is never overwritten: no suppression write at all', async () => {
  const { ports, w, log } = makePorts({ supp: { state: 'unreadable' } });
  const r = await restoreSuppression(carried({ global: false, persons: [X] }), AT, ports);
  assert.equal(r.suppression, 'kept-unreadable');
  assert.equal(r.pendingGlobalOff, false);
  assert.deepEqual(w.supp, { state: 'unreadable' });
  assert.ok(!log.includes('writeSuppressionIfAbsent') && !log.includes('replaceSuppression') && !log.includes('writePending'), `wrote: ${writes(log).join(',')}`);
});

test('a LOST RACE merges into what the other writer put there, and never replaces it with the fresh record', async () => {
  const other = rec({ global: true, persons: [Y] });
  const { ports, w, log } = makePorts({ race: { state: 'ok', value: other } });
  const r = await restoreSuppression(carried({ global: false, persons: [X] }), AT, ports);
  assert.equal(r.suppression, 'merged-after-race');
  assert.equal(r.pendingGlobalOff, false);
  assert.deepEqual(okRec(w).persons, [Y, X]);
  assert.equal(okRec(w).global, true, 'the other writer\'s global ON is kept');
  assert.ok(log.includes('replaceSuppression'));
  assert.equal(w.pending.state, 'absent', 'no marker: this device already had its own record');
});

test('a lost race whose winner cannot be read is left ALONE', async () => {
  const { ports, w, log } = makePorts({ race: { state: 'unreadable' } });
  const r = await restoreSuppression(carried({ persons: [X] }), AT, ports);
  assert.equal(r.suppression, 'race-unreadable');
  assert.deepEqual(w.supp, { state: 'unreadable' });
  assert.ok(!log.includes('replaceSuppression') && !log.includes('writePending'));
});

test('the marker keeps only a plain ISO time; any other text becomes null', async () => {
  const bad = ['yesterday', 'x'.repeat(100), '2026-11-15', '2026-11-15T12:00:00+01:00', `${AT}\n`, ` ${AT}`, '2026-11-15T12:00:00.1234Z', 5, {}, [], null, undefined];
  for (const at of bad) {
    const { ports, w } = makePorts();
    await restoreSuppression(carried({ global: false }), at, ports);
    assert.deepEqual(w.pending, { state: 'ok', value: { v: 1, backup_at: null } }, JSON.stringify(at));
  }
  for (const ok of [AT, '2026-11-15T12:00:00Z', '2026-11-15T12:00:00.5Z']) {
    const { ports, w } = makePorts();
    await restoreSuppression(carried({ global: false }), ok, ports);
    assert.deepEqual(w.pending, { state: 'ok', value: { v: 1, backup_at: ok } });
  }
});

test('parsePendingGlobalOff: exact keys, v1, ISO time or null; everything else is unreadable', () => {
  assert.deepEqual(parsePendingGlobalOff({ v: 1, backup_at: AT }), { v: 1, backup_at: AT });
  assert.deepEqual(parsePendingGlobalOff({ v: 1, backup_at: null }), { v: 1, backup_at: null });
  for (const bad of [null, undefined, 0, 'x', [], {}, { v: 1 }, { backup_at: AT }, { v: 2, backup_at: AT }, { v: '1', backup_at: AT }, { v: 1, backup_at: AT, extra: 1 }, { v: 1, backup_at: 'yesterday' }, { v: 1, backup_at: 5 }, { v: 1, backup_at: undefined }]) {
    assert.equal(parsePendingGlobalOff(bad), null, JSON.stringify(bad));
  }
});

test('parsePendingGlobalOff: an ARRAY that carries the right own properties is still refused (the keys check alone would pass it)', () => {
  const arr = Object.assign([], { v: 1, backup_at: null });
  assert.deepEqual(Object.keys(arr), ['v', 'backup_at'], 'the probe really has exactly the two keys');
  assert.equal(parsePendingGlobalOff(arr), null);
  assert.equal(parsePendingGlobalOff(Object.assign([], { v: 1, backup_at: AT })), null);
});

test('parseRemovedList: the strict reader for the stored list', () => {
  assert.deepEqual(parseRemovedList([]), []);
  assert.deepEqual(parseRemovedList([X, Y]), [X, Y]);
  const sparse: string[] = new Array(2); sparse[1] = X;
  const upper = hex(0xabc).toUpperCase();
  for (const bad of [null, undefined, 0, 'x', {}, [X, X], [upper], [X.slice(1)], [`${X} `], [5], [null], sparse, Array.from({ length: CARRY_MAX_ENTRIES + 1 }, (_, i) => hex(i + 1))]) {
    assert.equal(parseRemovedList(bad), null, JSON.stringify(bad)?.slice(0, 40));
  }
  assert.equal(parseRemovedList(Array.from({ length: CARRY_MAX_ENTRIES }, (_, i) => hex(i + 1)))?.length, CARRY_MAX_ENTRIES);
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
  const full = Array.from({ length: CARRY_MAX_ENTRIES }, (_, i) => hex(i + 1000));
  assert.deepEqual(planRemovedAppend({ state: 'ok', value: full }, X), { kind: 'refuse', why: 'too-large' });
  assert.deepEqual(planRemovedAppend({ state: 'ok', value: [...full.slice(1)] }, X), { kind: 'write', list: [...full.slice(1), X] });
  assert.deepEqual(planRemovedAppend({ state: 'ok', value: [...full, X].slice(1) }, X), { kind: 'noop' }, 'a full list that already holds the id is a no-op, not too-large');
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
    const t = makePorts({ supp, pending: { state: 'ok', value: { v: 1, backup_at: AT } } });
    assert.equal(await confirmPendingGlobalOff(t.ports), 'record-unreadable', supp.state);
    assert.deepEqual(writes(t.log), [], supp.state);
    assert.equal(t.w.pending.state, 'ok', 'the marker is kept');
  }
});

test('the confirmation writes the RECORD before it clears the marker, so a failure between them can be confirmed again', async () => {
  const t = makePorts({ supp: { state: 'ok', value: rec({ global: true, persons: [X] }) }, pending: { state: 'ok', value: { v: 1, backup_at: AT } }, failOn: 'clearPending' });
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
  await assert.rejects(() => restoreSuppression(carried({ global: false, persons: [X] }), AT, t.ports), /writePending failed/);
  assert.equal(okRec(t.w).global, true);
  assert.equal(suppressed(okRec(t.w), OTHER), true);
  assert.equal(t.w.pending.state, 'absent');
});

test('removed: absent + carried writes the list; a readable list is unioned in order; nothing new writes nothing', async () => {
  const a = makePorts();
  assert.equal((await restoreSuppression(carried({ removed: [X, Y] }), AT, a.ports)).removed, 'written');
  assert.deepEqual(a.w.removed, { state: 'ok', value: [X, Y] });

  const b = makePorts({ removed: { state: 'ok', value: [Y] } });
  assert.equal((await restoreSuppression(carried({ removed: [X, Y] }), AT, b.ports)).removed, 'written');
  assert.deepEqual(b.w.removed, { state: 'ok', value: [Y, X] });

  const c = makePorts({ removed: { state: 'ok', value: [X, Y] } });
  assert.equal((await restoreSuppression(carried({ removed: [Y] }), AT, c.ports)).removed, 'none-nothing-new');
  assert.ok(!c.log.includes('writeRemoved'));

  const d = makePorts();
  assert.equal((await restoreSuppression(carried({ removed: [] }), AT, d.ports)).removed, 'none-nothing-new');
  assert.ok(!d.log.includes('writeRemoved'));
});

test('removed: an UNREADABLE stored list is never overwritten, and the suppression record is still handled', async () => {
  const t = makePorts({ removed: { state: 'unreadable' } });
  const r = await restoreSuppression(carried({ removed: [X] }), AT, t.ports);
  assert.equal(r.removed, 'kept-unreadable');
  assert.equal(r.suppression, 'written-fresh');
  assert.deepEqual(t.w.removed, { state: 'unreadable' });
  assert.ok(!t.log.includes('writeRemoved'));
});

test('removed: an unreadable suppression record does not stop the removed list from being restored', async () => {
  const t = makePorts({ supp: { state: 'unreadable' } });
  const r = await restoreSuppression(carried({ removed: [X] }), AT, t.ports);
  assert.equal(r.suppression, 'kept-unreadable');
  assert.equal(r.removed, 'written');
  assert.deepEqual(t.w.removed, { state: 'ok', value: [X] });
  assert.deepEqual(t.w.supp, { state: 'unreadable' });
});

test('removed: over the cap REFUSES and writes nothing; exactly the cap is fine', async () => {
  const ids = (from: number, n: number): string[] => Array.from({ length: n }, (_, i) => hex(from + i));
  const over = makePorts({ removed: { state: 'ok', value: ids(1000, CARRY_MAX_ENTRIES) } });
  const r = await restoreSuppression(carried({ removed: [hex(1)] }), AT, over.ports);
  assert.equal(r.removed, 'refused-too-large');
  assert.ok(!over.log.includes('writeRemoved'));
  assert.equal(r.suppression, 'written-fresh', 'the suppression record is unaffected by a refused list');

  const exact = makePorts({ removed: { state: 'ok', value: ids(1000, CARRY_MAX_ENTRIES - 1) } });
  assert.equal((await restoreSuppression(carried({ removed: [hex(1)] }), AT, exact.ports)).removed, 'written');
  assert.equal((exact.w.removed as { value: string[] }).value.length, CARRY_MAX_ENTRIES);
});

test('removed ids never enter the suppression record: a Remove is not a Block', async () => {
  const t = makePorts();
  await restoreSuppression(carried({ persons: [X], removed: [Y] }), AT, t.ports);
  assert.deepEqual(okRec(t.w).persons, [X]);
  assert.deepEqual(t.w.removed, { state: 'ok', value: [Y] });
});

// ── static pins ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const SRC = join(process.cwd(), 'src', 'lib', 'trust', 'suppression-restore.ts');

test('PURE pin: imports only ./suppression (type) and ./suppression-carry, and touches no storage, clock or randomness', () => {
  const text = readFileSync(SRC, 'utf8');
  const imports = [...text.matchAll(/^import\s[^;]*?from\s+'([^']+)'/gm)].map((m) => m[1]);
  assert.deepEqual(imports, ['./suppression', './suppression-carry']);
  assert.match(text, /^import type \{ SuppressionRecord \} from '\.\/suppression';$/m, 'a type-only import: no runtime dependency on the store');
  const code = text.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
  for (const banned of ['Date.now', 'new Date', 'Math.random', 'crypto.', 'indexedDB', 'localStorage', 'fetch(']) assert.ok(!code.includes(banned), `uses ${banned}`);
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

test('DARK pin: nothing outside tests imports suppression-restore', () => {
  const roots = ['src', 'app'].map((d) => join(process.cwd(), d)).filter((d) => { try { return statSync(d).isDirectory(); } catch { return false; } });
  assert.ok(roots.length >= 1);
  const importers = roots.flatMap((r) => walk(r)).filter((f) => !/\.test\.[a-z]+$/.test(f) && !f.endsWith('suppression-restore.ts') && /suppression-restore/.test(readFileSync(f, 'utf8')));
  assert.deepEqual(importers, []);
});
