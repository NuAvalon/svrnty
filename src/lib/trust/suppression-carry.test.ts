// src/lib/trust/suppression-carry.test.ts
// ADVERSARIAL gate for the pure restore-carry of the suppression record (and the removed list). Refutes the ways a restore could LOOSEN suppression:
//   - the strict parser refuses (never normalises) every malformed, partial, oversize or duplicated shape,
//   - export is all-or-nothing: an unreadable, oversize or unparseable record is OMITTED, never truncated or cleaned,
//   - a merge onto a readable record never removes an entry and never turns a global TRUE into false,
//   - a fresh device never gets global false from a backup; confirmGlobalOff is the only path and changes only global,
//   - the removed list refuses over the cap instead of being cut short,
//   - the module is PURE (imports only ./suppression) and DARK (nothing outside tests imports it).
// Run: npx tsx --test src/lib/trust/suppression-carry.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  CARRY_MAX_ENTRIES,
  carrySuppression,
  confirmGlobalOff,
  freshDeviceWrite,
  mergeByTightening,
  mergeRemoved,
  parseCarriedSuppression,
  type CarriedSuppression,
} from '@/lib/trust/suppression-carry';
import type { SuppressionRecord } from '@/lib/trust/suppression';

const hex = (n: number): string => n.toString(16).padStart(64, '0');
const ids = (from: number, count: number): string[] => Array.from({ length: count }, (_, i) => hex(from + i));
const good = (over: Partial<CarriedSuppression> = {}): CarriedSuppression => ({ v: 1, global: false, groups: ['family'], persons: [hex(1), hex(2)], removed: [hex(9)], ...over });
const rec = (over: Partial<SuppressionRecord> = {}): SuppressionRecord => ({ global: false, groups: [], persons: [], ...over });

test('parse: a well-formed record round-trips and the result is a copy', () => {
  const input = good();
  const out = parseCarriedSuppression(input);
  assert.deepEqual(out, input);
  assert.notStrictEqual(out!.persons, input.persons);
  out!.persons.push(hex(77));
  assert.equal(input.persons.length, 2, 'mutating the result must not touch the input');
});

test('parse: refuses every non-record input', () => {
  for (const x of [null, undefined, 0, 1, 'x', true, [], [good()], () => 0]) assert.equal(parseCarriedSuppression(x), null);
});

test('parse: an ARRAY carrying the five right own properties is still refused (the exact-keys check alone would pass it, and a structured clone keeps array properties)', () => {
  const arr = Object.assign([], good());
  assert.deepEqual(Object.keys(arr).sort(), ['global', 'groups', 'persons', 'removed', 'v'], 'the probe really has exactly the five keys');
  assert.equal(parseCarriedSuppression(arr), null);
});

test('parse: refuses missing, extra and wrong-version keys', () => {
  const g = good();
  for (const k of Object.keys(g)) {
    const r: Record<string, unknown> = { ...g };
    delete r[k];
    assert.equal(parseCarriedSuppression(r), null, `missing ${k}`);
  }
  assert.equal(parseCarriedSuppression({ ...g, extra: 1 }), null);
  assert.equal(parseCarriedSuppression({ ...g, v: 2 }), null);
  assert.equal(parseCarriedSuppression({ ...g, v: '1' }), null);
  for (const bad of [0, 1, 'true', null, undefined]) assert.equal(parseCarriedSuppression({ ...g, global: bad }), null, `global ${String(bad)}`);
});

test('parse: persons and removed accept only canonical lowercase 64-hex, no duplicates, strings only', () => {
  const upper = hex(0xabc).toUpperCase();
  const cases: unknown[] = [upper, hex(1).slice(1), hex(1) + '0', ` ${hex(1)}`, `${hex(1)} `, 'g'.repeat(64), '', 5, null, { a: 1 }];
  for (const bad of cases) {
    assert.equal(parseCarriedSuppression(good({ persons: [bad as string] })), null, `persons ${String(bad).slice(0, 12)}`);
    assert.equal(parseCarriedSuppression(good({ removed: [bad as string] })), null, `removed ${String(bad).slice(0, 12)}`);
  }
  assert.equal(parseCarriedSuppression(good({ persons: [hex(1), hex(1)] })), null, 'duplicate person');
  assert.equal(parseCarriedSuppression(good({ removed: [hex(1), hex(1)] })), null, 'duplicate removed');
  assert.equal(parseCarriedSuppression(good({ persons: 'x' as unknown as string[] })), null);
});

test('parse: group ids are opaque stored-form text: spaces and accents accepted, control chars, empty, padded, uppercase, over-long refused', () => {
  for (const ok of ['family', 'close friends', 'famille é', '家族', 'a'.repeat(128)]) assert.deepEqual(parseCarriedSuppression(good({ groups: [ok] }))?.groups, [ok], ok.slice(0, 12));
  for (const bad of ['', ' lead', 'trail ', 'Family', 'FAMILY', 'a\nb', 'a\u0000b', 'a\u007fb', 'a'.repeat(129)]) {
    assert.equal(parseCarriedSuppression(good({ groups: [bad] })), null, JSON.stringify(bad).slice(0, 20));
  }
  assert.equal(parseCarriedSuppression(good({ groups: ['x', 'x'] })), null, 'duplicate group');
});

test('cap pin: the cap is the chosen 4096 (a CONSTANT pin, not behaviour: raising it grows the sealed record, so it is a reviewed change)', () => {
  assert.equal(CARRY_MAX_ENTRIES, 4096);
});

// A sparse array: JSON cannot make one, but a structured clone (IndexedDB) keeps holes, and Array.prototype.every() skips them.
const sparse = (len: number, at: number, value: string): string[] => { const a: string[] = new Array(len); a[at] = value; return a; };

test('parse: a SPARSE array is refused in every list (a hole must never read as an entry)', () => {
  for (const [key, v] of [['persons', hex(1)], ['removed', hex(1)], ['groups', 'x']] as const) {
    const hole = (at: number, len: number) => ({ ...good(), [key]: sparse(len, at, v) });
    assert.ok(0 in hole(1, 2)[key] === false && 1 in hole(1, 2)[key], `${key}: the probe really is sparse`);
    assert.equal(parseCarriedSuppression(hole(1, 2)), null, `${key}: hole first`);
    assert.equal(parseCarriedSuppression(hole(0, 2)), null, `${key}: hole last`);
    assert.equal(parseCarriedSuppression(hole(1, 3)), null, `${key}: hole in the middle`);
    assert.equal(parseCarriedSuppression({ ...good(), [key]: new Array(1) }), null, `${key}: one hole, nothing else`);
  }
});

test('parse: a bad entry is refused wherever it sits in the list, last position included', () => {
  assert.equal(parseCarriedSuppression(good({ persons: [hex(1), 'not-hex'] })), null);
  assert.equal(parseCarriedSuppression(good({ removed: [hex(1), hex(2), 'not-hex'] })), null);
  assert.equal(parseCarriedSuppression(good({ groups: ['ok', 'Bad'] })), null);
  assert.equal(parseCarriedSuppression(good({ persons: ['not-hex', hex(1)] })), null);
});

test('parse: group ids refuse EVERY control character (C0, DEL, C1) and keep format characters', () => {
  for (const bad of ['a\u0080b', 'a\u0085b', 'a\u009fb', '\u0085', 'a\u0000b', 'a\u001fb', 'a\u007fb']) {
    assert.equal(parseCarriedSuppression(good({ groups: [bad] })), null, JSON.stringify(bad));
  }
  // Format characters are legal (emoji tags need ZWJ). A renderer must isolate a group id (bidi): not this module's job, pinned so a change is deliberate.
  for (const ok of ['\u{1F468}‍\u{1F469}‍\u{1F467}', 'a‮b', 'a​b']) {
    assert.deepEqual(parseCarriedSuppression(good({ groups: [ok] }))?.groups, [ok], JSON.stringify(ok));
  }
});

test('carry: a record whose list has a hole is OMITTED, never cleaned', () => {
  assert.equal(carrySuppression(rec({ persons: sparse(2, 1, hex(1)) }), []), undefined);
  assert.equal(carrySuppression(rec({ groups: sparse(2, 1, 'x') }), []), undefined);
  assert.equal(carrySuppression(rec(), sparse(2, 1, hex(1))), undefined);
});

test('parse: the cap is exact and a list over it is refused whole', () => {
  assert.equal(parseCarriedSuppression(good({ persons: ids(1, CARRY_MAX_ENTRIES) }))?.persons.length, CARRY_MAX_ENTRIES);
  assert.equal(parseCarriedSuppression(good({ persons: ids(1, CARRY_MAX_ENTRIES + 1) })), null);
  assert.equal(parseCarriedSuppression(good({ removed: ids(1, CARRY_MAX_ENTRIES + 1) })), null);
  assert.equal(parseCarriedSuppression(good({ groups: Array.from({ length: CARRY_MAX_ENTRIES + 1 }, (_, i) => `g${i}`) })), null);
});

test('carry: null (unreadable or absent) is OMITTED', () => {
  assert.equal(carrySuppression(null, [hex(1)]), undefined);
});

test('carry: a readable record is carried with its removed list, global preserved both ways', () => {
  for (const g of [true, false]) {
    const out = carrySuppression(rec({ global: g, groups: ['family'], persons: [hex(1)] }), [hex(9)]);
    assert.deepEqual(out, { v: 1, global: g, groups: ['family'], persons: [hex(1)], removed: [hex(9)] });
  }
});

test('carry: never truncates and never cleans: any entry the parser would refuse, or any list over the cap, omits the WHOLE record', () => {
  assert.notEqual(hex(0xabc), hex(0xabc).toUpperCase(), 'the uppercase probe must differ from the lowercase id');
  assert.equal(carrySuppression(rec({ persons: [hex(1), hex(0xabc).toUpperCase()] }), []), undefined, 'one bad person');
  assert.equal(carrySuppression(rec({ groups: ['Family'] }), []), undefined, 'one bad group');
  assert.equal(carrySuppression(rec({ persons: [hex(1), hex(1)] }), []), undefined, 'duplicate person');
  assert.equal(carrySuppression(rec({ persons: ids(1, CARRY_MAX_ENTRIES + 1) }), []), undefined, 'persons over cap');
  assert.equal(carrySuppression(rec(), ids(1, CARRY_MAX_ENTRIES + 1)), undefined, 'removed over cap');
  assert.equal(carrySuppression(rec(), ['not-hex']), undefined, 'bad removed id');
  const atCap = carrySuppression(rec({ persons: ids(1, CARRY_MAX_ENTRIES) }), ids(5000, CARRY_MAX_ENTRIES));
  assert.equal(atCap?.persons.length, CARRY_MAX_ENTRIES);
  assert.equal(atCap?.removed.length, CARRY_MAX_ENTRIES);
});

test('carry: the output does not alias the input', () => {
  const r = rec({ persons: [hex(1)], groups: ['a'] });
  const removed = [hex(2)];
  const out = carrySuppression(r, removed)!;
  out.persons.push(hex(3));
  out.groups.push('b');
  out.removed.push(hex(4));
  assert.deepEqual(r, rec({ persons: [hex(1)], groups: ['a'] }));
  assert.deepEqual(removed, [hex(2)]);
});

test('merge: union of persons and groups, existing entries first, input untouched', () => {
  const existing = rec({ persons: [hex(1)], groups: ['a'] });
  const snap = JSON.stringify(existing);
  const carried = good({ persons: [hex(2), hex(1)], groups: ['b', 'a'] });
  const csnap = JSON.stringify(carried);
  const out = mergeByTightening(existing, carried);
  assert.deepEqual(out.persons, [hex(1), hex(2)]);
  assert.deepEqual(out.groups, ['a', 'b']);
  assert.equal(JSON.stringify(existing), snap);
  assert.equal(JSON.stringify(carried), csnap);
});

test('merge: the result shares no array with either input, even when the carried record adds nothing', () => {
  const existing = rec({ global: true, persons: [hex(1)], groups: ['a'] });
  const carried = good({ persons: [hex(1)], groups: ['a'] });
  const out = mergeByTightening(existing, carried);
  assert.notStrictEqual(out.persons, existing.persons);
  assert.notStrictEqual(out.groups, existing.groups);
  assert.notStrictEqual(out.persons, carried.persons);
  out.persons.push(hex(5));
  out.groups.push('z');
  assert.deepEqual(existing, rec({ global: true, persons: [hex(1)], groups: ['a'] }));
  assert.deepEqual(carried, good({ persons: [hex(1)], groups: ['a'] }));
});

test('merge: global is an OR: an existing TRUE is never turned off by a carried false', () => {
  assert.equal(mergeByTightening(rec({ global: true }), good({ global: false })).global, true);
  assert.equal(mergeByTightening(rec({ global: false }), good({ global: true })).global, true);
  assert.equal(mergeByTightening(rec({ global: true }), good({ global: true })).global, true);
  assert.equal(mergeByTightening(rec({ global: false }), good({ global: false })).global, false);
});

test('merge: idempotent, and an empty carried record changes nothing', () => {
  const existing = rec({ global: false, persons: [hex(1)], groups: ['a'] });
  const once = mergeByTightening(existing, good());
  assert.deepEqual(mergeByTightening(once, good()), once);
  assert.deepEqual(mergeByTightening(existing, good({ persons: [], groups: [], global: false, removed: [] })), existing);
});

test('merge: PROPERTY over 300 seeded cases: never loosens (superset of persons and groups, global only goes up)', () => {
  let s = 12345;
  const rnd = (n: number): number => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s % n; };
  const pick = (pool: string[]): string[] => Array.from(new Set(pool.filter(() => rnd(2) === 0)));
  const personPool = ids(1, 12);
  const groupPool = ['a', 'b', 'c', 'close friends', 'é'];
  for (let i = 0; i < 300; i += 1) {
    const existing = rec({ global: rnd(2) === 0, persons: pick(personPool), groups: pick(groupPool) });
    const carried = good({ global: rnd(2) === 0, persons: pick(personPool), groups: pick(groupPool) });
    const out = mergeByTightening(existing, carried);
    for (const p of existing.persons) assert.ok(out.persons.includes(p), `case ${i} lost person`);
    for (const g of existing.groups) assert.ok(out.groups.includes(g), `case ${i} lost group`);
    for (const p of carried.persons) assert.ok(out.persons.includes(p), `case ${i} dropped carried person`);
    for (const g of carried.groups) assert.ok(out.groups.includes(g), `case ${i} dropped carried group`);
    assert.equal(out.global, existing.global || carried.global, `case ${i} global`);
    assert.equal(new Set(out.persons).size, out.persons.length, `case ${i} duplicate persons`);
  }
});

test('fresh device: carried persons and groups are written at once with global TRUE whatever the backup said', () => {
  for (const g of [true, false]) {
    const out = freshDeviceWrite(good({ global: g }));
    assert.equal(out.record.global, true);
    assert.deepEqual(out.record.persons, [hex(1), hex(2)]);
    assert.deepEqual(out.record.groups, ['family']);
    assert.equal(out.globalOffWaitsForConfirm, g === false);
  }
});

test('fresh device: an empty carried record still writes global TRUE (never the looser empty record)', () => {
  const out = freshDeviceWrite(good({ persons: [], groups: [], global: false }));
  assert.deepEqual(out.record, { global: true, groups: [], persons: [] });
  assert.equal(out.globalOffWaitsForConfirm, true);
});

test('confirmGlobalOff: switches global off and changes nothing else; the input is untouched', () => {
  const r = rec({ global: true, persons: [hex(1)], groups: ['a'] });
  const snap = JSON.stringify(r);
  const out = confirmGlobalOff(r);
  assert.deepEqual(out, { global: false, persons: [hex(1)], groups: ['a'] });
  assert.equal(JSON.stringify(r), snap);
  out.persons.push(hex(2));
  assert.equal(r.persons.length, 1, 'no aliasing');
});

test('removed: union keeps the existing order, adds the new, drops duplicates', () => {
  assert.deepEqual(mergeRemoved([hex(1), hex(2)], [hex(2), hex(3)]), { ok: true, removed: [hex(1), hex(2), hex(3)] });
  assert.deepEqual(mergeRemoved([], []), { ok: true, removed: [] });
});

test('removed: exactly the cap is fine; one over REFUSES and is never cut short', () => {
  assert.equal(mergeRemoved(ids(1, CARRY_MAX_ENTRIES - 1), [hex(90000)]).ok, true);
  assert.deepEqual(mergeRemoved(ids(1, CARRY_MAX_ENTRIES), [hex(90000)]), { ok: false, reason: 'too-large' });
  assert.deepEqual(mergeRemoved(ids(1, CARRY_MAX_ENTRIES), ids(1, CARRY_MAX_ENTRIES)), { ok: true, removed: ids(1, CARRY_MAX_ENTRIES) }, 'a full overlap adds nothing');
});

// ── static pins ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const SRC = join(process.cwd(), 'src', 'lib', 'trust', 'suppression-carry.ts');

test('PURE pin: the module imports only ./suppression and touches no storage, clock or randomness', () => {
  const text = readFileSync(SRC, 'utf8');
  const imports = [...text.matchAll(/^import\s[^;]*?from\s+'([^']+)'/gm)].map((m) => m[1]);
  assert.deepEqual(imports, ['./suppression']);
  const code = text.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
  for (const banned of ['Date.now', 'new Date', 'Math.random', 'crypto.', 'indexedDB', 'localStorage', 'fetch(', 'await ']) assert.ok(!code.includes(banned), `uses ${banned}`);
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

test('DARK pin: nothing outside tests imports suppression-carry except the restore module, which has its own dark pin', () => {
  const roots = ['src', 'app'].map((d) => join(process.cwd(), d)).filter((d) => { try { return statSync(d).isDirectory(); } catch { return false; } });
  assert.ok(roots.length >= 1);
  const importers = roots.flatMap((r) => walk(r)).filter((f) => !/\.test\.[a-z]+$/.test(f) && !f.endsWith('suppression-carry.ts') && /suppression-carry/.test(readFileSync(f, 'utf8')));
  assert.deepEqual(importers.map((f) => f.slice(f.lastIndexOf('/') + 1)), ['suppression-restore.ts']);
});
