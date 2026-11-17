// src/lib/identity/backup-shards-shape.test.ts
// A plaintext backup's recovery-pieces record is stored as the file has it and read later by the give-a-piece screen, which prints its threshold. A record that cannot be a set
// the app minted is NOT stored; the rest of the backup restores, and the screen says so. What these pin, and why:
//   BS1  every rule has a case that fails it, and says which rule (integer threshold >= 2; a list of pieces; total = number of pieces; threshold <= total; each piece an object
//        with the record's own threshold, an index that is an integer and unique, and, when it names an identity, the backup's own)
//   BS2  a real set from createShards (3 of 5, as the app stores it), a set with custody fields, a piece that names no identity, the smallest set and "no record" are accepted;
//        the same real set under ANOTHER bound identity is not
//   BS3  the screen's sentence is the copy owner's words byte for byte (plain ASCII, frozen hash), it is NOT a suggestion to give new pieces, and the screen shows it from the report
//   BS4  the module is a leaf: it imports nothing and reads no store
//   BS5  the policy and the order, on the source (client-store has no runtime IndexedDB tests, so this is a source guard; IndexedDB is not run here): the record is judged
//        after the identity binding and BEFORE the first write; it is stored only when usable; an unusable one is reported, never silent; and there is no refusal in either
//        import function
//   BS6  the old refusal code is gone from the three files that carried it
//   BS7  the report's decision, run as written with a stubbed read: a record left out is reported ONLY when the device holds none of its own; a good record already on the device is kept and nothing is said; the decision only reads
//   BS8  the give-a-piece screen's "no record" line (row 265a) and its loading line (265b) are the copy owner's words byte for byte, and the old "create a new identity" advice is gone
// Run: npx tsx --test src/lib/identity/backup-shards-shape.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { backupShardsProblem, type ShardsProblem } from './backup-shards-shape';
import { RESTORE_MESSAGES } from './restore-errors';
import { createShards, generateMasterSecret } from '../crypto/recovery';

const read = (rel: string): string => readFileSync(new URL(rel, import.meta.url), 'utf8');
const code = (rel: string): string => read(rel).replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');

const FP = 'fp';
// the exact source of the report decision in importAll (comments stripped), so the behaviour test below runs the REAL text
const DECIDE = 'let shardsDropped = false;\n  if (backup.shards && !shardsUsable) {\n    try { shardsDropped = (await loadShards(fingerprint)) === null; } catch { shardsDropped = true; }\n  }';
// a record as the app stores it, with n pieces that each carry `pieceThreshold`
const piece = (i: number, threshold: unknown = 3): Record<string, unknown> => ({ index: i + 1, data: 'AAAA', identity_fingerprint: FP, threshold });
const record = (o: { threshold?: unknown; total?: unknown; n?: number; pieceThreshold?: unknown } = {}): Record<string, unknown> => {
  const threshold = 'threshold' in o ? o.threshold : 3;
  const n = o.n ?? 5;
  return { threshold, total: 'total' in o ? o.total : n, shards: Array.from({ length: n }, (_, i) => piece(i, 'pieceThreshold' in o ? o.pieceThreshold : threshold)) };
};
const withPieces = (pieces: unknown[]): Record<string, unknown> => ({ threshold: 3, total: pieces.length, shards: pieces });

test('BS1 every rule has a case that fails it, and the problem names the rule', () => {
  const cases: Array<[string, unknown, ShardsProblem]> = [
    ['a string', 'x', 'not-an-object'], ['a number', 5, 'not-an-object'], ['true', true, 'not-an-object'], ['an array', [], 'not-an-object'],
    ['threshold 1', record({ threshold: 1 }), 'threshold'], ['threshold 0', record({ threshold: 0 }), 'threshold'], ['threshold -2', record({ threshold: -2 }), 'threshold'],
    ['threshold NaN', record({ threshold: NaN }), 'threshold'], ['threshold 2.5', record({ threshold: 2.5 }), 'threshold'], ['threshold "3"', record({ threshold: '3' }), 'threshold'],
    ['threshold Infinity', record({ threshold: Infinity }), 'threshold'], ['threshold null', record({ threshold: null }), 'threshold'], ['no threshold', (() => { const r = record(); delete r.threshold; return r; })(), 'threshold'],
    ['pieces a string', { threshold: 3, total: 5, shards: 'abcde' }, 'not-a-list'], ['pieces an object', { threshold: 3, total: 5, shards: {} }, 'not-a-list'], ['no pieces field', { threshold: 3, total: 5 }, 'not-a-list'],
    ['total 6, 5 pieces', record({ total: 6 }), 'total'], ['total 4, 5 pieces', record({ total: 4 }), 'total'], ['total "5"', record({ total: '5' }), 'total'],
    ['total NaN', record({ total: NaN }), 'total'], ['no total', (() => { const r = record(); delete r.total; return r; })(), 'total'],
    ['threshold above the pieces', record({ threshold: 6, n: 5 }), 'unreachable'], ['3 of 2', record({ threshold: 3, n: 2 }), 'unreachable'], ['3 of 0', record({ threshold: 3, n: 0 }), 'unreachable'],
    ['a null piece', withPieces([piece(0), null, piece(2)]), 'bad-piece'], ['a number piece', withPieces([piece(0), 7, piece(2)]), 'bad-piece'],
    ['a string piece', withPieces([piece(0), 'x', piece(2)]), 'bad-piece'], ['an array piece', withPieces([piece(0), [], piece(2)]), 'bad-piece'],
    ['a sparse hole', withPieces([piece(0), , piece(2)]), 'bad-piece'],
    ['one piece with another threshold', withPieces([piece(0), piece(1, 2), piece(2)]), 'piece-threshold'],
    ['one piece without a threshold', withPieces([piece(0), { index: 2, data: 'AAAA', identity_fingerprint: FP }, piece(2)]), 'piece-threshold'],
    ['one piece with a string threshold', withPieces([piece(0), piece(1, '3'), piece(2)]), 'piece-threshold'],
    // a piece that names an identity names THIS one
    ['a piece for another identity', withPieces([piece(0), { ...piece(1), identity_fingerprint: 'someone-else' }, piece(2)]), 'piece-fingerprint'],
    ['a piece whose identity is null', withPieces([piece(0), { ...piece(1), identity_fingerprint: null }, piece(2)]), 'piece-fingerprint'],
    ['a piece whose identity is a number', withPieces([piece(0), { ...piece(1), identity_fingerprint: 7 }, piece(2)]), 'piece-fingerprint'],
    ['a piece whose identity is empty', withPieces([piece(0), { ...piece(1), identity_fingerprint: '' }, piece(2)]), 'piece-fingerprint'],
    // the index: an integer, one per piece
    ['a duplicate index', withPieces([piece(0), { ...piece(1), index: 1 }, piece(2)]), 'piece-index'],
    ['an index 1.5', withPieces([piece(0), { ...piece(1), index: 1.5 }, piece(2)]), 'piece-index'],
    ['an index "2"', withPieces([piece(0), { ...piece(1), index: '2' }, piece(2)]), 'piece-index'],
    ['an index missing', withPieces([piece(0), (() => { const p = piece(1); delete p.index; return p; })(), piece(2)]), 'piece-index'],
    ['an index NaN', withPieces([piece(0), { ...piece(1), index: NaN }, piece(2)]), 'piece-index'],
  ];
  for (const [name, rec, want] of cases) assert.equal(backupShardsProblem(rec, FP), want, name);
});

test('BS2 a real set, a set with custody fields, a piece naming no identity, the smallest set and no record are accepted; the real set under another identity is not', async () => {
  const fp = 'fingerprint-1';
  const shards = await createShards(generateMasterSecret(), 3, 5, fp);
  const real = { threshold: 3, total: 5, shards };
  assert.equal(shards.length, 5);
  assert.equal(backupShardsProblem(real, fp), null, 'a set as createShards makes it and the app stores it');
  assert.equal(backupShardsProblem(real, 'another-identity'), 'piece-fingerprint', 'the same set under ANOTHER bound identity');
  const given = { ...real, shards: shards.map((s, i) => (i < 2 ? { ...s, given_to: { kind: 'contact', ref: 'c1' }, given_at: '2026-11-17T00:00:00.000Z' } : s)) };
  assert.equal(backupShardsProblem(given, fp), null, 'custody fields on a piece are not a problem');
  const unnamed = { ...real, shards: shards.map((s) => { const { identity_fingerprint: _drop, ...rest } = s; void _drop; return rest; }) };
  assert.equal(backupShardsProblem(unnamed, fp), null, 'a piece that names no identity is accepted (the rule is "when present")');
  const smallest = { threshold: 2, total: 2, shards: await createShards(generateMasterSecret(), 2, 2, fp) };
  assert.equal(backupShardsProblem(smallest, fp), null, '2 of 2 is a usable set');
  assert.equal(backupShardsProblem(undefined, fp), null, 'a backup with no record');
  assert.equal(backupShardsProblem(null, fp), null, 'null is "no record"');
});

test('BS3 the screen\'s sentence is the copy owner\'s words byte for byte, is no remedy to give new pieces, and the screen shows it from the report', () => {
  const s = RESTORE_MESSAGES.piecesRecordNotRestored;
  assert.equal(s, "Your identity was restored, but this backup's record of your recovery pieces was damaged and wasn't restored. This device doesn't know who holds your pieces. If you have another copy of the backup, restoring it may bring that record back.");
  assert.equal(s.length, 238);
  assert.ok(/^[\x20-\x7e]+$/.test(s), 'plain ASCII');
  assert.equal(createHash('sha256').update(s).digest('hex').slice(0, 16), '45b8d615a71822d2', 'the frozen hash');
  assert.ok(!/give (out )?(a )?new|new (set of )?pieces|rotate/i.test(s), 'no remedy: a new set from the same key does not cancel the old one');
  const f = code('../../components/SoverentityFrontend.tsx');
  assert.equal(f.split('if (report.shardsDropped) parts.push(RESTORE_MESSAGES.piecesRecordNotRestored);').length - 1, 1, 'the restore note adds it, once');
  assert.ok(!f.includes('RESTORE_MESSAGES.piecesRecordNotRestored', f.indexOf('piecesRecordNotRestored') + 10), 'and nowhere else in the screen');
});

test('BS4 THE MODULE is a leaf: it imports nothing and reads no store', () => {
  const src = code('./backup-shards-shape.ts');
  assert.deepEqual([...src.matchAll(/^\s*import\s/gm)], [], 'no import in any form');
  assert.ok(!/\bawait\b|\bindexedDB\b|\bconsole\.|\bthrow\b/.test(src), 'it is pure: no await, no database, no logging, no throw');
  assert.ok(!/\.data\b|\.given_to\b/.test(src), 'it never reads a piece\'s data or custody');
});

test('BS5 THE POLICY AND THE ORDER: judged after the identity binding and before the first write; stored only when usable; an unusable record is reported; no refusal in either import function', () => {
  const s = code('./client-store.ts');
  const a = s.indexOf('export async function importAll(backup');
  const b = s.indexOf('export async function importAllWithPassword');
  const end = s.indexOf('export async function importVaultContents', b);
  assert.ok(a > 0 && b > a && end > b, 'both functions were found');
  const plain = s.slice(a, b);
  const withPw = s.slice(b, end);
  assert.equal(s.split('backupShardsProblem(').length - 1, 1, 'exactly one call site');
  const judge = 'const shardsUsable = !backup.shards || backupShardsProblem(backup.shards, fingerprint) === null;';
  assert.equal(plain.split(judge).length - 1, 1, 'importAll judges the record once, against the bound fingerprint');
  const bind = 'await assertPlaintextBackupIdentityBinds(backup);';
  assert.ok(plain.indexOf(bind) >= 0 && plain.indexOf(bind) < plain.indexOf(judge), 'after the identity binding');
  assert.ok(plain.indexOf(judge) < plain.indexOf('await storeIdentity('), 'before the first write');
  assert.ok(plain.includes('if (backup.shards && shardsUsable) {\n    await storeShards(fingerprint, backup.shards);'), 'stored only when usable');
  // the report (Flint's MUST, row 266a): set only when a record was left out AND the device ends up with none of its own
  assert.equal(plain.split(DECIDE).length - 1, 1, 'the flag is decided once, from what the device holds');
  assert.ok(plain.indexOf(DECIDE) > plain.indexOf('await storeShards(') && plain.indexOf(DECIDE) > plain.indexOf('await importPlaintextContacts(') && plain.indexOf(DECIDE) > plain.indexOf('await setActiveFingerprint('), 'read after every write');
  assert.equal(plain.split('...(shardsDropped ? { shardsDropped: true as const } : {})').length - 1, 1, 'and reported from that');
  assert.ok(!/\bconsole\./.test(plain), 'importAll stays log-free');
  assert.ok(s.includes('shardsDropped?: true;'), 'the report type carries the flag');
  assert.ok(!/shards/.test(withPw.replace(/\/\*[\s\S]*?\*\//g, '')), 'importAllWithPassword has no pieces check of its own: nothing refuses, importAll reports');
  assert.ok(!s.includes('assertBackupShardsShape'), 'there is no refusal');
});

test('BS7 the report decision, run as written: reported only when the device holds no record of its own; it only reads', async () => {
  const s = code('./client-store.ts');
  const plain = s.slice(s.indexOf('export async function importAll(backup'), s.indexOf('export async function importAllWithPassword'));
  const start = plain.indexOf(DECIDE);
  assert.ok(start > 0, 'the decision is in importAll as pinned');
  // the real text, with only the names it reads in scope: any write it tried (storeShards, txPut, ...) would be a ReferenceError
  const run = new Function('backup', 'shardsUsable', 'fingerprint', 'loadShards', `return (async () => { ${DECIDE}\n return shardsDropped; })();`) as
    (backup: { shards?: unknown }, shardsUsable: boolean, fingerprint: string, loadShards: (fp: string) => Promise<unknown>) => Promise<boolean>;
  const good = { threshold: 3, total: 5, shards: [] };
  const calls: string[] = [];
  const holds = (v: unknown) => async (fp: string) => { calls.push(fp); return v; };
  const bad = { shards: { threshold: 1 } };
  calls.length = 0;
  assert.equal(await run(bad, false, 'fp', holds(null)), true, 'a bad record left out, and the device holds none: reported');
  assert.deepEqual(calls, ['fp'], 'it read the record once, for the bound identity');
  calls.length = 0;
  assert.equal(await run(bad, false, 'fp', holds(good)), false, 'a bad record left out, and the device already holds a good one: nothing is said');
  assert.deepEqual(calls, ['fp'], 'and it only read: it could not write (no write function is in scope)');
  assert.equal(await run(bad, false, 'fp', async () => { throw new Error('unreadable'); }), true, 'a record this device cannot read counts as none');
  calls.length = 0;
  assert.equal(await run({}, true, 'fp', holds(null)), false, 'a backup with no record: not reported, and nothing is read');
  assert.equal(await run({ shards: good }, true, 'fp', holds(null)), false, 'a usable record is stored, not left out: not reported, and nothing is read');
  assert.deepEqual(calls, [], 'neither of the last two reads the device');
});

test('BS8 the give-a-piece screen: the "no record" line (265a) and the loading line (265b) are the copy owner\'s words, and the old advice is gone', () => {
  const raw = read('../../components/ShardGiveDialog.tsx');
  const m = /const NO_PIECES_RECORD_SENTENCE = '([^']*)';/.exec(raw);
  assert.ok(m, 'the sentence is one constant');
  const s = m[1];
  assert.equal(s, 'This device has no record of recovery pieces for this identity, so there are none to give from here. If you restored it from a backup, another copy of that backup may bring the record back.');
  assert.equal(s.length, 189);
  assert.ok(/^[\x20-\x7e]+$/.test(s), 'plain ASCII');
  assert.equal(createHash('sha256').update(s).digest('hex').slice(0, 16), '6fa72ccbd0f207c2', 'the frozen hash');
  assert.ok(!/give (out )?(a )?new|new (set of )?pieces|new identity|rotate/i.test(s), 'no remedy of giving new pieces or making a new identity');
  const ui = code('../../components/ShardGiveDialog.tsx');
  const none = ui.slice(ui.indexOf("phase === 'none' &&"), ui.indexOf("phase === 'all-given' &&"));
  assert.ok(none.includes('{NO_PIECES_RECORD_SENTENCE}') && none.split('{NO_PIECES_RECORD_SENTENCE}').length === 2, 'the "none" phase shows it, once');
  assert.equal(ui.split('NO_PIECES_RECORD_SENTENCE').length - 1, 2, 'defined once and used once, nowhere else');
  assert.ok(raw.includes('>Reading your recovery pieces\u2026</p>') && !/recovery shards/i.test(raw), 'the loading line says pieces, and "recovery shards" is gone from the screen');
  assert.ok(!/create a new identity|Shards are minted|use the tear/i.test(raw), 'the old advice is gone');
});

test('BS6 the old refusal code is gone from the three files that carried it', () => {
  assert.ok(!code('../crypto/coded-error.ts').includes('backup-shards-malformed'));
  assert.ok(!code('./restore-errors.ts').includes('backup-shards-malformed'));
  assert.ok(!code('./client-store.ts').includes('backup-shards-malformed'));
});
