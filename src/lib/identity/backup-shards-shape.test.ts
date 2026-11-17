// src/lib/identity/backup-shards-shape.test.ts
// A plaintext backup's recovery-pieces record is stored as the file has it and read later by the give-a-piece screen, which prints its threshold. Before this, a file
// with a threshold of 1 made that screen say "Any 1 of your keepers ... no single piece can", a contradiction. What these pin, and why:
//   BS1  every rule has a case that fails it, and says which rule (integer threshold >= 2; a list of pieces; total = number of pieces; threshold <= total; each piece is
//        an object with the record's own threshold)
//   BS2  a real set from createShards (3 of 5, exactly as the app stores it), a set with custody fields, the smallest set (2 of 2) and "no record at all" are accepted
//   BS3  the refusal has a CODE; the screen's sentence comes from the code (the ruled "part of this backup can't be read" one), and a look-alike message is not it
//   BS4  the module is a leaf: it imports only the coded error
//   BS5  the order, on the source (client-store has no runtime IndexedDB tests, so this is a source guard; IndexedDB is not run here): in BOTH import functions the
//        check comes right after the identity binding and BEFORE the first write or the session key, and it runs under the same condition as the store
//   BS6  the code is registered (coded-error.ts) and classified once (restore-errors.ts)
// Run: npx tsx --test src/lib/identity/backup-shards-shape.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { backupShardsProblem, assertBackupShardsShape, type ShardsProblem } from './backup-shards-shape';
import { RestoreThrow } from '../crypto/coded-error';
import { classifyRestoreFailure, RESTORE_MESSAGES } from './restore-errors';
import { createShards, generateMasterSecret } from '../crypto/recovery';

const read = (rel: string): string => readFileSync(new URL(rel, import.meta.url), 'utf8');
const code = (rel: string): string => read(rel).replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');

// a record as the app stores it, with n pieces that each carry `pieceThreshold`
const piece = (i: number, threshold: unknown = 3): Record<string, unknown> => ({ index: i + 1, data: 'AAAA', identity_fingerprint: 'fp', threshold });
const record = (o: { threshold?: unknown; total?: unknown; n?: number; pieceThreshold?: unknown } = {}): Record<string, unknown> => {
  const threshold = 'threshold' in o ? o.threshold : 3;
  const n = o.n ?? 5;
  return { threshold, total: 'total' in o ? o.total : n, shards: Array.from({ length: n }, (_, i) => piece(i, 'pieceThreshold' in o ? o.pieceThreshold : threshold)) };
};

test('BS1 every rule has a case that fails it, and the problem names the rule', () => {
  const cases: Array<[string, unknown, ShardsProblem]> = [
    // not an object
    ['a string', 'x', 'not-an-object'], ['a number', 5, 'not-an-object'], ['true', true, 'not-an-object'], ['an array', [], 'not-an-object'],
    // the threshold: an integer, at least 2 (a threshold of 1 is the contradiction on screen)
    ['threshold 1', record({ threshold: 1 }), 'threshold'], ['threshold 0', record({ threshold: 0 }), 'threshold'], ['threshold -2', record({ threshold: -2 }), 'threshold'],
    ['threshold NaN', record({ threshold: NaN }), 'threshold'], ['threshold 2.5', record({ threshold: 2.5 }), 'threshold'], ['threshold "3"', record({ threshold: '3' }), 'threshold'],
    ['threshold Infinity', record({ threshold: Infinity }), 'threshold'], ['threshold null', record({ threshold: null }), 'threshold'], ['no threshold', (() => { const r = record(); delete r.threshold; return r; })(), 'threshold'],
    // the pieces are a list
    ['pieces a string', { threshold: 3, total: 5, shards: 'abcde' }, 'not-a-list'], ['pieces an object', { threshold: 3, total: 5, shards: {} }, 'not-a-list'], ['no pieces field', { threshold: 3, total: 5 }, 'not-a-list'],
    // total equals the number of pieces
    ['total 6, 5 pieces', record({ total: 6 }), 'total'], ['total 4, 5 pieces', record({ total: 4 }), 'total'], ['total "5"', record({ total: '5' }), 'total'],
    ['total NaN', record({ total: NaN }), 'total'], ['no total', (() => { const r = record(); delete r.total; return r; })(), 'total'],
    // the threshold can be met
    ['threshold above the pieces', record({ threshold: 6, n: 5 }), 'unreachable'], ['3 of 2', record({ threshold: 3, n: 2 }), 'unreachable'], ['3 of 0', record({ threshold: 3, n: 0 }), 'unreachable'],
    // each piece is an object that carries the record's own threshold
    ['a null piece', { threshold: 3, total: 3, shards: [piece(0), null, piece(2)] }, 'bad-piece'], ['a number piece', { threshold: 3, total: 3, shards: [piece(0), 7, piece(2)] }, 'bad-piece'],
    ['a string piece', { threshold: 3, total: 3, shards: [piece(0), 'x', piece(2)] }, 'bad-piece'], ['an array piece', { threshold: 3, total: 3, shards: [piece(0), [], piece(2)] }, 'bad-piece'],
    ['one piece with another threshold', { threshold: 3, total: 3, shards: [piece(0), piece(1, 2), piece(2)] }, 'piece-threshold'],
    ['one piece without a threshold', { threshold: 3, total: 3, shards: [piece(0), { index: 2, data: 'AAAA', identity_fingerprint: 'fp' }, piece(2)] }, 'piece-threshold'],
    ['one piece with a string threshold', { threshold: 3, total: 3, shards: [piece(0), piece(1, '3'), piece(2)] }, 'piece-threshold'],
  ];
  for (const [name, rec, want] of cases) {
    assert.equal(backupShardsProblem(rec), want, name);
    assert.throws(() => assertBackupShardsShape(rec), (e: unknown) => e instanceof RestoreThrow && e.code === 'backup-shards-malformed' && e.message.includes(`(${want})`), `${name}: refused with the code`);
  }
});

test('BS2 a real set, a set with custody fields, the smallest set and no record at all are accepted', async () => {
  const fp = 'fingerprint-1';
  const shards = await createShards(generateMasterSecret(), 3, 5, fp);
  const real = { threshold: 3, total: 5, shards };
  assert.equal(shards.length, 5);
  assert.equal(backupShardsProblem(real), null, 'a set as createShards makes it and the app stores it');
  const given = { ...real, shards: shards.map((s, i) => (i < 2 ? { ...s, given_to: { kind: 'contact', ref: 'c1' }, given_at: '2026-11-17T00:00:00.000Z' } : s)) };
  assert.equal(backupShardsProblem(given), null, 'custody fields on a piece are not a problem');
  const smallest = { threshold: 2, total: 2, shards: await createShards(generateMasterSecret(), 2, 2, fp) };
  assert.equal(backupShardsProblem(smallest), null, '2 of 2 is a usable set');
  assert.equal(backupShardsProblem(undefined), null, 'a backup with no record');
  assert.equal(backupShardsProblem(null), null, 'null is "no record" (the import only checks a record that would be stored)');
  assert.doesNotThrow(() => assertBackupShardsShape(real));
  assert.doesNotThrow(() => assertBackupShardsShape(undefined));
});

test('BS3 the refusal is shown by its CODE as the ruled "part of this backup can\'t be read" sentence; a look-alike message is not it', () => {
  let err: unknown;
  try { assertBackupShardsShape(record({ threshold: 1 })); } catch (e) { err = e; }
  assert.ok(err instanceof RestoreThrow);
  assert.equal(err.code, 'backup-shards-malformed');
  assert.ok(!/stopped|saved|password/i.test(err.message), 'the console message says what is wrong with the record, not a restore verdict');
  const shown = classifyRestoreFailure(err);
  assert.deepEqual(shown, { code: 'backup-unreadable', message: RESTORE_MESSAGES.backupPartUnreadable });
  assert.equal(RESTORE_MESSAGES.backupPartUnreadable, "Part of this backup can't be read, so it can't be restored. If you have another copy, try that one.");
  // text is never the key: a plain Error that merely says it is not a usable set gets the generic sentence
  assert.equal(classifyRestoreFailure(new Error('Invalid backup: the recovery pieces record is not a usable set (threshold)')).code, 'unknown');
  assert.equal(classifyRestoreFailure(new Error('backup-shards-malformed')).code, 'unknown');
});

test('BS4 THE MODULE is a leaf: it imports only the coded error, and reads no store', () => {
  const src = code('./backup-shards-shape.ts');
  const imports = [...src.matchAll(/^\s*import\s[^;]*?from\s+'([^']+)'/gm)].map((m) => m[1]);
  assert.deepEqual(imports, ['../crypto/coded-error']);
  assert.ok(!/\bawait\b|\bindexedDB\b|\bconsole\./.test(src), 'it is pure: no await, no database, no logging');
});

test('BS5 THE ORDER: in both import functions the pieces check follows the identity binding and precedes the first write or the session key, under the same condition as the store', () => {
  const s = code('./client-store.ts');
  assert.equal(s.split('assertBackupShardsShape(').length - 1, 2, 'exactly two call sites (the import and the import with a password)');
  const a = s.indexOf('export async function importAll(backup');
  const b = s.indexOf('export async function importAllWithPassword');
  const end = s.indexOf('export async function importVaultContents', b);
  assert.ok(a > 0 && b > a && end > b, 'both functions were found');
  const plain = s.slice(a, b);
  const withPw = s.slice(b, end);
  const call = 'if (backup.shards) assertBackupShardsShape(backup.shards);';
  assert.equal(plain.split(call).length - 1, 1);
  assert.equal(withPw.split(call).length - 1, 1);
  const bind = 'await assertPlaintextBackupIdentityBinds(backup);';
  assert.ok(plain.indexOf(bind) >= 0 && plain.indexOf(bind) < plain.indexOf(call), 'importAll: after the identity binding');
  assert.ok(plain.indexOf(call) < plain.indexOf('await assertRestoreKeepsOwnerDomain('), 'importAll: before the owner-domain check');
  assert.ok(plain.indexOf(call) < plain.indexOf('await storeIdentity('), 'importAll: before the first write');
  assert.ok(withPw.indexOf(bind) >= 0 && withPw.indexOf(bind) < withPw.indexOf(call), 'with a password: after the identity binding');
  assert.ok(withPw.indexOf(call) < withPw.indexOf('throw new DevicePasswordRequired()'), 'with a password: before the person is asked for a device password');
  assert.ok(withPw.indexOf(call) < withPw.indexOf('await initSessionKey('), 'with a password: before the session key is set');
  // the store keeps its own condition, so the check and the store see the same record
  assert.ok(plain.includes('if (backup.shards) {\n    await storeShards(fingerprint, backup.shards);'), 'the store is still under `if (backup.shards)`');
});

test('BS6 the code is registered once and classified once', () => {
  assert.equal(code('../crypto/coded-error.ts').split("'backup-shards-malformed'").length - 1, 1);
  assert.equal(code('./restore-errors.ts').split("thrown === 'backup-shards-malformed'").length - 1, 1);
  assert.ok(code('./restore-errors.ts').includes("if (thrown === 'backup-shards-malformed') return { code: 'backup-unreadable', message: RESTORE_MESSAGES.backupPartUnreadable };"));
});
