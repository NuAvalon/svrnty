import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readJsonStrict, writeFileAtomic, RATCHET_HINT } from './atomic-file';
import { HeadlessStore } from './headless-store';

const dir = () => mkdtempSync(join(tmpdir(), 'atomic-file-'));
const TORN = '{"contacts": [{"id": "c1", "fingerp';          // a write caught half-way

test('writeFileAtomic: content, 0600, no tmp left behind', () => {
  const d = dir(); const p = join(d, 'store.json');
  writeFileAtomic(p, '{"a":1}');
  assert.equal(readFileSync(p, 'utf8'), '{"a":1}');
  assert.equal(statSync(p).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(d), ['store.json']);
});

test('writeFileAtomic: previous good copy kept as .bak', () => {
  const d = dir(); const p = join(d, 'store.json');
  writeFileAtomic(p, '{"v":1}');
  writeFileAtomic(p, '{"v":2}');
  assert.equal(readFileSync(p, 'utf8'), '{"v":2}');
  assert.equal(readFileSync(`${p}.bak`, 'utf8'), '{"v":1}');
  assert.deepEqual(readdirSync(d).sort(), ['store.json', 'store.json.bak']);
  assert.equal(statSync(`${p}.bak`).mode & 0o777, 0o600, '.bak holds contacts + notes: 0600');
});

test('writeFileAtomic: an invalid current file never overwrites the last good .bak', () => {
  const d = dir(); const p = join(d, 'store.json');
  writeFileAtomic(p, '{"v":1}');
  writeFileAtomic(p, '{"v":2}');                        // .bak = v1
  writeFileSync(p, TORN);                               // something else tore it
  writeFileAtomic(p, '{"v":3}');
  assert.equal(readFileSync(`${p}.bak`, 'utf8'), '{"v":1}');
});

test('readJsonStrict: missing → empty, valid → parsed, torn → throws and leaves the file alone', () => {
  const d = dir(); const p = join(d, 'ratchet-sessions.json');
  assert.deepEqual(readJsonStrict(p, {}), {});
  writeFileSync(p, '{"peer":{"n":3}}');
  assert.deepEqual(readJsonStrict(p, {}), { peer: { n: 3 } });
  writeFileSync(p, TORN);
  assert.throws(() => readJsonStrict(p, {}), /not valid JSON.*refusing/);
  assert.equal(readFileSync(p, 'utf8'), TORN);
});

test('HeadlessStore: a torn store.json aborts instead of starting fresh (address book survives)', () => {
  const d = dir(); const p = join(d, 'store.json');
  writeFileSync(p, TORN);
  assert.throws(() => new HeadlessStore({ path: p }), /not valid JSON/);
  assert.equal(readFileSync(p, 'utf8'), TORN, 'the file must be untouched');
});

test('HeadlessStore: missing file = empty book; mutations persist atomically with a .bak', () => {
  const d = dir(); const p = join(d, 'store.json');
  const s = new HeadlessStore({ path: p });
  s.upsertContact({ id: 'c1', fingerprint: 'fp1', name: 'one' } as never);
  s.upsertContact({ id: 'c2', fingerprint: 'fp2', name: 'two' } as never);
  const reloaded = new HeadlessStore({ path: p });
  assert.ok(reloaded.getContactByFingerprint('fp1') && reloaded.getContactByFingerprint('fp2'));
  assert.equal(JSON.parse(readFileSync(`${p}.bak`, 'utf8')).contacts.length, 1);
  assert.equal(statSync(p).mode & 0o777, 0o600);
});

test('ratchet state: backup:false leaves nothing to restore, and the error forbids restoring', () => {
  const d = dir(); const p = join(d, 'ratchet-sessions.json');
  writeFileAtomic(p, '{"peer":{"n":1}}', { backup: false });
  writeFileAtomic(p, '{"peer":{"n":2}}', { backup: false });
  assert.deepEqual(readdirSync(d), ['ratchet-sessions.json']);
  writeFileSync(p, TORN);
  assert.throws(() => readJsonStrict(p, {}, RATCHET_HINT), /Do NOT restore a backup of ratchet state/);
});

test('writeFileAtomic: a stale tmp from a crashed run (even a symlink) is replaced, never followed', () => {
  const d = dir(); const p = join(d, 'gate.json'); const victim = join(d, 'victim');
  writeFileSync(victim, 'keep');
  symlinkSync(victim, `${p}.tmp.${process.pid}`);
  writeFileAtomic(p, '{"ok":true}');
  assert.equal(readFileSync(victim, 'utf8'), 'keep');
  assert.equal(readFileSync(p, 'utf8'), '{"ok":true}');
});
