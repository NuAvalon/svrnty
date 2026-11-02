// Run: npx tsx --test src/lib/headless/join-backup.test.ts
// J5's backup rule (Flint #1444), tested DIRECTLY because the CLI cannot reach its error branches: anything that would make
// lstat throw (an unreadable directory) also breaks the store load that happens first.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, symlinkSync, existsSync, chmodSync, statSync, readdirSync, rmSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { backupStoreBeforeJoin } from './join-backup';

const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
function tmp<T>(fn: (dir: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), 'join-backup-'));
  try { return fn(dir); } finally { try { chmodSync(dir, 0o700); } catch { /* ignore */ } rmSync(dir, { recursive: true, force: true }); }
}
const AT = new Date('2026-10-25T11:04:16.789Z');

test('ENOENT (a brand-new agent, no store yet): skipped, nothing created', () => tmp((dir) => {
  const store = join(dir, 'store.json');
  assert.deepEqual(backupStoreBeforeJoin(store, AT), { skipped: true });
  assert.deepEqual(readdirSync(dir), []);
}));

test('a regular store: a dated copy with the same bytes, mode 0600, named store.json.bak-<UTC stamp>', () => tmp((dir) => {
  const store = join(dir, 'store.json');
  writeFileSync(store, '{"contacts":[1]}', { mode: 0o644 });
  const r = backupStoreBeforeJoin(store, AT);
  assert.equal(r.skipped, false);
  if (r.skipped) return;
  assert.equal(r.path, `${store}.bak-20261025T110416Z`);
  assert.equal(readFileSync(r.path, 'utf8'), '{"contacts":[1]}');
  assert.equal((statSync(r.path).mode & 0o777).toString(8), '600');
}));

test('a DANGLING symlink at the store path is refused, not skipped (existsSync would have said "missing")', () => tmp((dir) => {
  const store = join(dir, 'store.json');
  symlinkSync(join(dir, 'nowhere.json'), store);
  assert.equal(existsSync(store), false, 'precondition: this is exactly the case existsSync gets wrong');
  assert.throws(() => backupStoreBeforeJoin(store, AT), /symlink/);
  assert.deepEqual(readdirSync(dir).filter((f) => f.includes('.bak')), []);
  assert.equal(existsSync(join(dir, 'nowhere.json')), false);
}));

test('a symlink to a real file is refused too, and the target is untouched', () => tmp((dir) => {
  const target = join(dir, 'real.json'); writeFileSync(target, 'TARGET');
  const store = join(dir, 'store.json'); symlinkSync(target, store);
  assert.throws(() => backupStoreBeforeJoin(store, AT), /symlink/);
  assert.equal(readFileSync(target, 'utf8'), 'TARGET');
  assert.deepEqual(readdirSync(dir).filter((f) => f.includes('.bak')), []);
}));

test('any NON-ENOENT lstat error is rethrown, never skipped (an unsearchable parent directory -> EACCES)', (t) => {
  if (isRoot) { t.skip('root bypasses directory permissions'); return; }
  tmp((dir) => {
    const sub = join(dir, 'locked'); mkdirSync(sub);
    const store = join(sub, 'store.json'); writeFileSync(store, 'x');
    chmodSync(sub, 0o000);
    try { assert.throws(() => backupStoreBeforeJoin(store, AT), (e: NodeJS.ErrnoException) => e.code === 'EACCES'); }
    finally { chmodSync(sub, 0o700); }
  });
});

test('an existing store that cannot be READ makes the copy fail (refuse), it is not skipped', (t) => {
  if (isRoot) { t.skip('root can read mode-000 files'); return; }
  tmp((dir) => {
    const store = join(dir, 'store.json'); writeFileSync(store, 'x'); chmodSync(store, 0o000);
    try { assert.throws(() => backupStoreBeforeJoin(store, AT), (e: NodeJS.ErrnoException) => e.code === 'EACCES'); }
    finally { chmodSync(store, 0o600); }
    assert.deepEqual(readdirSync(dir).filter((f) => f.includes('.bak-')), []);
  });
});
