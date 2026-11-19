// src/lib/identity/restored-from-old-backup.test.ts: the marker's shape, the write rule and the show rule (all pure), plus the static guards on where it may and may not travel.
// Run: npx tsx --test src/lib/identity/restored-from-old-backup.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { markerForRestore, parseRestoredFromOldBackup, shouldShowRestoredNudge, type OwnerRecordRead, type RestoredFromOldBackup } from './restored-from-old-backup';

const NOW = new Date('2026-11-19T17:30:00.000Z');
const GOOD: RestoredFromOldBackup = { v: 1, restored_at: '2026-11-19T17:30:00.000Z' };
const src = (rel: string): string => readFileSync(new URL(rel, import.meta.url), 'utf8');

test('P1 the strict reader accepts exactly {v:1, restored_at: plain ISO time}, and nothing else', () => {
  assert.deepEqual(parseRestoredFromOldBackup(GOOD), GOOD);
  assert.deepEqual(parseRestoredFromOldBackup({ v: 1, restored_at: '2026-11-19T17:30:00Z' }), { v: 1, restored_at: '2026-11-19T17:30:00Z' });
  const bad: unknown[] = [
    null, undefined, 0, 'x', [], [GOOD],
    {}, { v: 1 }, { restored_at: GOOD.restored_at },
    { v: 2, restored_at: GOOD.restored_at }, { v: '1', restored_at: GOOD.restored_at }, { v: true, restored_at: GOOD.restored_at },
    { v: 1, restored_at: GOOD.restored_at, extra: 1 },
    { v: 1, restored_at: null }, { v: 1, restored_at: 5 }, { v: 1, restored_at: '' },
    { v: 1, restored_at: '2026-11-19' }, { v: 1, restored_at: '2026-11-19T17:30:00' }, { v: 1, restored_at: '2026-11-19T17:30:00+01:00' },
    { v: 1, restored_at: '2026-11-19T17:30:00.0000Z' }, { v: 1, restored_at: ' 2026-11-19T17:30:00Z' }, { v: 1, restored_at: GOOD.restored_at + '\n' },
    { v: 1, restored_at: 'x'.repeat(10_000) },
  ];
  for (const b of bad) assert.equal(parseRestoredFromOldBackup(b), null, JSON.stringify(b)?.slice(0, 80));
});

test('P2 a restore leaves the marker ONLY for an older-format file (3) that carried a recovery vault', () => {
  assert.deepEqual(markerForRestore(3, { shards: [] }, NOW), GOOD);
  assert.deepEqual(markerForRestore(3, 'sealed-vault-bytes', NOW), GOOD);
  // The current format and an unknown header: no marker. An unreadable header must not read as "older".
  for (const v of [4, 5, 2, 0, undefined]) assert.equal(markerForRestore(v, { shards: [] }, NOW), null, `header ${String(v)}`);
  // An older file with NO recovery vault: a new backup from that device has no recovery envelope, so the notice would promise what the file cannot keep.
  for (const r of [null, undefined, 0, '', false]) assert.equal(markerForRestore(3, r, NOW), null, `recovery ${String(r)}`);
});

test('P3 the notice shows only for a readable marker that was not dismissed this session; absent and unreadable show nothing', () => {
  const ok: OwnerRecordRead<RestoredFromOldBackup> = { state: 'ok', value: GOOD };
  assert.equal(shouldShowRestoredNudge(ok, false), true);
  assert.equal(shouldShowRestoredNudge(ok, true), false, 'dismissed hides it for this session');
  assert.equal(shouldShowRestoredNudge({ state: 'absent' }, false), false);
  assert.equal(shouldShowRestoredNudge({ state: 'unreadable' }, false), false);
  assert.equal(shouldShowRestoredNudge({ state: 'absent' }, true), false);
  assert.equal(shouldShowRestoredNudge({ state: 'unreadable' }, true), false);
});

test('P4 the pure file imports nothing and reads no clock of its own (the caller passes the time)', () => {
  const s = src('./restored-from-old-backup.ts').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
  assert.doesNotMatch(s, /^\s*import\s/m, 'no imports');
  assert.doesNotMatch(s, /Date\.now\(|new Date\(\s*\)/, 'no clock');
});

test('P5 the record is sealed like its neighbours: reserved id, its own key prefix, one write, one clear, listed in OWNER_SEALED_SETTINGS', () => {
  const store = src('./client-store.ts');
  assert.match(store, /const RESTORED_FROM_OLD_BACKUP_RECORD_ID = 'owner:restored-from-old-backup';/);
  assert.match(store, /return `restored_from_old_backup:\$\{ownerFingerprint\}`;/);
  assert.match(store, /\{ name: 'restored-from-old-backup', recordId: RESTORED_FROM_OLD_BACKUP_RECORD_ID, settingKey: restoredFromOldBackupSettingKey \},/);
  // The write refuses a locked session (never unsealed) and seals under the reserved id with the owner as authenticated data.
  const w = store.slice(store.indexOf('export async function writeRestoredFromOldBackup'), store.indexOf('export async function clearRestoredFromOldBackup'));
  assert.match(w, /if \(!_sessionKey\) throw new Error\(/);
  assert.match(w, /encryptContactRecord\(_sessionKey, RESTORED_FROM_OLD_BACKUP_RECORD_ID, ownerFingerprint, marker\)/);
  assert.equal((store.match(/txPut\('settings', \{ key: restoredFromOldBackupSettingKey\(/g) ?? []).length, 1, 'one write site');
  assert.equal((store.match(/txDelete\('settings', restoredFromOldBackupSettingKey\(/g) ?? []).length, 1, 'one clear site');
});

test('P6 the marker NEVER travels: neither exportAll nor the vault payload names it', () => {
  const store = src('./client-store.ts');
  const a = store.indexOf('export async function exportAll');
  assert.ok(a >= 0, 'exportAll exists');
  const rest = store.slice(a + 1);
  const next = rest.search(/\nexport (async )?function /);
  const body = store.slice(a, next < 0 ? undefined : a + 1 + next);
  assert.doesNotMatch(body, /RestoredFromOldBackup|restored_from_old_backup|restoredFromOldBackup/, 'exportAll does not carry it');
  const dialog = src('../../components/export/VaultExportDialog.tsx');
  const pack = dialog.slice(dialog.indexOf('const trustGraph = {'), dialog.indexOf('await packVault(contents, password)'));
  assert.ok(pack.length > 200, 'the payload block was found');
  assert.doesNotMatch(pack, /RestoredFromOldBackup|restored_from_old_backup|restoredFromOldBackup/, 'the vault payload does not carry it');
});

test('P7 the READ goes through the strict reader under the reserved id: a row that is not exactly the marker is unreadable, never taken for one', () => {
  const store = src('./client-store.ts');
  assert.match(
    store,
    /export const readRestoredFromOldBackup = \(ownerFingerprint: string\): Promise<SealedRead<RestoredFromOldBackup>> =>\s*readSealed\(ownerFingerprint, restoredFromOldBackupSettingKey\(ownerFingerprint\), RESTORED_FROM_OLD_BACKUP_RECORD_ID, parseRestoredFromOldBackup\);/,
  );
});
