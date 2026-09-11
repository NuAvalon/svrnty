// Cloud-backup shell: target parse, status, claim-honesty, device-local-only payload.
// Run: npx tsx --test src/components/backup/cloud-backup-targets.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  CLOUD_BACKUP_COPY,
  CLOUD_BACKUP_TARGETS,
  clearCloudBackupTarget,
  connectCloudBackupTarget,
  formatBackupStatus,
  isCloudBackupTargetId,
  isCloudBlobTransportLive,
  loadCloudBackupStatus,
  loadCloudBackupTarget,
  parseCloudBackupStatus,
  parseCloudBackupTarget,
  recordCloudBackupAttempt,
  resetCloudBackupStoreForTests,
  serializeCloudBackupStatus,
  serializeCloudBackupTarget,
} from './cloud-backup-targets';

test('queue targets are Dropbox, iCloud, Google Drive — not a live transport', () => {
  assert.deepEqual(
    CLOUD_BACKUP_TARGETS.map((t) => t.id),
    ['dropbox', 'icloud', 'google-drive'],
  );
  assert.equal(isCloudBlobTransportLive(), false);
  assert.equal(isCloudBackupTargetId('webdav'), false);
  assert.equal(isCloudBackupTargetId('dropbox'), true);
});

test('parse target: json wrapper or bare id; reject junk', () => {
  assert.equal(parseCloudBackupTarget(null), null);
  assert.equal(parseCloudBackupTarget('{"target":"icloud"}'), 'icloud');
  assert.equal(parseCloudBackupTarget('google-drive'), 'google-drive');
  assert.equal(parseCloudBackupTarget('{"target":"s3"}'), null);
  assert.equal(parseCloudBackupTarget('{'), null);
});

test('parse status: file-kind only; reject extra capability shapes', () => {
  const ok = parseCloudBackupStatus(
    JSON.stringify({ at: '2026-09-11T20:00:00.000Z', ok: true, target: 'dropbox', kind: 'file' }),
  );
  assert.deepEqual(ok, {
    at: '2026-09-11T20:00:00.000Z',
    ok: true,
    target: 'dropbox',
    kind: 'file',
  });
  assert.equal(
    parseCloudBackupStatus(
      JSON.stringify({ at: '2026-09-11T20:00:00.000Z', ok: true, target: 'dropbox', kind: 'cloud-upload' }),
    ),
    null,
  );
  assert.equal(parseCloudBackupStatus('not-json'), null);
});

test('format status is file-honest (never "uploaded to")', () => {
  assert.equal(formatBackupStatus(null), CLOUD_BACKUP_COPY.statusEmpty);
  const line = formatBackupStatus({
    at: '2026-09-11T20:04:00.000Z',
    ok: true,
    target: 'dropbox',
    kind: 'file',
  });
  assert.match(line, /Last backup: 2026-09-11 20:04:00 UTC/);
  assert.match(line, /Saved as a file on this device/);
  assert.doesNotMatch(line, /uploaded/i);
  assert.doesNotMatch(line, /synced/i);
  assert.doesNotMatch(line, /Dropbox/);
});

test('connect + record round-trip in the store', () => {
  resetCloudBackupStoreForTests();
  assert.equal(loadCloudBackupTarget(), null);
  connectCloudBackupTarget('icloud');
  assert.equal(loadCloudBackupTarget(), 'icloud');
  recordCloudBackupAttempt({
    ok: true,
    target: 'icloud',
    at: '2026-09-11T12:00:00.000Z',
  });
  assert.deepEqual(loadCloudBackupStatus(), {
    at: '2026-09-11T12:00:00.000Z',
    ok: true,
    target: 'icloud',
    kind: 'file',
  });
  clearCloudBackupTarget();
  assert.equal(loadCloudBackupTarget(), null);
  resetCloudBackupStoreForTests();
});

test('NEGATIVE: serialized preference/status never carry tags, contacts, keys, or tokens', () => {
  const targetJson = serializeCloudBackupTarget('dropbox');
  const statusJson = serializeCloudBackupStatus({
    at: '2026-09-11T20:00:00.000Z',
    ok: true,
    target: 'dropbox',
    kind: 'file',
  });
  for (const blob of [targetJson, statusJson]) {
    assert.doesNotMatch(blob, /tags/i);
    assert.doesNotMatch(blob, /blocked/i);
    assert.doesNotMatch(blob, /contact/i);
    assert.doesNotMatch(blob, /token/i);
    assert.doesNotMatch(blob, /passphrase|privateKey|recovery/i);
    assert.doesNotMatch(blob, /owner_local/);
  }
  const targetObj = JSON.parse(targetJson) as Record<string, unknown>;
  const statusObj = JSON.parse(statusJson) as Record<string, unknown>;
  assert.deepEqual(Object.keys(targetObj).sort(), ['target']);
  assert.deepEqual(Object.keys(statusObj).sort(), ['at', 'kind', 'ok', 'target']);
});

test('claim-honesty: copy does not claim crypto or live cloud send', () => {
  const joined = Object.values(CLOUD_BACKUP_COPY).join('\n');
  assert.doesNotMatch(joined, /post-quantum/i);
  assert.doesNotMatch(joined, /end-to-end/i);
  assert.doesNotMatch(joined, /seamless/i);
  assert.doesNotMatch(joined, /social recovery/i);
  assert.doesNotMatch(joined, /\bverified\b/i);
  assert.doesNotMatch(joined, /automatically/i);
  assert.match(CLOUD_BACKUP_COPY.intro, /not multi-device sync/);
  assert.match(CLOUD_BACKUP_COPY.transportPending, /not wired yet/);
});

test('shell source does not call cloud adapters or vault packers', () => {
  const dir = dirname(fileURLToPath(import.meta.url));
  const shell = readFileSync(join(dir, 'CloudBackupShell.tsx'), 'utf8');
  const store = readFileSync(join(dir, 'cloud-backup-targets.ts'), 'utf8');
  for (const src of [shell, store]) {
    assert.doesNotMatch(src, /from ['"]@\/lib\/sync\/cloud/);
    assert.doesNotMatch(src, /packVault\(|unpackVault\(/);
    assert.doesNotMatch(src, /accessToken|clientSecret/);
    assert.doesNotMatch(src, /innerHTML|dangerouslySetInnerHTML/);
  }
});
