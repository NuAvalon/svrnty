// src/lib/identity/old-backup-wiring.test.ts: static pins on where the "restored from an older backup" marker is written, read and cleared, and on how the notice is mounted.
// The pure rules are in restored-from-old-backup.test.ts. Run: npx tsx --test src/lib/identity/old-backup-wiring.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = new URL('../../../', import.meta.url).pathname; // repo root
const read = (rel: string): string => readFileSync(join(ROOT, rel), 'utf8');
const strip = (s: string): string => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');

const walk = (dir: string): string[] => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f);
  if (statSync(p).isDirectory()) return f === 'node_modules' || f === '.next' ? [] : walk(p);
  return /\.(ts|tsx)$/.test(f) && !/\.(test|selftest)\.(ts|tsx)$/.test(f) ? [p] : [];
});
const NON_TEST = [...walk(join(ROOT, 'src')), ...walk(join(ROOT, 'app'))].map((p) => p.slice(ROOT.length));
const callers = (re: RegExp): string[] => NON_TEST.filter((f) => re.test(strip(read(f)))).sort();

test('OW1 the marker is WRITTEN by exactly one caller: the older-format branch of the passphrase restore, only through markerForRestore', () => {
  assert.deepEqual(callers(/\bwriteRestoredFromOldBackup\(/), ['src/lib/identity/client-store.ts', 'src/components/SoverentityFrontend.tsx'].sort());
  const s = strip(read('src/components/SoverentityFrontend.tsx'));
  assert.equal((s.match(/writeRestoredFromOldBackup\(/g) ?? []).length, 1);
  assert.match(s, /const marker = markerForRestore\(vaultHeader\?\.version, contents\.recovery, new Date\(\)\);\s*if \(marker\) \{[\s\S]{0,200}writeRestoredFromOldBackup\(restored\.fingerprint, marker\)/);
});

test('OW2 the marker is written BEFORE the identity is set (setting the identity mounts the tab that reads it once)', () => {
  const s = strip(read('src/components/SoverentityFrontend.tsx'));
  const w = s.indexOf('writeRestoredFromOldBackup(restored.fingerprint, marker)');
  const set = s.indexOf('setIdentity(contents.identity);', w);
  assert.ok(w > 0 && set > w, 'the write comes before the next setIdentity(contents.identity)');
  assert.equal(s.slice(w - 6, w), 'await ', 'and it is awaited');
});

test('OW3 the marker is CLEARED by exactly one caller: the export dialog\'s success path, after the file is handed over and before onDownloaded', () => {
  assert.deepEqual(callers(/\bclearRestoredFromOldBackup\(/), ['src/components/export/VaultExportDialog.tsx', 'src/lib/identity/client-store.ts']);
  const s = strip(read('src/components/export/VaultExportDialog.tsx'));
  assert.equal((s.match(/clearRestoredFromOldBackup\(/g) ?? []).length, 1);
  const d = s.indexOf('downloadVault(packed);');
  const c = s.indexOf('await clearRestoredFromOldBackup(fingerprint);');
  const n = s.indexOf('onDownloaded?.();');
  assert.ok(d > 0 && c > d && n > c, 'downloadVault, then the clear, then onDownloaded');
});

test('OW4 the marker is READ by exactly one component (the reminder), and the reminder is mounted once, for an existing identity only', () => {
  // (The store defines the reader as a constant arrow, so only a CALL matches `name(`: the one caller is the reminder.)
  assert.deepEqual(callers(/\breadRestoredFromOldBackup\(/), ['src/components/export/OldBackupReminder.tsx']);
  assert.deepEqual(callers(/<OldBackupReminder\b/), ['src/components/SoverentityFrontend.tsx']);
  const s = strip(read('src/components/SoverentityFrontend.tsx'));
  assert.equal((s.match(/<OldBackupReminder\b/g) ?? []).length, 1);
  assert.match(s, /\{existingIdentity && identity\?\.identity\?\.fingerprint \? \(\s*<OldBackupReminder/);
});

test('OW5 "Make a new backup" opens the existing Full Backup dialog and NOTHING else', () => {
  const s = strip(read('src/components/SoverentityFrontend.tsx'));
  const i = s.indexOf('<OldBackupReminder');
  const mount = s.slice(i, s.indexOf('/>', i));
  assert.match(mount, /onMakeBackup=\{\(\) => setShowVaultExportDialog\(true\)\}/);
  assert.doesNotMatch(mount.replace('onMakeBackup={() => setShowVaultExportDialog(true)}', ''), /setShowVaultExportDialog|clearRestored|writeRestored/);
});

test('OW6 Not now is the PAGE\'s session flag: it never touches the stored marker, and the page resets it when the identity changes', () => {
  const rem = strip(read('src/components/export/OldBackupReminder.tsx'));
  assert.doesNotMatch(rem, /clearRestoredFromOldBackup|writeRestoredFromOldBackup/);
  const page = strip(read('app/page.tsx'));
  assert.match(page, /const \[oldBackupNoticeDismissed, setOldBackupNoticeDismissed\] = useState\(false\);/);
  assert.match(page, /useEffect\(\(\) => \{ setOldBackupNoticeDismissed\(false\); \}, \[noteIdentityFp\]\);/);
  assert.equal((page.match(/onOldBackupNoticeDismiss=\{/g) ?? []).length, 1, 'passed to one mount: the Identity tab, not the gate');
  const tab = page.indexOf('<TabsContent value="identity">');
  assert.ok(page.indexOf('onOldBackupNoticeDismiss={') > tab, 'and that mount is inside the identity tab');
});

test('OW7 a finished export makes the notice look again: onDownloaded bumps the tick the reminder keys its read on', () => {
  const s = strip(read('src/components/SoverentityFrontend.tsx'));
  assert.match(s, /onDownloaded=\{\(\) => \{[\s\S]{0,200}setBackupWrittenTick\(\(n\) => n \+ 1\);/);
  assert.match(s, /reloadKey=\{backupWrittenTick\}/);
});
