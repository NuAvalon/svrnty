// src/components/export/old-backup-copy.test.ts: the words about an older-format backup are the copy owner's bytes, and the screens render the constants only.
// Run: npx tsx --test src/components/export/old-backup-copy.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as copy from './old-backup-copy';

const h = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 16);
const read = (rel: string): string => readFileSync(new URL(rel, import.meta.url), 'utf8');
const code = (rel: string): string => read(rel).replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');

test('OB1 the four strings are the copy owner\'s bytes (length + sha256 prefix) and plain ASCII', () => {
  const rows: Array<[string, string, number, string]> = [
    ['329a pre-restore hint', copy.OLD_BACKUP_PRE_RESTORE_HINT, 175, '697091a9f466eb77'],
    ['329b notice', copy.OLD_BACKUP_NOTICE, 169, 'de59608988bc7d47'],
    ['329b button make', copy.OLD_BACKUP_MAKE_NEW, 17, 'd98cf9e9ac8384b2'],
    ['329b button not now', copy.OLD_BACKUP_NOT_NOW, 7, 'a0e63d7c7125d29a'],
  ];
  for (const [name, text, len, sha] of rows) {
    assert.equal(text.length, len, `${name} length`);
    assert.equal(h(text), sha, `${name} hash`);
    assert.match(text, /^[\x20-\x7e]+$/, `${name} is plain ASCII (straight apostrophes, no dashes)`);
  }
});

test('OB2 no format number and no promise that is not built: neither "v3" nor "social"/"shard"/"guardian" is in any string the screen shows', () => {
  for (const v of Object.values(copy)) assert.doesNotMatch(String(v), /\bv\d|social|shard|guardian|friends/i);
});

test('OB3 the two buttons are exactly Make a new backup / Not now, and there is no default, no autofocus and no "Dismiss"', () => {
  assert.equal(copy.OLD_BACKUP_MAKE_NEW, 'Make a new backup');
  assert.equal(copy.OLD_BACKUP_NOT_NOW, 'Not now');
  assert.doesNotMatch(code('./OldBackupNotice.tsx') + code('./old-backup-copy.ts'), /Dismiss|autoFocus|defaultChecked/);
});

test('OB4 the notice file spells no sentence of its own: it renders the constants only', () => {
  const src = code('./OldBackupNotice.tsx');
  assert.doesNotMatch(src, />\s*[A-Za-z][^<>{}]*\s[^<>{}]*</, 'no literal text between tags');
  const lits = [...src.matchAll(/(['"`])((?:(?!\1).)*)\1/g)].map((m) => m[2]);
  assert.deepEqual(lits.filter((t) => /[A-Z][a-z]+( [a-z']+){2,}/.test(t)), [], 'no quoted sentence');
});

test('OB5 the old English is gone from every screen file: no "v3" notice text, no "Re-export" paragraph, no old nudge state', () => {
  for (const f of ['../SoverentityFrontend.tsx', './VaultExportDialog.tsx', '../../../app/page.tsx']) {
    const s = read(f);
    assert.doesNotMatch(s, /opened from a v3 backup|Update your backup to enable|Re-export your identity|showV3MigrationNudge/, f);
  }
});

test('OB6 the pre-restore hint is the constant, shown once, from the restore screen\'s old-format branch', () => {
  const s = read('../SoverentityFrontend.tsx');
  assert.equal((s.match(/\{OLD_BACKUP_PRE_RESTORE_HINT\}/g) ?? []).length, 1);
  const i = s.indexOf('{OLD_BACKUP_PRE_RESTORE_HINT}');
  assert.match(s.slice(Math.max(0, i - 400), i), /\{isV3Vault && \(/, 'inside the older-format branch');
});
