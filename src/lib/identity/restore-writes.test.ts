// What a failed restore left on the device: the verdict from two snapshots. A snapshot that could not be read is "unknown", never "unchanged".
// Run: node --import tsx --test src/lib/identity/restore-writes.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { restoreWritesVerdict, restoreWritesOf, tagRestoreWrites, type OwnerSnapshot } from './restore-writes';

const snap = (over: Partial<Record<string, { n: number; d: string }>> = {}): OwnerSnapshot => ({
  identities: { n: 1, d: 'a' }, keys: { n: 1, d: 'b' }, contacts: { n: 2, d: 'c' }, 'contact-manifest': { n: 1, d: 'd' },
  ...(over as OwnerSnapshot),
});

test('W1 identical snapshots = none; a different count or digest in ANY place = some', () => {
  assert.equal(restoreWritesVerdict(snap(), snap()), 'none');
  assert.equal(restoreWritesVerdict(snap(), snap({ contacts: { n: 3, d: 'c' } })), 'some', 'a row added');
  assert.equal(restoreWritesVerdict(snap(), snap({ keys: { n: 1, d: 'changed' } })), 'some', 'a row rewritten');
  assert.equal(restoreWritesVerdict(snap({ keys: { n: 0, d: 'e' } }), snap()), 'some', 'a first write on an empty store');
  const withExtra = { ...snap(), shards: { n: 1, d: 'z' } };
  assert.equal(restoreWritesVerdict(snap(), withExtra), 'some', 'a place only one side has');
});

test('W2 a snapshot that could not be read (either side) is unknown, never none', () => {
  assert.equal(restoreWritesVerdict(null, snap()), 'unknown');
  assert.equal(restoreWritesVerdict(snap(), null), 'unknown');
  assert.equal(restoreWritesVerdict(null, null), 'unknown');
});

test('W3 the verdict rides on the thrown error and is read back from it; an untagged error has none', () => {
  const e = new Error('boom');
  assert.equal(restoreWritesOf(e), undefined);
  tagRestoreWrites(e, 'some');
  assert.equal(restoreWritesOf(e), 'some');
  assert.equal(restoreWritesOf('a string'), undefined);
  assert.equal(restoreWritesOf(null), undefined);
  assert.doesNotThrow(() => tagRestoreWrites('a string', 'none'));
});

// The order in importAllWithPassword: the owner-domain check, then the session, then the snapshot, then the first owner-record write; and the failure path.
const src = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
const fn = (() => {
  const a = src.indexOf('export async function importAllWithPassword(');
  const b = src.indexOf('/**\n * Persist an already-decrypted .svrnty VaultContents', a);
  assert.ok(a >= 0 && b > a, 'importAllWithPassword is found');
  return src.slice(a, b);
})();
const at = (s: string) => { const i = fn.indexOf(s); assert.ok(i >= 0, `${s} is in importAllWithPassword`); return i; };

test('W4 the snapshot is taken after the session step and before the first write; an unreadable snapshot is null, and the failure is tagged from a comparison', () => {
  assert.ok(at('initSessionKey(use)') < at('snapshotOwnerRows(fingerprint)'), 'the snapshot comes after the session step');
  assert.ok(at('snapshotOwnerRows(fingerprint)') < at('importAll(backup)'), 'and before the first write');
  assert.match(fn, /try \{ before = await snapshotOwnerRows\(fingerprint\); \} catch \{ before = null; \}/, 'a snapshot that throws is null (unknown)');
  assert.match(fn, /try \{ after = await snapshotOwnerRows\(fingerprint\); \} catch \{ after = null; \}/, 'so is the compare side');
  assert.match(fn, /tagRestoreWrites\(err, restoreWritesVerdict\(before, after\)\)/, 'the verdict is the comparison of the two');
});
