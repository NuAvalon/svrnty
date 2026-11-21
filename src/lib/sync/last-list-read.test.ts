// Run: npx tsx --test src/lib/sync/last-list-read.test.ts
// The last read of the satellite's allowed list, kept IN MEMORY so the owner's panel can show what the revoke check last saw without making a request of its own.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { recordListRead, lastListRead, resetLastListRead } from './last-list-read';
import { lockSession, setActiveFingerprint } from '@/lib/identity/client-store';
import type { AllowedListResult } from './allowed-sync';

const OK: AllowedListResult = { status: 'ok', fps: ['a'.repeat(64), 'b'.repeat(64)] };

test('RHL1 recordListRead hands the result back UNCHANGED (the same object): the drain sees exactly what it saw before, and lastListRead holds it with the time', () => {
  resetLastListRead();
  assert.equal(lastListRead('owner'), undefined, 'nothing read yet');
  assert.equal(recordListRead('owner', OK, 1_000), OK);
  assert.deepEqual(lastListRead('owner'), { result: OK, at: 1_000 });
  for (const r of [{ status: 'gone' } as const, { status: 'unknown' } as const]) assert.equal(recordListRead('owner', r, 2_000), r);
});

test('RHL2 the LAST read wins, whatever it said: an unknown after an ok means the panel must say it could not check, not show the older list', () => {
  resetLastListRead();
  recordListRead('owner', OK, 1_000);
  recordListRead('owner', { status: 'unknown' }, 5_000);
  assert.deepEqual(lastListRead('owner'), { result: { status: 'unknown' }, at: 5_000 });
});

test('RHL3 owners are kept apart, and a reset forgets everything', () => {
  resetLastListRead();
  recordListRead('one', OK, 1);
  recordListRead('two', { status: 'gone' }, 2);
  assert.equal(lastListRead('one')?.result.status, 'ok');
  assert.equal(lastListRead('two')?.result.status, 'gone');
  resetLastListRead();
  assert.equal(lastListRead('one'), undefined);
});

test('RHL4 SHAPE: the recorder keeps the list in memory only (no storage, no logging, no network); its ONLY tie to the identity store is the one lock registration', () => {
  const src = readFileSync('src/lib/sync/last-list-read.ts', 'utf8').replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, '');
  assert.doesNotMatch(src, /localStorage|sessionStorage|indexedDB|console\.|\bfetch\b|document\.cookie/);
  assert.equal((src.match(/client-store/g) ?? []).length, 1, 'one mention of the identity store');
  assert.match(src, /import \{ onSessionLock \} from '@\/lib\/identity\/client-store';/);
  assert.match(src, /onSessionLock\(resetLastListRead\);/, 'registered once, at module load (the hook list is append-only)');
});

test('RHL8 LOCK and LOGOUT (lockSession) clear every owner\'s last read: a locked device shows nothing of the owner\'s graph, so the panel can only say it could not check', () => {
  resetLastListRead();
  recordListRead('A', OK, 1); recordListRead('B', OK, 2);
  lockSession();
  assert.equal(lastListRead('A'), undefined);
  assert.equal(lastListRead('B'), undefined);
});

test('RHL9 an IDENTITY SWITCH (setActiveFingerprint, the one chokepoint that restore and import also go through) clears the last read BEFORE the write, so the new owner never sees the old owner\'s', async () => {
  resetLastListRead();
  recordListRead('A', OK, 1);
  try { await setActiveFingerprint('b'.repeat(64)); } catch { /* the write needs IndexedDB; the hook fires first */ }
  assert.equal(lastListRead('A'), undefined);
  assert.equal(lastListRead('B'), undefined, 'and B has nothing of A\'s');
});
