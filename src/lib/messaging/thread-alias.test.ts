// src/lib/messaging/thread-alias.test.ts: the pure alias row (thread-alias.ts) and its static pins. The alias is local metadata that pairs a sender with someone else's thread id.
// Run: npx tsx --test src/lib/messaging/thread-alias.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { MAX_CLAIMED_ID_LENGTH, MAX_THREAD_ALIASES, THREAD_ALIAS_PREFIX, aliasFor, parseThreadAliasRow, threadAliasKey, withAlias, type ThreadAliasRow } from './thread-alias';

const FP = 'ab'.repeat(32);
const FP2 = 'cd'.repeat(32);

test('A1 the key is the prefix plus the sender fingerprint in lowercase hex (the shared normaliser: a key is never built from raw text); anything that is not hex has no key', () => {
  assert.equal(threadAliasKey(FP), `${THREAD_ALIAS_PREFIX}${FP}`);
  assert.equal(threadAliasKey(FP.toUpperCase()), `${THREAD_ALIAS_PREFIX}${FP}`, 'case is normalised, so one sender is one row');
  for (const bad of ['', 'not-hex', 'xyz', 'ab cd', 'ab/cd', null, undefined, 7, {}]) assert.equal(threadAliasKey(bad), null, JSON.stringify(bad));
});

test('A2 the row is STRICT: exactly {fp, entries}, entries exactly {c, l}, bounded; anything else is absent, never repaired', () => {
  const ok: ThreadAliasRow = { fp: FP, entries: [{ c: 'T1', l: 'L1' }] };
  assert.deepEqual(parseThreadAliasRow(ok), ok);
  assert.deepEqual(parseThreadAliasRow({ fp: FP, entries: [] }), { fp: FP, entries: [] });
  const bad: unknown[] = [
    null, 'x', [], 7, {}, { fp: FP }, { entries: [] }, { fp: FP, entries: [], extra: 1 }, { fp: FP.toUpperCase(), entries: [] }, { fp: 'nope', entries: [] },
    { fp: FP, entries: 'x' }, { fp: FP, entries: [null] }, { fp: FP, entries: [{ c: 'a' }] }, { fp: FP, entries: [{ c: 'a', l: 'b', z: 1 }] },
    { fp: FP, entries: [{ c: '', l: 'b' }] }, { fp: FP, entries: [{ c: 'a', l: '' }] }, { fp: FP, entries: [{ c: 5, l: 'b' }] },
    { fp: FP, entries: [{ c: 'a'.repeat(MAX_CLAIMED_ID_LENGTH + 1), l: 'b' }] },
    { fp: FP, entries: Array.from({ length: MAX_THREAD_ALIASES + 1 }, (_, i) => ({ c: `c${i}`, l: `l${i}` })) },
  ];
  for (const b of bad) assert.equal(parseThreadAliasRow(b), null, JSON.stringify(b)?.slice(0, 80));
});

test('A3 remembering is NEWEST FIRST, one entry per claimed id (a re-map replaces, never duplicates), and BOUNDED to the newest MAX entries', () => {
  let row: ThreadAliasRow | null = null;
  for (let i = 0; i < MAX_THREAD_ALIASES + 10; i++) row = withAlias(row, FP, `c${i}`, `l${i}`);
  assert.equal(row!.entries.length, MAX_THREAD_ALIASES, 'bounded');
  assert.equal(row!.entries[0].c, `c${MAX_THREAD_ALIASES + 9}`, 'newest first');
  assert.equal(aliasFor(row, 'c0'), null, 'the oldest were evicted: an evicted claimed id resolves to NOTHING (the caller then makes a fresh thread, never joins the original)');
  assert.equal(aliasFor(row, `c${MAX_THREAD_ALIASES + 9}`), `l${MAX_THREAD_ALIASES + 9}`);
  const again = withAlias(row, FP, 'c40', 'NEW');
  assert.equal(again!.entries.filter((e) => e.c === 'c40').length, 1, 'one entry per claimed id');
  assert.equal(again!.entries[0].l, 'NEW', 'and the re-mapped one is now the newest');
  assert.equal(again!.entries.length, MAX_THREAD_ALIASES);
});

test('A4 a claimed or local id that is empty or too long is NOT aliased (nothing is stored); an alias is per sender', () => {
  assert.equal(withAlias(null, FP, '', 'l'), null);
  assert.equal(withAlias(null, FP, 'c', ''), null);
  assert.equal(withAlias(null, FP, 'c'.repeat(MAX_CLAIMED_ID_LENGTH + 1), 'l'), null);
  assert.equal(withAlias(null, FP, 'c'.repeat(MAX_CLAIMED_ID_LENGTH), 'l')!.entries.length, 1, 'exactly the limit is fine');
  assert.notEqual(threadAliasKey(FP), threadAliasKey(FP2), 'two senders never share a row');
});

// ---- static pins: the alias is local metadata (it pairs a sender with someone else's thread id) and must never leave the device ----
const CWD = process.cwd();
const codeOnly = (t: string): string => t.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
function sources(dir: string, out: string[] = []): string[] {
  for (const n of readdirSync(dir)) {
    const p = join(dir, n);
    if (statSync(p).isDirectory()) { if (n !== 'node_modules' && n !== '.next') sources(p, out); continue; }
    if (/\.(ts|tsx)$/.test(n) && !/\.test\.(ts|tsx)$/.test(n) && !/\.d\.ts$/.test(n)) out.push(p);
  }
  return out;
}
const filesNaming = (needle: RegExp): string[] =>
  ['app', 'src'].flatMap((r) => (existsSync(join(CWD, r)) ? sources(join(CWD, r)) : [])).filter((f) => needle.test(codeOnly(readFileSync(f, 'utf8')))).map((f) => f.slice(CWD.length + 1)).sort();

test('A5 PIN: only the alias modules, the settings-key allowlist, the accept path and the live note seam name the alias; no backup, export, vault or sync module does', () => {
  assert.deepEqual(filesNaming(/thread[-_]alias|ThreadAlias|threadAlias/), [
    'src/lib/headless/headless-store.ts', // the headless agent's own accept path: the same pure rule, its alias kept in the headless book (headless-thread-membership.test.ts)
    'src/lib/messaging/settings-row-keys.ts',
    'src/lib/messaging/thread-alias-store.ts',
    'src/lib/messaging/thread-alias.ts',
    'src/lib/messaging/transport.ts',
    'src/lib/sync/live-book-poll.ts',
  ]);
  assert.deepEqual(filesNaming(/thread-alias-store/), ['src/lib/sync/live-book-poll.ts'], 'the store port is imported by the live seam alone');
});
