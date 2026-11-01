// Wiring FENCE for the heal of a pinned thread (thread-activity.ts: healedLastActivity). The IndexedDB-backed listThreads cannot run in a unit test
// here (there is no fake-indexeddb), so these read the source of store.ts and check that the pieces are connected. This is WEAKER than a test that runs
// the real store: it proves the calls are present, not that they behave. The behaviour is pinned in thread-activity.test.ts.
//
// Run: npx tsx --test src/lib/messaging/thread-activity-heal-wiring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC = readFileSync(join(process.cwd(), 'src/lib/messaging/store.ts'), 'utf8');
const body = (name: string) => {
  const start = SRC.indexOf(`function ${name}(`);
  assert.ok(start >= 0, `${name} exists`);
  const next = SRC.indexOf('\nexport ', start + 1);
  const next2 = SRC.indexOf('\nasync function ', start + 1);
  const ends = [next, next2].filter((i) => i > 0);
  return SRC.slice(start, ends.length ? Math.min(...ends) : undefined);
};

test('listThreads heals each pinned thread and sorts on the bounded value', () => {
  const b = body('listThreads');
  assert.match(b, /healPinnedThread\(/, 'listThreads calls healPinnedThread');
  assert.match(b, /activityMs\(/, 'the sort uses the bounded numeric key, not the raw stored text');
  assert.doesNotMatch(b, /localeCompare/, 'no string comparison of timestamps is left in the sort');
});

test('healPinnedThread re-reads the row, reads the notes, lowers via healedLastActivity and writes once', () => {
  const b = body('healPinnedThread');
  assert.match(b, /needsLastActivityHeal\(/, 'it skips a thread that needs no heal');
  assert.match(b, /txGet<ThreadRow>\('threads'/, 're-reads the row before writing (a note may have written its own time)');
  assert.match(b, /listNotesForThread\(/, 'reads the thread\'s own notes for the newest plausible time');
  assert.match(b, /healedLastActivity\(/, 'the value comes from the pure function');
  assert.match(b, /await putThread\(next\)/, 'it persists the lowered value');
  // A DELETED thread must never come back: deleteThread removes the notes first and the row last, so a list load that raced it can find no row.
  assert.match(b, /if \(!row\) return thread;/, 'a missing row returns without writing');
  assert.ok(b.indexOf('if (!row) return thread;') >= 0 && b.indexOf('if (!row) return thread;') < b.indexOf('await putThread(next)'), 'the no-row return comes BEFORE the write');
  assert.doesNotMatch(b, /row \? await decryptJson/, 'there is no fallback to the stale copy when the row is gone');
  assert.match(b, /catch/, 'it never throws into the list load');
});
