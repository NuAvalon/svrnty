// src/lib/messaging/held-readers.test.ts: static pins for Freeze keep (hold, don't discard). Like the other store fences here these READ source text: the
// IndexedDB-backed store cannot run in a unit test (no fake-indexeddb), so they prove the pieces are connected, not that they behave; the behaviour is
// run in a real browser by e2e/freeze-store.spec.ts.
//
// The point of the first pin: a held note is hidden from EVERY ordinary reader by default, and the few readers that can see one are separately named and
// listed here by file and count. A new caller (a screen, an export) fails this test until someone adds it on purpose, in review.
//
// Run: npx tsx --test src/lib/messaging/held-readers.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const walk = (dir: string): string[] =>
  readdirSync(join(ROOT, dir)).flatMap((name) => {
    const rel = `${dir}/${name}`;
    if (statSync(join(ROOT, rel)).isDirectory()) return walk(rel);
    return /\.(ts|tsx)$/.test(name) && !/\.test\./.test(name) ? [rel] : [];
  });
const SOURCES = [...walk('src'), ...walk('app')];
const text = (rel: string) => readFileSync(join(ROOT, rel), 'utf8');
const occurrences = (name: string): Record<string, number> => {
  const out: Record<string, number> = {};
  for (const f of SOURCES) {
    const n = (text(f).match(new RegExp(`\\b${name}\\b`, 'g')) || []).length;
    if (n) out[f] = n;
  }
  return out;
};
const STORE = text('src/lib/messaging/store.ts');
const body = (src: string, header: string): string => {
  const start = src.indexOf(header);
  assert.ok(start >= 0, `${header} exists`);
  const next = [src.indexOf('\nexport ', start + 1), src.indexOf('\nasync function ', start + 1), src.indexOf('\nfunction ', start + 1)].filter((i) => i > 0);
  return src.slice(start, next.length ? Math.min(...next) : undefined);
};

test('S1 the include-held readers are used ONLY where they are meant to be: exact files and counts (a 5th caller fails)', () => {
  // store.ts: the definition + the replay guard (listInboundSentAtFrom) + the cap count (countHeldFrom). Nothing else reads a held note by name.
  // When the hold view and the evidence export are built they add THEIR file here, in their own commit, with a reason.
  assert.deepEqual(occurrences('listNotesIncludingHeld'), { 'src/lib/messaging/store.ts': 3 });
  assert.deepEqual(occurrences('listThreadsIncludingHeld'), { 'src/lib/messaging/store.ts': 3 });
  // countHeldFrom: defined in store.ts; transport.ts uses it ONLY as the cap check (import, the io seam's type, and the one call).
  assert.deepEqual(occurrences('countHeldFrom'), { 'src/lib/messaging/store.ts': 1, 'src/lib/messaging/transport.ts': 5 });
});

test('S2 the DEFAULT readers drop held rows; the include-held readers keep them (both go through the one read function)', () => {
  assert.match(body(STORE, 'async function listNotesForThread('), /return readNotesForThread\(threadId, false\);/, 'the default note reader excludes held');
  assert.match(body(STORE, 'async function listNotesIncludingHeld('), /return readNotesForThread\(threadId, true\);/, 'the include-held note reader keeps them');
  const read = body(STORE, 'async function readNotesForThread(');
  assert.match(read, /if \(!includeHeld && isHeldNote\(note\)\) continue;/, 'the one read function is where held rows are dropped');
});

test('S3 a note\'s expiry goes through the shared rule only: no direct read of the SENDER-chosen expiry in the store (a held note never expires on it)', () => {
  assert.match(body(STORE, 'async function readNotesForThread('), /noteExpired\(note, now\)/, 'expiry is decided by noteExpired');
  assert.doesNotMatch(STORE, /note\.retention\.expires_at/, 'the store no longer reads the sender-set expiry itself');
});

test('S4 the replay guard sees HELD notes (it uses the include-held readers), so a replayed old first frame cannot replace the session', () => {
  const g = body(STORE, 'async function listInboundSentAtFrom(');
  assert.match(g, /listThreadsIncludingHeld\(\)/);
  assert.match(g, /listNotesIncludingHeld\(/);
  assert.doesNotMatch(g, /listNotesForThread\(|listThreads\(\)/, 'and it does not fall back to the default readers');
});

test('S5 no module but held-note.ts reads a NOTE\'s or THREAD\'s held key itself (it would disagree with isHeldNote, which means exactly true)', () => {
  // NAME-BASED, so weaker than a type-based fence: it catches `note.held`, `thread.held`, `n.held`, `t.held`, `rec.held`, `record.held`, `row.held`. Two unrelated
  // features already have a `.held` of their own (view.held for held ratchet frames, facts.held in the restore domain) and are deliberately not matched.
  const stray = SOURCES.filter((f) => f !== 'src/lib/messaging/held-note.ts').filter((f) => /\b(note|thread|n|t|rec|record|row)\.held\b/.test(text(f)));
  assert.deepEqual(stray, []);
});
