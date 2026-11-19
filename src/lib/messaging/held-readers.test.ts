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
import { join, dirname, normalize } from 'node:path';

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
  // store.ts: the definition + the replay guard (listInboundSentAtFrom) + the cap count (countHeldFrom) + deleteThread (it must SEE the held notes to leave them,
  // and to keep the thread row they hang on). Nothing else reads a held note by name.
  // When the hold view and the evidence export are built they add THEIR file here, in their own commit, with a reason.
  assert.deepEqual(occurrences('listNotesIncludingHeld'), { 'src/lib/messaging/store.ts': 4 });
  assert.deepEqual(occurrences('listThreadsIncludingHeld'), { 'src/lib/messaging/store.ts': 3, 'src/lib/messaging/transport.ts': 7 }); // transport = the accept path reading threads INCLUDING held ones, twice: (1) the claimed thread's participants (thread membership: a sender who is not in the thread they name never joins it), (2) finding the note's thread. 1 import + 2 per read in the injectable io field (name, type) + 2 in the ONE call (injected, default)
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

test('S6 deleteThread deletes what the owner can SEE and leaves every held note, keeping their thread row (flagged held) so the include-held readers can still find them', () => {
  const d = body(STORE, 'async function deleteThread(');
  assert.match(d, /listNotesIncludingHeld\(threadId\)/, 'it must see the held notes to leave them');
  assert.match(d, /if \(!isHeldNote\(n\)\) await txDelete\('notes', n\.note_id\);/, 'only visible notes are deleted');
  assert.match(d, /held: true/, 'the thread row that anchors held notes is kept, flagged held (hidden from every default reader)');
  assert.match(d, /else await txDelete\('threads', threadId\);/, 'the thread row is deleted ONLY when no held note remains');
  assert.doesNotMatch(d, /txDelete\('threads', threadId\);[\s\S]*held: true/, 'and the delete does not come before the keep');
});

// ── Who may touch the messaging store at all ──
// A backup, an export, a search index or an unblock that read or wrote the notes store could carry a held note or turn it back into an ordinary one. Today none does:
// the vault backup (SovereignBackup) carries contacts, keys and settings but no notes or threads, there is no search over notes, and unblock only changes the contact.
// This pins the EXACT set of modules that import the store (or the messaging index that re-exports it), so a new importer fails here until it is added on purpose, in
// review, with a reason. (Test 4 "a backup excludes held", test 5 "an unblock moves zero rows" and test 7 "a search index has no held row" rest on this.)
const resolveSpec = (from: string, spec: string): string | null => {
  const base = spec.startsWith('@/') ? `src/${spec.slice(2)}` : spec.startsWith('.') ? normalize(join(dirname(from), spec)) : null;
  return base ? base.replace(/\.(ts|tsx)$/, '') : null;
};
const STORE_TARGETS = new Set(['src/lib/messaging/store', 'src/lib/messaging', 'src/lib/messaging/index']);

test('S7 the modules that import the messaging store (or its index) are exactly these: no backup, export, search or unblock path reaches the notes store', () => {
  const importers = SOURCES.filter((f) => {
    const t = text(f);
    for (const m of t.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)) {
      const r = resolveSpec(f, m[1]);
      if (r && STORE_TARGETS.has(r)) return true;
    }
    return false;
  }).sort();
  assert.deepEqual(importers, [
    'app/msg/page.tsx',
    'src/components/notes/NotesInbox.tsx',
    'src/components/notes/notes-field.ts',
    'src/components/notes/seed-demo-notes.ts',
    'src/lib/messaging/adopt-floor-store.ts',
    'src/lib/messaging/dead-letter-store.ts',
    'src/lib/messaging/direct-session.ts',
    'src/lib/messaging/index.ts',
    'src/lib/messaging/ratchet-test-io.ts',
    'src/lib/messaging/reset-flag-store.ts',
    'src/lib/messaging/thread-alias-store.ts', // thread membership: the local (sender, claimed thread id) -> fresh thread id alias, one sealed row per sender; never exported
    'src/lib/messaging/transport.ts',
    'src/lib/sync/live-book-poll.ts',
  ]);
});

test('S8 the held flag on a note or thread is written in exactly three places and never cleared by an assignment: no path can turn a held NOTE back into an ordinary one (a THREAD row loses the flag only through clearedHeld: S9)', () => {
  // `held: true` on a RECORD is written by transport.ts (the note and the thread it creates) and by deleteThread in store.ts. Other files use the word for unrelated
  // things (a mailbox hold in consume-mailbox and the lens reader, the seam result in live-book-poll) and are deliberately not counted.
  const writes = (f: string) => (text(f).match(/\bheld: true as const\b|\bheld: true \}\)/g) || []).length;
  assert.equal(writes('src/lib/messaging/transport.ts'), 2, 'the held note and the thread created only because of held notes');
  assert.equal(writes('src/lib/messaging/store.ts'), 1, 'deleteThread flagging the row it keeps');
  const elsewhere = SOURCES.filter((f) => !['src/lib/messaging/transport.ts', 'src/lib/messaging/store.ts'].includes(f)).filter((f) => /\bheld: true as const\b/.test(text(f)));
  assert.deepEqual(elsewhere, []);
  // and nothing clears, unsets or falsifies it. NAME- and PLACE-BASED (weaker than a type fence): a note or thread identifier assigned or deleted, or `held: false/undefined`
  // inside the messaging files. Unrelated features have a `held` of their own (summary.held in consume-mailbox counts held mailbox blobs) and are deliberately not matched.
  const clearers = SOURCES.filter((f) => {
    const t = text(f);
    if (/\bdelete\s+(note|thread|n|t|rec|record|row)\.held\b|\b(note|thread|n|t|rec|record|row)\.held\s*=[^=]/.test(t)) return true;
    return (f.startsWith('src/lib/messaging/') || f === 'src/lib/sync/live-book-poll.ts') && /\bheld\s*:\s*(false|undefined)\b/.test(t);
  });
  assert.deepEqual(clearers, []);
});

test('S9 a thread row loses its held flag in ONE place only: clearedHeld, called once from the accept path, on a thread and never on a note', () => {
  const callers = SOURCES.filter((f) => f !== 'src/lib/messaging/held-note.ts' && /\bclearedHeld\(/.test(text(f)));
  assert.deepEqual(callers, ['src/lib/messaging/transport.ts']);
  const t = text('src/lib/messaging/transport.ts');
  assert.equal((t.match(/\bclearedHeld\(/g) || []).length, 1);
  assert.match(t, /clearedHeld\(thread\)/, 'its argument is the THREAD row');
  assert.match(t, /!held && isHeldThread\(thread\)/, 'only for an ADMITTED arrival on a thread that is held');
});
