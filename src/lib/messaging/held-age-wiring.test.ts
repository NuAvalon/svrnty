// src/lib/messaging/held-age-wiring.test.ts: static pins for the hold's AGE LIMIT (G3). Like the other store fences here these READ source text: the IndexedDB-backed store cannot run in a unit test, so they
// prove the pieces are connected the way the rulings say; the behaviour is run in a real browser by e2e/hold-age.spec.ts.
//
// What they hold in place (Flint, task 946 seq 18; Archie, seq 17):
//   - a held row is removed only through the COUNTED delete (the note row goes and the count row drops in ONE compare-and-swap), and every other note delete is reached only for NON-held notes;
//   - the age runs from the owner's clock (held_at) and never from anything the sender controls; held_at and expiry_seen_at are written in one rule file and never from the wire;
//   - the sweep runs at unlock, after the count row is put right, through the per-tab write queue, and production passes it no limits (the limit is the one named number).
//
// Run: npx tsx --test src/lib/messaging/held-age-wiring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = process.cwd();
const codeOnly = (t: string): string => t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\w'"`])\/\/.*$/gm, '$1');
const read = (rel: string): string => codeOnly(readFileSync(join(ROOT, rel), 'utf8'));
const STORE = read('src/lib/messaging/store.ts');
const TRANSPORT = read('src/lib/messaging/transport.ts');
const HELD = read('src/lib/messaging/held-note.ts');

/** The text of one top-level function, from its head to the first lone closing brace; checked to exist, so a rename cannot turn a pin into a pass over nothing. */
const cut = (code: string, head: string): string => {
  const a = code.indexOf(head);
  assert.ok(a >= 0, `${head} exists`);
  const b = code.indexOf('\n}\n', a);
  assert.ok(b > a, `${head} ends`);
  return code.slice(a, b);
};
const walk = (dir: string): string[] =>
  readdirSync(join(ROOT, dir)).flatMap((name) => {
    const rel = `${dir}/${name}`;
    if (statSync(join(ROOT, rel)).isDirectory()) return walk(rel);
    return /\.(ts|tsx)$/.test(name) && !/\.test\./.test(name) ? [rel] : [];
  });
const SOURCES = [...walk('src'), ...walk('app')];
const filesNaming = (word: string): string[] => SOURCES.filter((f) => new RegExp(`\\b${word}\\b`).test(codeOnly(readFileSync(join(ROOT, f), 'utf8')))).sort();

test('AW1 every bare delete of a note row is reached only for a NON-held note: the thread delete skips held, and the read-time expiry is gated by noteExpired, which is false for a held note first thing', () => {
  const sites = STORE.match(/txDelete\('notes'/g) ?? [];
  assert.equal(sites.length, 2, 'exactly two bare note deletes (a third must go through the counted delete, or be shown to be non-held)');
  assert.match(cut(STORE, 'async function deleteThread('), /if \(!isHeldNote\(n\)\) await txDelete\('notes'/, 'deleteThread: only non-held notes');
  assert.match(cut(STORE, 'async function readNotesForThread('), /if \(noteExpired\(note, now\)\) \{\s*await txDelete\('notes', note\.note_id\);/, 'the read-time expiry deletes only what noteExpired says is expired');
  const ne = cut(HELD, 'export function noteExpired(');
  const guard = ne.indexOf('if (isHeldNote(note)) return false;');
  assert.ok(guard > 0 && ne.indexOf('note.retention') > guard, 'noteExpired answers false for a held note BEFORE it reads the note\'s retention (the signature names the type; the READ is note.retention)');
});

test('AW2 the ONLY delete handed to the commit is the counted one, in ONE shared function used by the sweep and by the owner: one `deletes` argument, on notes only, in the same compare-and-swap as the count row', () => {
  assert.equal((STORE.match(/\[\{ store: 'notes', key: noteId \}\]/g) ?? []).length, 1, 'one place passes a note row to delete');
  const del = cut(STORE, 'async function commitCountedHeldDelete(');
  assert.match(del, /\{ store: 'settings', key: HELD_COUNTS_KEY, enc: counter\.enc \}/, 'the count row is compared in the same transaction');
  assert.match(del, /applyChange\(usable, heldInboundSender\(note\), null\)/, 'the count row drops by the deleted note');
  assert.match(del, /: \{ state: 'dirty' \};/, 'a count row that cannot be adjusted is written DIRTY, never a guessed number');
  assert.match(del, /txCommitIfUnchanged\(expects, \[\{ store: 'settings', value: countRow \}\], \[\{ store: 'notes', key: noteId \}\]\)/, 'count put and note delete in ONE commit');
  assert.match(del, /if \(committed && usable === null\) scheduleHeldCountsReconcile\(\);/, 'and a dirty write schedules a rebuild');
  // exactly two callers: the sweep (under its delete verdict) and the owner's delete
  assert.equal((STORE.match(/\bcommitCountedHeldDelete\(/g) ?? []).length, 3, 'the definition and two callers');
  assert.match(cut(STORE, 'async function heldAgeStep('), /if \(action === 'delete'\) \{\s*committed = await commitCountedHeldDelete\(noteId, priorRow, note\);/, 'the sweep deletes only under its delete verdict');
  assert.match(cut(STORE, 'async function ownerHeldStep('), /if \(what === 'delete'\) \{\s*committed = await commitCountedHeldDelete\(noteId, priorRow, note\);/, 'the owner deletes through the same function');
  const commit = cut(STORE, 'async function txCommitIfUnchanged(');
  assert.match(commit, /deletes: Array<\{ store: 'notes'; key: string \}> = \[\]/, 'the commit can delete a NOTES row only: never a settings row, so never the count row');
  assert.equal((commit.match(/\.delete\(d\.key\)/g) ?? []).length, 1);
  assert.ok(commit.indexOf('.put(p.value)') < commit.indexOf('.delete(d.key)') && commit.indexOf('.delete(d.key)') < commit.indexOf('wrote = true;'), 'the deletes go out with the puts, inside the all-rows-unchanged branch, before it answers');
});

test('AW3 the sweep step reads its row INSIDE the retry loop, skips what it cannot read, writes nothing on keep, and every write compares the note row it read', () => {
  const step = cut(STORE, 'async function heldAgeStep(');
  assert.ok(step.indexOf('for (let attempt') < step.indexOf("txGet<NoteRow>('notes', noteId)"), 'the row is read inside the loop: the decision is always made on the latest copy');
  assert.match(step, /catch \{\s*return 'unreadable';\s*\}/, 'a note that cannot be decrypted is skipped: unknown age means keep');
  assert.ok(step.indexOf("if (action === 'keep') return 'keep';") > 0 && step.indexOf("if (action === 'keep') return 'keep';") < step.indexOf('txCommitIfUnchanged('), 'keep returns before any write');
  assert.equal((step.match(/txCommitIfUnchanged\(/g) ?? []).length, 1, 'one direct write (the stamp); the delete goes through the shared counted delete (AW2)');
  assert.match(step, /\{ store: 'notes', key: noteId, enc: priorRow\.enc \}/, 'the note row it read is the first thing compared');
  assert.match(step, /heldSweepAction\(note, nowMs, limits\?\.limitDays, limits\?\.graceDays\)/, 'the verdict is the one rule (held-note.ts), given the owner\'s clock');
  assert.match(step, /stampedHeldNote\(note, action, nowMs\)/, 'a stamp is that rule\'s own rewrite');
});

test('AW4 the sweep runs at unlock only, after the count row is put right, through the per-tab write queue, and production passes it no limits', () => {
  const callers = STORE.match(/\bsweepHeldAge\(/g) ?? [];
  assert.equal(callers.length, 2, 'the definition and the ONE call');
  assert.match(STORE, /\.then\(\(\) => sweepHeldAge\(\)\)/, 'the one call passes no arguments: the clock and the limit are the real ones');
  assert.deepEqual(filesNaming('sweepHeldAge'), ['src/lib/messaging/store.ts'], 'no screen, export or other module can run it');
  const sweep = cut(STORE, 'export function sweepHeldAge(');
  assert.match(sweep, /serializeNoteWrite\(\(\) => heldAgeStep\(n\.note_id, nowMs, limits\)\)/, 'each step goes through the per-tab write queue like every other note write');
  assert.match(sweep, /if \(_sweepRun\) return _sweepRun;/, 'one run at a time');
  assert.match(sweep, /if \(!isHeldNote\(n\)\) continue;/, 'only held notes are ever stepped');
  assert.match(sweep, /requireUnlocked\(\);/, 'a locked store throws, it never sweeps');
});

test('AW5 the age NEVER reads anything the sender controls: no sent_at and no retention in the rule, the step or the sweep', () => {
  for (const [name, text] of [['heldSweepAction', cut(HELD, 'export function heldSweepAction(')], ['stampedHeldNote', cut(HELD, 'export function stampedHeldNote')], ['heldStampsFor', cut(HELD, 'export function heldStampsFor(')], ['heldAgeStep', cut(STORE, 'async function heldAgeStep(')], ['sweepHeldAge', cut(STORE, 'export function sweepHeldAge(')]] as const) {
    assert.doesNotMatch(text, /sent_at|sentAt|retention|expires_at/, `${name} does not read sent_at or retention`);
  }
  assert.doesNotMatch(STORE, /HOLD_AGE_LIMIT_DAYS|HOLD_EXPIRY_GRACE_DAYS/, 'the store never names the numbers: it passes them through the one rule');
});

test('AW6 the two stamps are written in ONE rule file and never from the wire: the accept builds the record from named fields, the stamps come from heldStampsFor, and transport.ts never reads either stamp', () => {
  assert.deepEqual(filesNaming('held_at'), ['src/lib/messaging/held-note.ts', 'src/lib/messaging/types.ts']);
  assert.deepEqual(filesNaming('expiry_seen_at'), ['src/lib/messaging/held-note.ts', 'src/lib/messaging/types.ts']);
  assert.equal((TRANSPORT.match(/heldStampsFor\(/g) ?? []).length, 1, 'one call');
  const a = TRANSPORT.indexOf('const record: NoteRecord = {');
  assert.ok(a > 0, 'the held record literal exists');
  const lit = TRANSPORT.slice(a, TRANSPORT.indexOf('\n  };', a));
  assert.doesNotMatch(lit, /\.\.\.\s*(args\.)?wire\b/, 'the record is built from named fields: no spread of the wire');
  assert.match(lit, /\.\.\.\(held \? \{ held: true as const, \.\.\.heldStampsFor\(prior, \(args\.io\?\.nowMs \?\? Date\.now\)\(\)\) \} : \{\}\),/, 'the stamps exist only in the held branch, from the stored prior row and the owner\'s clock');
  assert.doesNotMatch(TRANSPORT, /wire\.held\b|wire\.held_at|wire\.expiry_seen_at|\.held_at\b|\.expiry_seen_at\b/, 'transport.ts reads neither stamp (nor a held flag) off anything');
});

test('AW7 the rule file has the guards the rulings name: only held-exactly-true notes, 0 or a bad limit is OFF before any stamp, unknown age is stamped not deleted, delete needs the limit AND the grace', () => {
  const r = cut(HELD, 'export function heldSweepAction(');
  assert.ok(r.indexOf('if (!isHeldNote(note)) return \'keep\';') > 0);
  assert.ok(r.indexOf('if (!(limitDays > 0)') > r.indexOf('isHeldNote') && r.indexOf('if (!(limitDays > 0)') < r.indexOf("'stamp-held-at'"), 'the off switch is checked before anything can be stamped');
  assert.match(r, /if \(heldAt === null\) return 'stamp-held-at';/);
  assert.match(r, /const pastLimit = nowMs - heldAt >= limitDays \* DAY_MS;/, 'AT the limit is past it');
  assert.match(r, /if \(seen === null\) return 'stamp-expiry';/);
  assert.match(r, /if \(seen > nowMs\) return 'keep';/, 'a stamp in the future never deletes');
  assert.match(r, /return nowMs - seen >= graceDays \* DAY_MS \? 'delete' : 'keep';/, 'AT the grace is enough');
  assert.equal((r.match(/'delete'/g) ?? []).length, 1, 'one way to answer delete');
});
