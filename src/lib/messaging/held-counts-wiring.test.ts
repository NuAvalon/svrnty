// src/lib/messaging/held-counts-wiring.test.ts: STATIC guards for how store.ts keeps the held-count row (held-counts.ts) in step with the notes. The notes store has no runtime IndexedDB test in
// node, so these read the SOURCE: they say what the code is, not what a browser ran. e2e/freeze-counter.spec.ts runs the same behaviours in a real browser against the real store.
// What they pin (each is a ruling or a property the row's correctness depends on):
//   - no note row is written except through writeNote, and no held row is deleted except at the two known sites: a NEW write or delete path fails here, and must update the count in the SAME transaction,
//   - the note write and the count write are ONE compare-and-swap, decided and encrypted before it, with no await inside the transaction,
//   - an unusable count row falls back to the SCAN, never to 0 and never to "full", and schedules a reconcile off the receive path,
//   - the reconcile reads the row's blob BEFORE it walks the notes and writes only against that blob,
//   - only held-counts.ts, store.ts and the allowed-prefix list name the row: no export, vault or identity-store file can carry it.
// Run: npx tsx --test src/lib/messaging/held-counts-wiring.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { HELD_COUNTS_KEY } from './held-counts';
import { isAllowedSettingsRowKey } from './settings-row-keys';

const root = new URL('../../', import.meta.url).pathname; // src/
const store = readFileSync(new URL('./store.ts', import.meta.url), 'utf8');
const codeOnly = (t: string): string => t.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\w'"`])\/\/.*$/gm, '$1');
const code = codeOnly(store);

/** The text of one top-level function: from its head to the first lone closing brace. Checked to be real, so a rename cannot turn a pin into a pass over nothing. */
const fn = (head: string): string => {
  const a = code.indexOf(head);
  assert.ok(a >= 0, `${head} exists`);
  const b = code.indexOf('\n}\n', a);
  assert.ok(b > a, `${head} ends`);
  const body = code.slice(a, b);
  assert.ok(body.length > 150, `${head} is a real body`);
  return body;
};

const sources = (dir: string): string[] => readdirSync(dir).flatMap((f) => {
  const p = join(dir, f);
  if (statSync(p).isDirectory()) return f === 'node_modules' ? [] : sources(p);
  return /\.(ts|tsx)$/.test(f) && !/\.test\.(ts|tsx)$/.test(f) ? [p] : [];
});

test('W1 the row is named only by held-counts.ts, store.ts and the allowed-prefix list: no export, vault or identity-store file can carry it', () => {
  const users = sources(root).filter((f) => /held_counts|HELD_COUNTS|heldCounts/.test(codeOnly(readFileSync(f, 'utf8')))).map((f) => f.slice(f.indexOf('/src/') + 1)).sort();
  assert.deepEqual(users, ['src/lib/messaging/held-counts.ts', 'src/lib/messaging/settings-row-keys.ts', 'src/lib/messaging/store.ts'].sort());
  assert.equal(isAllowedSettingsRowKey(HELD_COUNTS_KEY), true, 'the key is under an allowed settings prefix (so it can never be the salt row)');
});

test('W2 no note row is put except through writeNote, and a note row is deleted at exactly two known sites: a new one must update the count in the same transaction', () => {
  assert.equal((code.match(/txPut\('notes'/g) ?? []).length, 0, 'no direct put into the notes store');
  assert.equal((code.match(/store: 'notes', value:/g) ?? []).length, 1, 'writeNote is the one place a note row is put');
  assert.equal((code.match(/objectStore\('notes'\)\.put\(/g) ?? []).length, 0, 'no raw put on the notes store object');
  assert.equal((code.match(/txCommitIfUnchanged\(/g) ?? []).length, 3, 'the commit helper is defined once and called twice: by writeNote and by the reconcile; a third caller is a new write path');
  // The two delete sites: the read function's expiry of an ORDINARY note (a held note never expires on the sender's retention: pin S3), and deleteThread, which keeps every held note.
  assert.equal((code.match(/txDelete\('notes'/g) ?? []).length, 2, 'a third delete of a note row (the hold view, the 30-day expiry, an unfreeze) must go through the count row in the SAME transaction, then raise this number');
  assert.match(fn('async function deleteThread('), /if \(!isHeldNote\(n\)\) await txDelete\('notes'/, 'deleteThread deletes only non-held notes, so it changes no count');
});

test('W3 the note write and the count write are ONE compare-and-swap, decided and encrypted BEFORE it, and nothing in the transaction awaits', () => {
  const w = fn('async function writeNote(');
  assert.equal((w.match(/txCommitIfUnchanged\(/g) ?? []).length, 1, 'one commit');
  assert.match(w, /expects\.push\(\{ store: 'settings', key: HELD_COUNTS_KEY, enc: counter\.enc \}\)/, 'the count row is compared in the same commit');
  assert.match(w, /puts\.push\(\{ store: 'settings', value: \{ key: HELD_COUNTS_KEY, enc: await encryptJson\(sealedShape\(next\)\) \} satisfies SettingsRow \}\)/, 'and written in it, sealed and padded');
  assert.ok(w.indexOf('encryptJson(note)') < w.indexOf('txCommitIfUnchanged('), 'the note is encrypted before the transaction');
  assert.ok(w.indexOf('sealedShape(next)') < w.indexOf('txCommitIfUnchanged('), 'and so is the count');
  const tx = fn('async function txCommitIfUnchanged(');
  const inside = tx.slice(tx.indexOf('return new Promise('));
  assert.ok(inside.length > 100, 'the transaction body was found');
  assert.doesNotMatch(inside, /\bawait\b/, 'no await inside the transaction: WebCrypto in there would auto-commit it');
  assert.match(inside, /cur === undefined/, 'an expected-absent row must still be absent');
});

test('W4 an unusable count row falls back to the SCAN, never to 0 and never to the cap, and schedules a reconcile off the receive path', () => {
  const f = fn('export async function countHeldFromFast(');
  assert.match(f, /return countHeldFrom\(sender\);/, 'the fallback is the full scan');
  assert.match(f, /scheduleHeldCountsReconcile\(\)/);
  assert.doesNotMatch(f, /return 0\b|HOLD_CAP|return Infinity|return Number/, 'it never answers 0 and never answers "full"');
  assert.match(f, /if \('count' in got\) return got\.count;/, 'a usable row answers, and only a usable row');
});

test('W5 the reconcile reads the row\'s blob BEFORE it walks the notes and writes only against that blob', () => {
  const r = codeOnly(store.slice(store.indexOf('export function reconcileHeldCounts(')));
  const read = r.indexOf('readHeldCountsRow()');
  const walk = r.indexOf('listThreadsIncludingHeld()');
  const commit = r.indexOf('txCommitIfUnchanged(');
  assert.ok(read > 0 && read < walk && walk < commit, 'token, then walk, then commit');
  assert.match(r.slice(commit, commit + 160), /enc: token/, 'the commit compares the blob read before the walk');
  assert.match(r, /sealedShape\(\{ state: 'ok', counts: counts as HeldCounts \}\)/, 'and writes the padded shape');
});

test('W6 unlocking schedules a reconcile unless a caller opts out, and a dirty rewrite schedules one too', () => {
  const i = fn('export async function initNotesStore(');
  assert.match(i, /if \(opts\?\.reconcile !== false\) scheduleHeldCountsReconcile\(\);/);
  assert.ok(i.indexOf('_notesOwner = ownerFingerprint;') < i.indexOf('scheduleHeldCountsReconcile()'), 'only after the key is assigned');
  assert.match(fn('async function writeNote('), /if \(wroteDirty\) scheduleHeldCountsReconcile\(\);/);
});

test('W7 a held row whose prior copy cannot be read, or a count row that cannot be adjusted, makes the count DIRTY (a fresh blob), never a guessed number', () => {
  const w = fn('async function writeNote(');
  assert.match(w, /priorUnreadable = true;/);
  assert.match(w, /if \(before !== after \|\| priorUnreadable\) \{/, 'a prior row that cannot be read touches the count row even when "before" and "after" look the same');
  assert.match(w, /const usable = !priorUnreadable && counter\.read !== 'absent' && counter\.read !== null && counter\.read\.state === 'ok' \? counter\.read\.counts : null;/);
  assert.match(w, /: \{ state: 'dirty' \};/);
  assert.match(w, /wroteDirty = usable === null;/);
});

test('W8 the two exported note writers are the ONLY callers of writeNote and both go through the per-tab queue, so a burst of held writes cannot starve itself on the one count row', () => {
  assert.equal((code.match(/\bwriteNote\(/g) ?? []).length, 3, 'the definition and exactly two calls');
  assert.equal((code.match(/serializeNoteWrite\(\(\) => writeNote\(note\)\)/g) ?? []).length, 2, 'putNote and putNoteReportingCreated, each through the queue');
  const q = fn('function serializeNoteWrite<T>(');
  assert.match(q, /_noteWriteTail\.then\(run, run\)/, 'a write waits for the one before it, whether that one worked or not');
  assert.match(q, /_noteWriteTail = mine\.catch\(\(\) => \{\}\)/, 'and a failed write never blocks the next one');
});

