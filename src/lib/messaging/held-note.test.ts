// src/lib/messaging/held-note.test.ts: the pure rules for a note kept from a frozen sender ("held"). The flag lives ONLY inside the sealed payload;
// the readers every screen uses never see a held row, and the sender cannot make one expire.
// Run: npx tsx --test src/lib/messaging/held-note.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isHeldNote, isHeldThread, visibleNotes, visibleThreads, noteExpired } from './held-note';

const NOW = Date.parse('2026-11-18T12:00:00Z');
const note = (id: string, extra: Record<string, unknown> = {}) => ({ note_id: id, retention: { expires_at: null as string | null }, ...extra });
const thread = (id: string, extra: Record<string, unknown> = {}) => ({ thread_id: id, ...extra });

test('H1 only the exact value true marks a row held (a truthy look-alike is an ordinary row)', () => {
  assert.equal(isHeldNote(note('a', { held: true })), true);
  assert.equal(isHeldThread(thread('t', { held: true })), true);
  for (const v of [false, 'true', 1, null, undefined, {}]) {
    assert.equal(isHeldNote(note('b', { held: v })), false, `held: ${String(v)} must not hide a row`);
    assert.equal(isHeldThread(thread('u', { held: v })), false);
  }
});

test('H2 the default readers drop held notes and held threads and keep the rest, in order', () => {
  const notes = [note('1'), note('2', { held: true }), note('3'), note('4', { held: true })];
  assert.deepEqual(visibleNotes(notes).map((n) => n.note_id), ['1', '3']);
  const threads = [thread('x', { held: true }), thread('y'), thread('z')];
  assert.deepEqual(visibleThreads(threads).map((t) => t.thread_id), ['y', 'z']);
  assert.deepEqual(visibleNotes([]), []);
});

test('H3 a held note is never expired, whatever expiry the SENDER put in it (evidence cannot erase itself)', () => {
  const past = '2020-01-01T00:00:00Z';
  assert.equal(noteExpired(note('h', { held: true, retention: { expires_at: past } }), NOW), false);
  assert.equal(noteExpired(note('h2', { held: true, retention: { expires_at: '2026-11-18T11:59:59Z' } }), NOW), false);
});

test('H4 an ordinary note keeps today\'s rule exactly: expired only when its expiry is a real time strictly in the past', () => {
  assert.equal(noteExpired(note('o', { retention: { expires_at: '2026-11-18T11:59:59Z' } }), NOW), true);
  assert.equal(noteExpired(note('o', { retention: { expires_at: '2026-11-18T12:00:00Z' } }), NOW), false, 'equal to now is not yet past');
  assert.equal(noteExpired(note('o', { retention: { expires_at: '2026-11-19T00:00:00Z' } }), NOW), false);
  assert.equal(noteExpired(note('o', { retention: { expires_at: null } }), NOW), false);
  assert.equal(noteExpired(note('o', { retention: { expires_at: 'not a date' } }), NOW), false, 'an unparseable date does not expire a note (NaN compares false), as before');
});

test('H5 the readers do not mutate their input', () => {
  const notes = Object.freeze([Object.freeze(note('1')), Object.freeze(note('2', { held: true }))]);
  assert.doesNotThrow(() => visibleNotes(notes));
  assert.equal(notes.length, 2);
});
