import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HeadlessStore } from './headless-store';
import type { NoteRecord } from '../messaging/types';

const note = (note_id: string, direction: 'inbound' | 'outbound', from: string, body: string) =>
  ({ note_id, thread_id: 't', direction, from_fingerprint: from, to_fingerprints: [], sent_at: '', body } as unknown as NoteRecord);
const store = () => new HeadlessStore({ path: join(mkdtempSync(join(tmpdir(), 'hstore-')), 'store.json') });

test('putNote: redelivery of the same inbound (same sender + id) stays one row', () => {
  const s = store();
  s.putNote(note('n1', 'inbound', 'A', 'hi'));
  s.putNote(note('n1', 'inbound', 'A', 'hi'));
  assert.equal(s.listNotes().length, 1);
});

test('putNote: an inbound reusing the id of OUR outbound note never replaces it (Chaos #170)', () => {
  const s = store();
  s.putNote(note('n1', 'outbound', 'ME', 'what we said'));
  s.putNote(note('n1', 'inbound', 'B', 'forged'));
  assert.equal(s.listNotes().length, 2);
  assert.equal(s.listNotes().find((n) => n.direction === 'outbound')!.body, 'what we said');
});

test('putNote: an inbound from B reusing an inbound id from A is a separate row', () => {
  const s = store();
  s.putNote(note('n1', 'inbound', 'A', 'from A'));
  s.putNote(note('n1', 'inbound', 'B', 'from B'));
  assert.deepEqual(s.listNotes().map((n) => n.body).sort(), ['from A', 'from B']);
});
