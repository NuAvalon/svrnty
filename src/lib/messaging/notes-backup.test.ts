// src/lib/messaging/notes-backup.test.ts
// Run: npx tsx --test src/lib/messaging/notes-backup.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildNotesBackup, parseNotesBackup } from './notes-backup';
import type { NoteRecord, NoteThread } from './types';

const thread: NoteThread = {
  thread_id: 'thr_1',
  kind: 'direct',
  participants: [{ fingerprint: 'abc', kind: 'human', display_name: 'Ada' }],
  created_at: '2026-09-30T00:00:00.000Z',
  last_activity_at: '2026-09-30T00:00:00.000Z',
  retention: { expires_at: null },
};

const note: NoteRecord = {
  note_id: 'note_1',
  thread_id: 'thr_1',
  direction: 'outbound',
  from_fingerprint: 'abc',
  to_fingerprints: ['def'],
  sent_at: '2026-09-30T00:00:00.000Z',
  body: 'hello',
  participant_kind: 'human',
  retention: { expires_at: null },
  wire_type: 'svrnty-note-v0',
};

test('a notes backup is notes only', () => {
  const backup = buildNotesBackup({ threads: [thread], notes: [note], ring_channels: [], exported_at: '2026-09-30T00:00:00.000Z' });
  assert.equal(backup.version, 'notes-1');
  const raw = backup as unknown as Record<string, unknown>;
  assert.equal('contacts' in raw, false);
  assert.equal('identity' in raw, false);
  assert.equal('keys' in raw, false);
  assert.equal(parseNotesBackup(backup)?.notes[0]?.body, 'hello');
});

test('a contact-book file is not a notes backup', () => {
  assert.equal(parseNotesBackup({
    version: '1.0',
    exported_at: '2026-09-30T00:00:00.000Z',
    identity: { name: 'You' },
    contacts: [],
  }), null);
  assert.equal(parseNotesBackup({
    version: 'notes-1',
    exported_at: '2026-09-30T00:00:00.000Z',
    threads: [],
    notes: [],
    ring_channels: [],
    contacts: [],
  }), null);
  assert.equal(parseNotesBackup({
    version: 'notes-1',
    exported_at: '2026-09-30T00:00:00.000Z',
    threads: [],
    notes: [],
    ring_channels: [],
    keys: { privateKey: 'nope' },
  }), null);
});
