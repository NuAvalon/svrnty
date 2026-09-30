// src/lib/messaging/notes-backup.ts
// Portable notes file. Separate from the contact-book backup (`version: '1.0'`
// in client-store `exportAll`). A long thread must not bloat the book.
//
// The file holds the notes themselves (bodies included). It is not the book:
// no identity, keys, vault, shards, or contacts. Keep it like a diary.

import type { NoteRecord, NoteThread, RingChannel } from './types';
import { listAllNotes, listRingChannels, listThreads, putNote, putRingChannel, putThread } from './store';

export const NOTES_BACKUP_VERSION = 'notes-1' as const;

export interface NotesBackup {
  version: typeof NOTES_BACKUP_VERSION;
  exported_at: string;
  threads: NoteThread[];
  notes: NoteRecord[];
  ring_channels: RingChannel[];
}

const BOOK_KEYS = ['contacts', 'identity', 'keys', 'pq_keys', 'vault', 'shards'] as const;

export function buildNotesBackup(parts: {
  threads: NoteThread[];
  notes: NoteRecord[];
  ring_channels: RingChannel[];
  exported_at?: string;
}): NotesBackup {
  return {
    version: NOTES_BACKUP_VERSION,
    exported_at: parts.exported_at ?? new Date().toISOString(),
    threads: parts.threads,
    notes: parts.notes,
    ring_channels: parts.ring_channels,
  };
}

/** Reject a contact-book file (`1.0`) and anything carrying book fields. */
export function parseNotesBackup(raw: unknown): NotesBackup | null {
  if (!raw || typeof raw !== 'object') return null;
  const o = raw as Record<string, unknown>;
  if (o.version !== NOTES_BACKUP_VERSION) return null;
  for (const key of BOOK_KEYS) {
    if (key in o) return null;
  }
  if (typeof o.exported_at !== 'string' || o.exported_at.length === 0 || o.exported_at.length > 40) return null;
  if (!Array.isArray(o.threads) || !Array.isArray(o.notes) || !Array.isArray(o.ring_channels)) return null;
  for (const thread of o.threads) {
    if (!thread || typeof thread !== 'object') return null;
    const t = thread as Record<string, unknown>;
    if (typeof t.thread_id !== 'string' || (t.kind !== 'direct' && t.kind !== 'ring')) return null;
  }
  for (const note of o.notes) {
    if (!note || typeof note !== 'object') return null;
    const n = note as Record<string, unknown>;
    if (typeof n.note_id !== 'string' || typeof n.thread_id !== 'string' || typeof n.body !== 'string') return null;
  }
  for (const ring of o.ring_channels) {
    if (!ring || typeof ring !== 'object') return null;
    const r = ring as Record<string, unknown>;
    if (typeof r.channel_id !== 'string' || !Array.isArray(r.member_fingerprints)) return null;
  }
  return {
    version: NOTES_BACKUP_VERSION,
    exported_at: o.exported_at,
    threads: o.threads as NoteThread[],
    notes: o.notes as NoteRecord[],
    ring_channels: o.ring_channels as RingChannel[],
  };
}

export async function exportNotesBackup(exportedAt?: string): Promise<NotesBackup> {
  const [threads, notes, ring_channels] = await Promise.all([
    listThreads(),
    listAllNotes(),
    listRingChannels(),
  ]);
  return buildNotesBackup({ threads, notes, ring_channels, exported_at: exportedAt });
}

/** Merge by id into the notes store. Does not touch the contact book. */
export async function importNotesBackup(raw: unknown): Promise<void> {
  const backup = parseNotesBackup(raw);
  if (!backup) throw new Error('That file is not a notes backup');
  for (const thread of backup.threads) await putThread(thread);
  for (const note of backup.notes) await putNote(note);
  for (const channel of backup.ring_channels) await putRingChannel(channel);
}
