// src/lib/messaging/threads.ts
// Conversation threads and side threads (reply threads) for notes.
//
// A NoteThread is the conversation: direct (one admitted person) or ring (a small group).
// Inside it, the main timeline is every note with no thread_root. A side thread hangs off
// one main-timeline note: thread_root is that note's id, reply_to is the parent.
// The relay never sees this structure. It rides inside the sealed note.

export interface ThreadedNote {
  note_id: string;
  sent_at: string;
  reply_to?: string;
  thread_root?: string;
}

const ID_RE = /^[A-Za-z0-9_-]{1,40}$/;

export function isNoteId(value: unknown): value is string {
  return typeof value === 'string' && ID_RE.test(value);
}

/** Main timeline: notes that are not inside a side thread, oldest first by the caller's order. */
export function mainTimeline<T extends ThreadedNote>(notes: T[]): T[] {
  return notes.filter((n) => !n.thread_root);
}

/** The root plus every reply whose thread_root is that note, in sent_at order. */
export function sideThread<T extends ThreadedNote>(notes: T[], rootId: string): T[] {
  return notes
    .filter((n) => n.note_id === rootId || n.thread_root === rootId)
    .slice()
    .sort((a, b) => a.sent_at.localeCompare(b.sent_at) || a.note_id.localeCompare(b.note_id));
}

/** Replies under a root, not counting the root itself. */
export function replyCount<T extends ThreadedNote>(notes: T[], rootId: string): number {
  return notes.filter((n) => n.thread_root === rootId).length;
}

/**
 * Fields to stamp on a reply. Replying to a main-timeline note starts a side thread
 * rooted there. Replying inside a side thread stays on that root.
 * Null when the target note is not in this set.
 */
export function replyLink<T extends ThreadedNote>(
  notes: T[],
  replyToId: string,
): { reply_to: string; thread_root: string } | null {
  const target = notes.find((n) => n.note_id === replyToId);
  if (!target || !isNoteId(target.note_id)) return null;
  const root = target.thread_root ?? target.note_id;
  if (!isNoteId(root)) return null;
  return { reply_to: target.note_id, thread_root: root };
}
