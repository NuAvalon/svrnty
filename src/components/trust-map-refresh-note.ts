// src/components/trust-map-refresh-note.ts
// Galaxy pull-to-refresh / refresh button: what the note under the map says after a check. "Caught up." is a claim that the mailbox was
// read and nothing is waiting, so it is shown ONLY when the poll says 'ok'. A refused poll (e.g. 401 owner-auth) resolves without
// throwing; before this it showed "Caught up." (Hypatia #2396). Anything that isn't a known status reads as "could not check".
// Copy v4 (Hypatia, shared/outbox/hypatia/svrnty_poll_status_copy_v4.md sha256 c109fb20), verbatim.
import type { PollOnceStatus } from '@/lib/sync/live-book-poll';

export const REFRESH_NOTE = {
  checking: 'Checking for updates…',
  ok: 'Caught up.',
  checkedWaiting: 'Checked. Some messages are still on the relay.',
  failed: 'Could not check right now.',
  locked: 'Unlock to check for messages.',
} as const;

export function refreshNoteFor(status: unknown): string {
  if (status === 'ok') return REFRESH_NOTE.ok;
  if (status === 'checked-waiting') return REFRESH_NOTE.checkedWaiting;
  if (status === 'locked') return REFRESH_NOTE.locked;
  return REFRESH_NOTE.failed; // 'rejected', 'unreadable', undefined, anything else
}

/** Run the refresh and return the note to show. Never throws. */
export async function refreshNoteAfter(onRefresh: () => Promise<PollOnceStatus>): Promise<string> {
  try {
    return refreshNoteFor(await onRefresh());
  } catch {
    return REFRESH_NOTE.failed;
  }
}
