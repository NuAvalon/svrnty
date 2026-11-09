// src/components/trust-map-refresh-note.ts
// Galaxy pull-to-refresh / refresh button: what the note under the map says after a check. "Caught up." is a claim that the mailbox was
// read and nothing is waiting, so it is shown ONLY when the poll says 'ok'. A refused poll (e.g. 401 owner-auth) resolves without
// throwing; before this it showed "Caught up." (Hypatia #2396). Anything that isn't a known status reads as "could not check".
// Copy v4 (Hypatia, shared/outbox/hypatia/svrnty_poll_status_copy_v4.md sha256 c109fb20), verbatim.
import type { PollOnceStatus } from '@/lib/sync/live-book-poll';
import { BUSY_MS_BEFORE_NOTICE, busyBackoffMs } from '@/lib/notes/poll-status-events';

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
  return REFRESH_NOTE.failed; // 'rejected', 'unreadable', 'busy' (once its retries are spent), undefined, anything else
}

/**
 * Run the refresh and return the note to show. Never throws. A busy relay (429/503) is retried silently, with backoff, for up to
 * BUSY_MS_BEFORE_NOTICE; the note stays on "Checking for updates…" meanwhile, so one shed poll shows the user nothing.
 */
export async function refreshNoteAfter(
  onRefresh: () => Promise<PollOnceStatus>,
  opts: { sleep?: (ms: number) => Promise<void>; now?: () => number } = {},
): Promise<string> {
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const now = opts.now ?? Date.now;
  try {
    const startedAt = now();
    for (let streak = 1; ; streak++) {
      const status = await onRefresh();
      if (status !== 'busy' || now() - startedAt >= BUSY_MS_BEFORE_NOTICE) return refreshNoteFor(status);
      await sleep(busyBackoffMs(streak));
    }
  } catch {
    return REFRESH_NOTE.failed;
  }
}
