// src/components/notes/poll-refused-notice.ts
// Copy v4 §B (Hypatia, shared/outbox/hypatia/svrnty_poll_status_copy_v4.md sha256 c109fb20; §B unchanged since v3), verbatim. Says only what this device
// observed on its LATEST failing poll: a non-OK status ("refused", + the hedged clock hint) or a 2xx it couldn't read (no hint: clock skew
// yields a 401, not a bad body). Never a cause as fact, never "caught up", never that messages are kept, never a count.
import type { PollRefusedReport } from '@/lib/notes/poll-status-events';

export const POLL_REFUSED_COPY = {
  since: (time: string) => `Couldn't check for new messages since ${time}. The relay refused this device's request.`,
  never: "Couldn't check for new messages. The relay refused this device's request.",
  hint: "If your device's date and time are wrong, fixing them may help.",
  unreadableSince: (time: string) => `Couldn't check for new messages since ${time}. The relay's reply couldn't be read.`,
  unreadableNever: "Couldn't check for new messages. The relay's reply couldn't be read.",
} as const;

export function pollRefusedNotice(
  report: PollRefusedReport,
  formatTime: (ms: number) => string,
): { text: string; hint?: string } | null {
  if (!report.refused) return null;
  const since = typeof report.lastOkAt === 'number' && Number.isFinite(report.lastOkAt) ? formatTime(report.lastOkAt) : null;
  if (report.kind === 'refused') {
    return { text: since ? POLL_REFUSED_COPY.since(since) : POLL_REFUSED_COPY.never, hint: POLL_REFUSED_COPY.hint };
  }
  return { text: since ? POLL_REFUSED_COPY.unreadableSince(since) : POLL_REFUSED_COPY.unreadableNever };
}
