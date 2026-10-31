// src/components/notes/poll-refused-notice.ts
// Copy v1 §B (Hypatia, shared/outbox/hypatia/svrnty_poll_status_copy_v1.md sha256 07c6d5ae), verbatim. Says only what this device
// observed (a non-OK status on its own poll); never a cause as fact, never "caught up", never that messages are kept, never a count.
import type { PollRefusedReport } from '@/lib/notes/poll-status-events';

export const POLL_REFUSED_COPY = {
  since: (time: string) => `Couldn't check for new messages since ${time}. The relay refused this device's request.`,
  never: "Couldn't check for new messages. The relay refused this device's request.",
  hint: "If your device's date and time are wrong, fixing them may help.",
} as const;

export function pollRefusedNotice(
  report: PollRefusedReport,
  formatTime: (ms: number) => string,
): { text: string; hint: string } | null {
  if (!report.refused) return null;
  const text =
    typeof report.lastOkAt === 'number' && Number.isFinite(report.lastOkAt)
      ? POLL_REFUSED_COPY.since(formatTime(report.lastOkAt))
      : POLL_REFUSED_COPY.never;
  return { text, hint: POLL_REFUSED_COPY.hint };
}
