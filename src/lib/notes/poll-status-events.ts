// src/lib/notes/poll-status-events.ts
// #720 / copy v1 §B (Hypatia 07c6d5ae): whether the shared mailbox poll has been REFUSED by the relay on 3 consecutive polls, for the
// Chat tab's notice. In memory only (nothing is stored at rest). Fed by every poll (background tick and pull-to-refresh); read by NotesInbox.
//
// Rules: 3 consecutive 'rejected' polls show the notice; the first 'ok' clears it and becomes the "since" time; 'locked' means no poll
// ran, which is expected, so it clears everything (never shown while locked); a thrown poll (network) is not a refusal and changes
// nothing; clearPollStatus() runs on session lock / identity switch so identity A's state can never show under identity B.
import type { PollOnceStatus } from '@/lib/sync/live-book-poll';

export const REFUSED_POLLS_BEFORE_NOTICE = 3;

export type PollRefusedReport =
  | { refused: false }
  | {
      refused: true;
      /** Device time (ms) of the last poll the relay answered in this session; absent if none. */
      lastOkAt?: number;
    };

type Listener = (report: PollRefusedReport) => void;

const NONE: PollRefusedReport = { refused: false };
let current: PollRefusedReport = NONE;
let consecutiveRejected = 0;
let lastOkAt: number | undefined;
const listeners = new Set<Listener>();

function set(next: PollRefusedReport): void {
  const same =
    next.refused === current.refused && (!next.refused || !current.refused || next.lastOkAt === current.lastOkAt);
  if (same) return;
  current = next;
  for (const l of [...listeners]) {
    try {
      l(current);
    } catch {
      /* isolate subscriber errors */
    }
  }
}

export function reportPollStatus(status: PollOnceStatus, nowMs: number = Date.now()): void {
  if (status === 'ok') {
    consecutiveRejected = 0;
    lastOkAt = nowMs;
    return set(NONE);
  }
  if (status === 'rejected') {
    consecutiveRejected += 1;
    if (consecutiveRejected >= REFUSED_POLLS_BEFORE_NOTICE) set({ refused: true, lastOkAt });
    return;
  }
  if (status === 'locked') return clearPollStatus();
  // anything else is not a status: ignored rather than guessed at
}

export function getPollRefusedReport(): PollRefusedReport {
  return current;
}

export function clearPollStatus(): void {
  consecutiveRejected = 0;
  lastOkAt = undefined;
  set(NONE);
}

export function subscribePollRefused(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function __resetPollStatusForTest(): void {
  listeners.clear();
  consecutiveRejected = 0;
  lastOkAt = undefined;
  current = NONE;
}
