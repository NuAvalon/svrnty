// src/lib/notes/poll-status-events.ts
// #720 / copy v3 §B (Hypatia d8fea4ae): whether the shared mailbox poll has FAILED (refused, or a reply that couldn't be read) on 3
// consecutive polls, and which kind the LATEST failure was, for the
// Chat tab's notice. In memory only (nothing is stored at rest). Fed by every poll (background tick and pull-to-refresh); read by NotesInbox.
//
// Rules: 3 consecutive failed polls ('rejected' or 'unreadable', both kinds count) show the notice, worded for the latest one; the first answered poll ('ok' or 'checked-waiting': the relay DID answer) clears
// it and becomes the "since" time; 'locked' means no poll
// ran, which is expected, so it clears everything (never shown while locked); a thrown poll (network) is not a refusal and changes
// nothing; clearPollStatus() runs on session lock / identity switch so identity A's state can never show under identity B.
// A 'busy' poll (429/503: the relay is shedding load) is NOT a refusal of this device: it is retried silently, with backoff, and shows
// nothing unless polls stay busy for BUSY_MS_BEFORE_NOTICE straight; then only the plain "Could not check right now." line, cleared by
// the first answered poll.
import type { PollOnceStatus } from '@/lib/sync/live-book-poll';

export const REFUSED_POLLS_BEFORE_NOTICE = 3;
export const BUSY_MS_BEFORE_NOTICE = 30_000;
const BUSY_BACKOFF_MAX_MS = 8_000;

/** How long to wait before retrying after the `streak`th busy poll in a row (1 s, 2 s, 4 s, then 8 s). */
export function busyBackoffMs(streak: number): number {
  return Math.min(BUSY_BACKOFF_MAX_MS, 1_000 * 2 ** Math.max(0, streak - 1));
}

export type PollRefusedReport =
  | { refused: false }
  | {
      refused: true;
      /**
       * What the LATEST failing poll observed: a 401 ('refused-auth', the only refusal a wrong device clock can cause), a 5xx ('relay-error':
       * the relay failing, not rejecting this device; 503 never gets here, it is 'busy'), any other non-OK status ('refused'), a 2xx whose
       * body wasn't a list ('unreadable'), or a relay shedding load ('busy').
       */
      kind: 'refused-auth' | 'refused' | 'relay-error' | 'unreadable' | 'busy';
      /** Device time (ms) of the last poll the relay answered ('ok' or 'checked-waiting') in this session; absent if none. */
      lastOkAt?: number;
    };

type Listener = (report: PollRefusedReport) => void;

const NONE: PollRefusedReport = { refused: false };
let current: PollRefusedReport = NONE;
let consecutiveRejected = 0;
let busySince: number | undefined;
let lastOkAt: number | undefined;
const listeners = new Set<Listener>();

function set(next: PollRefusedReport): void {
  const same =
    next.refused === current.refused &&
    (!next.refused || !current.refused || (next.lastOkAt === current.lastOkAt && next.kind === current.kind));
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

export function reportPollStatus(status: PollOnceStatus, nowMs: number = Date.now(), httpStatus?: number): void {
  if (status === 'ok' || status === 'checked-waiting') {
    consecutiveRejected = 0;
    busySince = undefined;
    lastOkAt = nowMs;
    return set(NONE);
  }
  if (status === 'busy') {
    busySince ??= nowMs;
    if (nowMs - busySince >= BUSY_MS_BEFORE_NOTICE) set({ refused: true, lastOkAt, kind: 'busy' });
    return;
  }
  if (status === 'rejected' || status === 'unreadable') {
    busySince = undefined; // a different answer from the relay: no longer "busy for 30 s straight"
    consecutiveRejected += 1;
    const kind =
      status === 'unreadable'
        ? 'unreadable'
        : httpStatus === 401
          ? 'refused-auth'
          : httpStatus !== undefined && httpStatus >= 500
            ? 'relay-error'
            : 'refused';
    if (consecutiveRejected >= REFUSED_POLLS_BEFORE_NOTICE) set({ refused: true, lastOkAt, kind });
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
  busySince = undefined;
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
  busySince = undefined;
  lastOkAt = undefined;
  current = NONE;
}
