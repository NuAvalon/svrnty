// src/lib/notes/held-events.ts
// #720: the latest "blobs this device could not open YET, kept on the relay" report from the shared mailbox poll, for the Chat tab's
// notice. In memory only (nothing is stored at rest). Fed by consume's emitHeld; read by NotesInbox.
//
// Rules: a report REPLACES the last one (0 clears the notice); an invalid report is ignored rather than guessed at; subscribers are
// only woken when the report actually changed (the poll reports every few seconds); and clearHeldReport() must run on session lock /
// identity switch so identity A's count can never show under identity B.

export interface HeldReport {
  count: number;
  /** ISO deadline from the relay (the earliest of the held envelopes), only when every held envelope carried one. Untrusted. */
  expiresAt?: string;
}

type Listener = (report: HeldReport) => void;

const NONE: HeldReport = { count: 0 };
let current: HeldReport = NONE;
const listeners = new Set<Listener>();

function set(next: HeldReport): void {
  if (next.count === current.count && next.expiresAt === current.expiresAt) return;
  current = next;
  for (const l of [...listeners]) {
    try {
      l(current);
    } catch {
      /* isolate subscriber errors */
    }
  }
}

export function reportHeld(count: number, info?: { expiresAt?: string }): void {
  if (!Number.isInteger(count) || count < 0) return;
  if (count === 0) return set(NONE);
  set({ count, expiresAt: typeof info?.expiresAt === 'string' ? info.expiresAt : undefined });
}

export function getHeldReport(): HeldReport {
  return current;
}

export function clearHeldReport(): void {
  set(NONE);
}

export function subscribeHeld(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function __resetHeldEventsForTest(): void {
  listeners.clear();
  current = NONE;
}
