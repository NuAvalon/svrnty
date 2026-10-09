// Inbox-repaint bus (render-glass). Mirrors contact-events so the Notes tab
// can subscribe without touching CODEOWNERS sync/consume.
//
// Same-page send emits immediately. Inbound notes persist via the app-shell
// live-book poll; this tab also re-reads the notes store while it is open.
// Fleet: wire consume's emitNote → emitNoteArrival (live-book-poll.ts) so
// arrivals fan out without the store poll. Do not edit that file from this PR.

export type NoteArrivalEvent = {
  note_id?: string;
  thread_id?: string;
  from_fingerprint?: string;
};

type Listener = (evt: NoteArrivalEvent) => void;

const CHANNEL_NAME = 'svrnty:notes';
const listeners = new Set<Listener>();
let channel: BroadcastChannel | null = null;

function ensureChannel(): BroadcastChannel | null {
  if (channel) return channel;
  if (typeof BroadcastChannel === 'undefined') return null;
  channel = new BroadcastChannel(CHANNEL_NAME);
  channel.onmessage = (e: MessageEvent) => {
    fanout((e.data || {}) as NoteArrivalEvent);
  };
  (channel as unknown as { unref?: () => void }).unref?.();
  return channel;
}

function fanout(evt: NoteArrivalEvent): void {
  for (const l of [...listeners]) {
    try {
      l(evt);
    } catch {
      /* isolate subscriber errors */
    }
  }
}

export function emitNoteArrival(evt: NoteArrivalEvent = {}): void {
  fanout(evt);
  const ch = ensureChannel();
  if (ch) ch.postMessage(evt);
}

export function subscribeNoteArrivals(listener: Listener): () => void {
  ensureChannel();
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function __resetNoteEventsForTest(): void {
  listeners.clear();
  if (channel) {
    channel.close();
    channel = null;
  }
}
