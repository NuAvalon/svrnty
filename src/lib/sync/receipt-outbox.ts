// src/lib/sync/receipt-outbox.ts
// S62 slice 3, Flint's review R3-1 / R3-2 / R3-3 (#2094): a "delivered" receipt is best-effort and must never sit on the path of the note it answers,
// must be sent ONCE per note however often the note is redelivered, and must not eat the user's own deposit budget.
//
//  R3-1  enqueue() STARTS the send and returns; nothing awaits it. A slow or dead relay can no longer stretch the poll or hold the ack of a stored note.
//  R3-2  one receipt per (owner fingerprint, note_id) for as long as this tab lives (the dedupe set is bounded FIFO, cleared on session lock): deps and
//        the seam are rebuilt every tick, so a redelivered note (ack lost) would otherwise send a receipt per delivery.
//  R3-3  receipts share the per-IP deposit bucket with the user's own sends (default 10 / 60 s). At most `maxPerWindow` (4) receipts start in any
//        `windowMs` (60 s); the rest wait in a BOUNDED in-memory queue and are started by later pump() calls (every enqueue and every poll tick).
//        Overflow is dropped: the sender simply stays at the honest "Sent" floor, which is the truth.
//
// Memory only, by design: a persistent receipt queue would be new state to protect and migrate. A receipt lost to a closed tab is the same honest floor.

export interface ReceiptOutboxOpts {
  now?: () => number;
  maxPerWindow?: number;
  windowMs?: number;
  maxQueue?: number;
  maxSeen?: number;
}

export interface ReceiptOutbox {
  /** Queue a receipt for (owner, note). Never throws, never awaits. A repeat of the same (owner, note) is ignored. */
  enqueue(ownerFingerprint: string, noteId: string, send: () => Promise<unknown>): void;
  /** Start as many queued sends as the rate window allows. Cheap; call it every poll tick. */
  pump(): void;
  /** Forget everything (session lock / identity switch): queued receipts are dropped and the dedupe set is reset. */
  clear(): void;
  /** For tests / diagnostics only. Counts, never contents. */
  stats(): { queued: number; seen: number; startedInWindow: number };
}

export function createReceiptOutbox(opts: ReceiptOutboxOpts = {}): ReceiptOutbox {
  const now = opts.now ?? Date.now;
  const maxPerWindow = opts.maxPerWindow ?? 4;
  const windowMs = opts.windowMs ?? 60_000;
  const maxQueue = opts.maxQueue ?? 200;
  const maxSeen = opts.maxSeen ?? 2000;

  const seen = new Set<string>();
  const seenOrder: string[] = [];
  const queue: Array<() => Promise<unknown>> = [];
  const startedAt: number[] = [];

  const remember = (key: string) => {
    seen.add(key);
    seenOrder.push(key);
    while (seenOrder.length > maxSeen) seen.delete(seenOrder.shift()!);
  };

  const pump = () => {
    const t = now();
    while (startedAt.length > 0 && t - startedAt[0] >= windowMs) startedAt.shift();
    while (queue.length > 0 && startedAt.length < maxPerWindow) {
      const send = queue.shift()!;
      startedAt.push(t);
      try {
        // fire and forget: a rejection or a synchronous throw is swallowed (the receipt is simply not confirmed), and no await ever waits on it
        void Promise.resolve(send()).catch(() => {});
      } catch {
        /* a synchronous throw from the sender */
      }
    }
  };

  return {
    enqueue(ownerFingerprint, noteId, send) {
      const key = `${ownerFingerprint}|${noteId}`;
      if (seen.has(key)) return;
      if (queue.length >= maxQueue) return; // overflow: not marked seen, so a later redelivery may still get a slot once the queue drains
      remember(key);
      queue.push(send);
      pump();
    },
    pump,
    clear() {
      seen.clear();
      seenOrder.length = 0;
      queue.length = 0;
      startedAt.length = 0;
    },
    stats: () => ({ queued: queue.length, seen: seen.size, startedInWindow: startedAt.length }),
  };
}

/** The one outbox the live poll uses. Cleared by live-book-poll on session lock / identity switch. */
export const receiptOutbox: ReceiptOutbox = createReceiptOutbox();
