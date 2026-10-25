// src/lib/compose/compose-receive.ts
// The note-open pipeline as DATA: given one accepted inbound note, the pin state and the queue, decide what happens. PURE (no React, no store, no keys), so
// every branch has a test. The host component (ComposeRequestHost) only reads the record, calls this, and renders the result.
//
// PRECONDITION the caller states with `authenticatedByAcceptance: true`: the record came through acceptInboundNote (src/lib/messaging/transport.ts), which runs
// verifyNoteSender BEFORE isAdmitted, so `from_fingerprint` is a key the sender proved it holds. Nothing else may call this with a note that skipped that path.
//
// ORDER (Flint #996 Q3, K1-K5): (0) only an inbound note, and only one SHAPED like a compose request (so plain chat makes no candidate and no log noise);
// (1) the sender decision looks at the sender alone; (2) only an `accept` goes on to parse the note; (3) the parser then the validator; (4) the queue.
import { COMPOSE_NOTE_MAX_CHARS, COMPOSE_NOTE_TYPE, parseComposeNote, type InboundRefusalCode } from './compose-inbound';
import { decideSender, type PinState } from './compose-pin';
import { enqueue, type EnqueueOutcome, type QueueState } from './compose-queue';
import { dropLogLine, safeRef } from './compose-drop-log';

export interface AcceptedInboundNote {
  note_id: string;
  from_fingerprint: string;
  body: string;
  direction: string;
  /** Must be the literal true: the note was authenticated by acceptInboundNote before it was stored. */
  authenticatedByAcceptance: true;
}

export type ReceiveEvent =
  | { kind: 'ignored' }
  /** Nothing shown, nothing recorded. `logLine` is fixed text, never request text. */
  | { kind: 'no-card'; logLine: string }
  /** A verified sender, nothing pinned: remember the fp as a CANDIDATE (Settings may offer it). Nothing shown. */
  | { kind: 'unpinned'; candidate: string; logLine: string }
  /** Pinned, but a different verified key: blocked, PASSIVE notice only. */
  | { kind: 'blocked'; notice: string }
  /** Pinned sender, but the note did not parse as a compose request. The code is for a counter, never for display. */
  | { kind: 'bad-note'; code: InboundRefusalCode }
  /** Handed to the queue. `logLine` is set only for the thread-drop case (fixed text + the note id as the token). */
  | { kind: 'queued' | 'duplicate' | 'full' | 'dropped'; outcome: EnqueueOutcome; logLine: string | null };

/** A cheap shape test that looks at nothing but the note's top-level `type`. Bounded BEFORE it parses; never throws. Plain chat is false. */
export function isComposeShaped(body: unknown): boolean {
  if (typeof body !== 'string' || body.length === 0 || body.length > COMPOSE_NOTE_MAX_CHARS) return false;
  if (body.charCodeAt(0) !== 0x7b) return false; // '{'
  try {
    const o = JSON.parse(body) as unknown;
    return o !== null && typeof o === 'object' && !Array.isArray(o) && (o as { type?: unknown }).type === COMPOSE_NOTE_TYPE;
  } catch {
    return false;
  }
}

export function receiveComposeNote(
  note: AcceptedInboundNote,
  pin: PinState,
  queue: QueueState,
  now: Date,
): { queue: QueueState; event: ReceiveEvent } {
  const same = (event: ReceiveEvent) => ({ queue, event });
  if (note.authenticatedByAcceptance !== true) return same({ kind: 'ignored' }); // defence in depth: the type already requires it
  if (note.direction !== 'inbound') return same({ kind: 'ignored' });
  if (!isComposeShaped(note.body)) return same({ kind: 'ignored' });

  const d = decideSender(pin, { fingerprint: note.from_fingerprint, verified: true });
  switch (d.kind) {
    case 'no-card': return same({ kind: 'no-card', logLine: d.logLine });
    case 'unpinned': return same({ kind: 'unpinned', candidate: d.candidate, logLine: d.logLine });
    case 'blocked-changed': return same({ kind: 'blocked', notice: d.notice });
    case 'blocked-unreadable': return same({ kind: 'blocked', notice: d.notice });
    case 'accept': break;
    default: return same({ kind: 'ignored' }); // an unknown decision is never trusted
  }
  if (pin.state !== 'pinned') return same({ kind: 'ignored' }); // unreachable after `accept`; kept so the parse below never gets an unpinned fp

  const parsed = parseComposeNote(
    { plaintext: note.body, senderFingerprint: note.from_fingerprint, senderVerified: true },
    pin.record.fp,
  );
  if (!parsed.ok) return same({ kind: 'bad-note', code: parsed.code });

  const { state, result } = enqueue(queue, parsed.raw, now);
  const logLine = result.outcome === 'dropped' ? dropLogLine(result.code, safeRef(note.note_id)) : null;
  return { queue: state, event: { kind: result.outcome, outcome: result, logLine } as ReceiveEvent };
}
