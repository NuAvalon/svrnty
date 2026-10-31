// src/components/notes/ratchet-rows.ts
// #720 reliable receive, UI half (slice 2d-4 + T3): the NAMED rows shown in a contact's thread for a message from that AUTHENTICATED,
// ADMITTED contact that did not open, and the user-initiated "Reset message session" action.
// Pure: no React, no I/O. Every user-facing string is Hypatia's copy v0.9 (svrnty_720_receive_copy_v0_9.md, sha256 88387ea0) BY VALUE and
// a test pins each one. Semantics: Flint ratchet_reset_semantics_v1.md (sha256 05bac511) R1-R7.
// Rule for every line: say what THIS device observed. A named row exists only because the sender was authenticated and admitted (v2 R3).

/** The row's class, as the lib reports it (contract v5.3 typed result + Flint reset semantics R2/R5). */
export type NamedRowInput =
  | { kind: 'local'; phase: 'held' | 'recorded' } // ratchet-local: something on THIS device stopped it; held + retried, then recorded past the bound
  | { kind: 'desync'; phase: 'held' | 'recorded' } // ratchet-desync (v0.9, Apollo T2a): session.receive() failed; the sessions are out of step; held, then recorded
  | { kind: 'verdict'; firstFrameRejected?: boolean; outOfStep?: boolean } // ratchet-unopenable: the frame's fault; recorded + acked
  | { kind: 'session-reset' }; // released by a reset (ours, R2) or by adopting theirs (R5)

export interface NamedRow {
  line: string;
  hint?: string;
}

/**
 * The row for one message. `outOfStep` is the lib's per-contact flag: this device reset <contact> and has received no frame from them
 * since (R4), or lost the both-reset tie-break (R6). It changes the wording ONLY for a first-frame-rejected verdict; any other
 * first-frame-rejected keeps the v0.5 verdict lines (copy v0.7).
 */
export function namedRow(contact: string, row: NamedRowInput): NamedRow {
  switch (row.kind) {
    case 'local':
      return row.phase === 'held'
        ? {
            line: `A message from ${contact} couldn't be opened on this device yet: this device is missing a key it needs to open it. This app will keep trying.`,
            hint: 'Unlocking or restoring your keys on this device may open it.',
          }
        : {
            // v0.8: the recorded row's FIRST line (the held line's "yet … keep trying" would be false once recorded + acked)
            line: `A message from ${contact} arrived but couldn't be opened on this device.`,
            hint: "This app couldn't keep the message itself, only a note that it arrived. Restoring your keys on this device may help with new messages.",
          };
    case 'desync':
      // v0.9: never "missing a key" (that's LOCAL), and never "ask them to send it again" while held (a resend on an out-of-step
      // session fails the same way); the way out is the user-initiated reset.
      return row.phase === 'held'
        ? {
            line: `A message from ${contact} couldn't be opened on this device yet: your message sessions are out of step. This app will keep trying.`,
            hint: `If messages from ${contact} keep failing to open, you can reset your message session with them.`,
          }
        : {
            line: `A message from ${contact} arrived but couldn't be opened on this device.`,
            hint: `This app couldn't keep the message itself, only a note that it arrived. If messages from ${contact} keep failing, reset your message session with them, then ask them to send it again.`,
          };
    case 'verdict':
      if (row.firstFrameRejected && row.outOfStep) {
        return {
          line: `A message from ${contact} couldn't be opened: your message sessions are out of step. Your next message to ${contact} brings them back in step; then ask them to send it again.`,
        };
      }
      return {
        line: `A message from ${contact} arrived but couldn't be opened on this device.`,
        hint: `This app couldn't keep the message itself, only a note that it arrived. Ask ${contact} to send it again.`,
      };
    case 'session-reset':
      return {
        line: `A message from ${contact} couldn't be opened because your message session with them was restarted.`,
        hint: `Ask ${contact} to send it again.`,
      };
  }
}

// ---- Reset message session (T3, R1-R7): user-initiated only, Cancel is the default, never automatic.

export const resetButtonLabel = (contact: string) => `Reset message session with ${contact}`;

export const resetExplainer = (contact: string) =>
  `Use this if messages from ${contact} keep failing to open. Your message session with ${contact} restarts the next time you send them a message. Your contact, trust and saved messages stay as they are.`;

/** R2: the held messages a reset will discard, stated BEFORE confirm. N = 0 (or junk): no line at all. */
export function resetCountLine(contact: string, held: number): string | null {
  if (!Number.isInteger(held) || held < 1) return null;
  return held === 1
    ? `1 waiting message from ${contact} can't be opened after a reset and will be discarded. ${contact} will need to send it again.`
    : `${held} waiting messages from ${contact} can't be opened after a reset and will be discarded. ${contact} will need to send them again.`;
}

export const RESET_CONFIRM = 'Reset';
export const RESET_CANCEL = 'Cancel';

export interface ResetDialog {
  title: string;
  /** Dropped first if the cut order (Archie #2147, item 2) is applied; the count line and the buttons stay. */
  explainer: string;
  countLine: string | null;
  confirm: string;
  cancel: string;
  /** Which button has focus when the dialog opens: always Cancel (R1/R7). */
  focus: 'cancel';
}

export function resetDialog(contact: string, held: number): ResetDialog {
  return {
    title: resetButtonLabel(contact),
    explainer: resetExplainer(contact),
    countLine: resetCountLine(contact, held),
    confirm: RESET_CONFIRM,
    cancel: RESET_CANCEL,
    focus: 'cancel',
  };
}
