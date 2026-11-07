// src/lib/trust/psi-epoch-flags.ts
/**
 * The three switches that bring per-epoch PSI elements in, and the order they may be turned on. Pure: no storage, no environment, no clock; the
 * caller reads the switches from wherever they live and passes them here. All three are OFF unless a caller says otherwise.
 *
 *   F1 receive  - take in and store a friend's epoch notes (slice 1c). Nothing is sent and nothing matches on them.
 *   F2 send     - send our epoch notes to friends (slice 1d).
 *   F3 use      - PSI matches on epoch elements instead of bare fingerprints (slice 1e).
 *
 * Order: F1, then F2, then F3. A sender must never send to a fleet that cannot yet take the notes in, and PSI must never match on elements nobody
 * has been sent. So F2 on with F1 off, and F3 on with F2 off, are refused: a flip mistake fails loud instead of reaching an unprepared fleet.
 */
export interface PsiEpochFlags {
  /** F1 */
  receive: boolean;
  /** F2 */
  send: boolean;
  /** F3 */
  use: boolean;
}

/** Every switch off. */
export const PSI_EPOCH_FLAGS_OFF: Readonly<PsiEpochFlags> = Object.freeze({ receive: false, send: false, use: false });

export type FlagOrderViolation = 'send-needs-receive' | 'use-needs-send';

export type FlagOrderCheck = { ok: true } | { ok: false; violation: FlagOrderViolation; detail: string };

/** Why a set of switches is out of order, or ok. A switch that is not exactly `true` counts as off. */
export function checkFlagOrder(flags: Partial<PsiEpochFlags>): FlagOrderCheck {
  const receive = flags.receive === true;
  const send = flags.send === true;
  const use = flags.use === true;
  if (send && !receive) return { ok: false, violation: 'send-needs-receive', detail: 'F2 (send epoch notes) is on but F1 (receive and store them) is off' };
  if (use && !send) return { ok: false, violation: 'use-needs-send', detail: 'F3 (match on epoch elements) is on but F2 (send epoch notes) is off' };
  return { ok: true };
}

export class FlagOrderError extends Error {
  constructor(readonly violation: FlagOrderViolation, detail: string) {
    super(`psi-epoch-flags: ${violation}: ${detail}`);
    this.name = 'FlagOrderError';
  }
}

/** Throws FlagOrderError if the switches are out of order. Call it wherever a switch is acted on (build or send a note, use an element). */
export function assertFlagOrder(flags: Partial<PsiEpochFlags>): void {
  const c = checkFlagOrder(flags);
  if (!c.ok) throw new FlagOrderError(c.violation, c.detail);
}
