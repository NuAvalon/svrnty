// src/lib/messaging/session-reset.ts
// #720 RESET, the user action (Flint reset-semantics v1 R1 + R2; copy v0_9). User-initiated only: the caller is the confirm dialog, whose
// default is Cancel. Never called by a poll, never by a message (R7).
//
//   1. R1  drop ONLY this device's session row for that contact, under the per-peer lock (resetRatchetSession).
//   2. R2  turn that contact's HELD ratchet rows into session-reset records. The next poll finds them and acks the envelopes without opening
//          them. This is the one case where "ask them to send it again" is true advice: the loss is our own deliberate act.
// Order matters: the session is deleted FIRST. If it fails nothing was released (the frames are still held and still openable). If it succeeds
// and the marking fails, the frames stay held and a repeated reset marks them (both steps are idempotent); marking first could release frames
// for a reset that then failed.
import { resetRatchetSession } from './direct-session';
import { markSessionReset } from './dead-letter-store';

export interface SessionResetResult {
  /** A session row existed and was deleted. */
  hadSession: boolean;
  /** Held frames from this contact turned into session-reset records (the next poll acks them). */
  released: number;
}

export async function resetMessageSession(ownerFingerprint: string, peerFingerprint: string): Promise<SessionResetResult> {
  const hadSession = await resetRatchetSession(ownerFingerprint, peerFingerprint);
  const released = await markSessionReset(peerFingerprint.toLowerCase());
  return { hadSession, released };
}
