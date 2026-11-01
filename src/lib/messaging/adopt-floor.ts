// src/lib/messaging/adopt-floor.ts
// L-318a (Archie lane:svrnty #3263, Flint #3266, task #739): the adopt replay guard must not depend on note retention. R5b compares a candidate
// first frame's SIGNED sent_at with the newest note STORED from that contact; with nothing stored it falls back to the 7-day relay window, so
// after the user deletes a conversation a replayed old first frame (from whoever kept a copy) could replace an established session.
//
// The floor: per contact, the newest signed sent_at of any first frame this device's session with them was created or adopted from. It is
// an encrypted row in the notes DB's 'settings' store (same pattern as the reset flag), so deleting a conversation does not touch it. The guard's
// bar becomes max(newest stored note, floor). Pure here: the key and the strict row. Nothing from any message text: a fingerprint and a time.
import { normalizeResetFp } from './reset-flag';
import { parseSentAtMs } from './session-adopt-policy';

export const ADOPT_FLOOR_PREFIX = 'adopt_floor:';

export interface AdoptFloorRow {
  /** The contact's fingerprint, lowercase hex. */
  fp: string;
  /** The newest signed sent_at of a first frame this session started from (ISO-8601 with a zone). */
  sent_at: string;
}

export function adoptFloorKey(peerFp: unknown): string | null {
  const fp = normalizeResetFp(peerFp);
  return fp ? `${ADOPT_FLOOR_PREFIX}${fp}` : null;
}

const KEYS = ['fp', 'sent_at'];

/** Strict: exactly {fp, sent_at}, fp lowercase hex, sent_at a strict ISO timestamp. Anything else is absent, never repaired. */
export function parseAdoptFloorRow(v: unknown): AdoptFloorRow | null {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const ks = Object.keys(o).sort();
  if (ks.length !== KEYS.length || ks.some((k, i) => k !== [...KEYS].sort()[i])) return null;
  if (typeof o.fp !== 'string' || o.fp !== o.fp.toLowerCase() || normalizeResetFp(o.fp) !== o.fp) return null;
  if (!Number.isFinite(parseSentAtMs(o.sent_at))) return null;
  return { fp: o.fp, sent_at: o.sent_at as string };
}

/** The floor to store after a session started from a frame signed `candidateIso`, given what is already stored: it only ever RISES. null = write nothing. */
export function raisedFloor(existingIso: string | undefined, candidateIso: unknown): string | null {
  const c = parseSentAtMs(candidateIso);
  if (!Number.isFinite(c)) return null; // an unusable time is never a floor
  const e = existingIso === undefined ? NaN : parseSentAtMs(existingIso);
  return Number.isFinite(e) && e >= c ? null : (candidateIso as string);
}
