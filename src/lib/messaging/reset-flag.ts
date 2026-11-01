// src/lib/messaging/reset-flag.ts
// #720 R4 (Flint reset-semantics v1): the per-contact flag "this device reset <contact> and has received no frame from them since". Pure: the key
// and the strict row shape. The store (reset-flag-store.ts) keeps it as an encrypted row in the per-owner notes DB, so it is unreadable after lock,
// dropped with the identity, and never in localStorage. It carries NO text from any message: a fingerprint (hex) and the time the user reset.
//
// Meaning (what the UI may say): the user reset this contact and no ratchet frame from them has OPENED since. It is set when the reset completes
// (whether or not a session row existed: our next message starts a fresh session either way) and cleared when the first frame from that contact opens.
import { parseSentAtMs } from './session-adopt-policy';

export const RESET_FLAG_PREFIX = 'reset_flag:';

// A contact fingerprint in lowercase hex. 128 is the bound (a 64-hex canonical id is the longest in use); the key stays under the 200-char row-key limit.
const FP_HEX = /^[0-9a-f]{1,128}$/;

export interface ResetFlagRow {
  /** The contact's fingerprint, lowercase hex. */
  fp: string;
  /** When the user's reset completed (ISO-8601 with a zone). */
  reset_at: string;
}

/** The lowercase-hex form of a contact fingerprint, or null when it is not hex (never a key built from raw text). */
export function normalizeResetFp(peerFp: unknown): string | null {
  if (typeof peerFp !== 'string') return null;
  const fp = peerFp.toLowerCase();
  return FP_HEX.test(fp) ? fp : null;
}

export function resetFlagKey(peerFp: unknown): string | null {
  const fp = normalizeResetFp(peerFp);
  return fp ? `${RESET_FLAG_PREFIX}${fp}` : null;
}

const KEYS = ['fp', 'reset_at'];

/** Strict: exactly {fp, reset_at}, fp lowercase hex, reset_at a strict ISO timestamp. Anything else is absent, never repaired. */
export function parseResetFlagRow(v: unknown): ResetFlagRow | null {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const o = v as Record<string, unknown>;
  const ks = Object.keys(o).sort();
  if (ks.length !== KEYS.length || ks.some((k, i) => k !== [...KEYS].sort()[i])) return null;
  if (typeof o.fp !== 'string' || o.fp !== o.fp.toLowerCase() || !FP_HEX.test(o.fp)) return null;
  if (!Number.isFinite(parseSentAtMs(o.reset_at))) return null;
  return { fp: o.fp, reset_at: o.reset_at as string };
}
