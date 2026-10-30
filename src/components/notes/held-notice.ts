// src/components/notes/held-notice.ts
// #720 reliable receive: the AGGREGATE notice for messages this device could not turn into a stored message (contract v2 R3/R4).
// Pure: no React, no I/O. Every user-facing string is Hypatia's copy v0.3 (svrnty_720_receive_copy_v0.md, sha256 92e7c6ce) BY VALUE and
// a test pins each one. Rule for every line: say what THIS device observed; never a sender the device did not verify (F3/F4).
//
// Two things the copy doc does not settle, so they are NOT invented here (asked on lane:svrnty): the singular form for N = 1, and how
// the kept-line formats the date. Until she answers, N = 1 uses the same "N messages" text and the date comes from an injected formatter.

export type AggregateReason = 'missing_key' | 'different_encryption' | 'not_verified' | 'unknown_sender' | 'expired';

/** What the code actually did with THESE messages; the kept-line must match it (copy doc: "append exactly one"). */
export type Kept = 'relay' | 'local' | 'none';

export interface HeldNoticeInput {
  reason: AggregateReason;
  count: number;
  kept: Kept;
  /** The relay's `expires_at` for the held envelopes, as received (untrusted). Used only for kept === 'relay'. */
  expiresAt?: unknown;
  /** unknown_sender only: the what-to-do line applies only when the verified sender fingerprint was kept. */
  canAdmit?: boolean;
}

export interface HeldNotice {
  reason: AggregateReason;
  text: string;
  kept?: string;
  hint?: string;
}

const TEXT: Record<AggregateReason, (n: number) => string> = {
  missing_key: (n) => `${n} messages couldn't be opened on this device: they were sealed to a key this device doesn't have.`,
  different_encryption: (n) => `${n} messages arrived in a format this app can't open yet.`,
  not_verified: (n) => `${n} messages couldn't be verified, so they aren't shown.`,
  unknown_sender: (n) => `${n} messages from people not in your Gate.`,
  expired: (n) => `${n} messages arrived after their time limit and weren't accepted.`,
};

const HINT: Record<AggregateReason, string | null> = {
  missing_key: 'Restoring your keys on this device may open them.',
  different_encryption: 'Updating the app may open them.',
  not_verified: 'If you expected a message, ask the sender to send it again.',
  unknown_sender: 'Admit the sender to read them.',
  expired: null,
};

export const KEPT_RELAY_NO_DATE = "They're still on the relay, and this app will try again.";
export const KEPT_LOCAL = "They're saved on this device, not deleted.";
export const keptRelayUntil = (date: string) => `They're kept on the relay until ${date}, and this app will try again.`;

/** A relay that claims an expiry further out than this is not believed: the line falls back to the no-date wording. */
export const MAX_BELIEVABLE_EXPIRY_MS = 366 * 24 * 60 * 60 * 1000;

/**
 * The date to show, or null. Only a well-formed ISO time that is still in the future and not absurdly far out counts; anything else
 * (missing, malformed, past, a non-string) yields null so the caller uses the no-date line. Never computed from anything local.
 */
export function relayExpiry(raw: unknown, nowMs: number): number | null {
  if (typeof raw !== 'string') return null;
  const t = Date.parse(raw);
  if (!Number.isFinite(t) || t <= nowMs || t - nowMs > MAX_BELIEVABLE_EXPIRY_MS) return null;
  return t;
}

export function heldNotices(
  inputs: readonly HeldNoticeInput[],
  nowMs: number,
  formatDate: (ms: number) => string,
): HeldNotice[] {
  const out: HeldNotice[] = [];
  for (const i of inputs) {
    if (!Number.isInteger(i.count) || i.count < 1) continue; // 0 / junk: nothing to say (this is what clears a notice)
    const n: HeldNotice = { reason: i.reason, text: TEXT[i.reason](i.count) };
    if (i.kept === 'relay') {
      const t = relayExpiry(i.expiresAt, nowMs);
      n.kept = t === null ? KEPT_RELAY_NO_DATE : keptRelayUntil(formatDate(t));
    } else if (i.kept === 'local') {
      n.kept = KEPT_LOCAL;
    }
    const hint = HINT[i.reason];
    if (hint && (i.reason !== 'unknown_sender' || i.canAdmit === true)) n.hint = hint;
    out.push(n);
  }
  return out;
}
