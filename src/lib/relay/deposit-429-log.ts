// src/lib/relay/deposit-429-log.ts
// Refused deposits (429) leave a log line naming WHY, so the operator can tell a per-IP rate-limit refusal from a
// mailbox-at-cap one (the response body is the same shape for both on purpose). The line carries no IP, mailbox id or blob.
//
// VOLUME IS BOUNDED: the first refusal of a reason logs at once, then at most ONE line per reason per LOG_EVERY_MS, however
// many refusals arrive (a flood of the cheapest 429 path must not become a flood of log writes). `count` is the running total
// for that reason, `since_last` the refusals folded into this line. Both are per process and start at 0 on restart.

export type Deposit429Reason = 'rate_limit' | 'mailbox_cap';

export const LOG_EVERY_MS = 60_000;

interface ReasonState {
  count: number;
  sinceLast: number;
  lastLogAt: number | null;
}

declare global {
  // eslint-disable-next-line no-var
  var __deposit429State: Record<Deposit429Reason, ReasonState> | undefined;
}

function state(): Record<Deposit429Reason, ReasonState> {
  if (!globalThis.__deposit429State) {
    globalThis.__deposit429State = {
      rate_limit: { count: 0, sinceLast: 0, lastLogAt: null },
      mailbox_cap: { count: 0, sinceLast: 0, lastLogAt: null },
    };
  }
  return globalThis.__deposit429State;
}

export function logDeposit429(reason: Deposit429Reason, now: number = Date.now()): void {
  const s = state()[reason];
  s.count++;
  s.sinceLast++;
  if (s.lastLogAt !== null && now - s.lastLogAt < LOG_EVERY_MS) return;
  console.warn(`relay deposit 429 reason=${reason} count=${s.count} since_last=${s.sinceLast}`);
  s.sinceLast = 0;
  s.lastLogAt = now;
}

export function resetDeposit429Counts(): void {
  globalThis.__deposit429State = undefined;
}
