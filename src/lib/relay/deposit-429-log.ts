// src/lib/relay/deposit-429-log.ts
// One log line per refused deposit (429), naming WHY and a running count for that reason, so the operator can tell a
// per-IP rate-limit refusal from a mailbox-at-cap one (the response body is the same shape for both on purpose).
// The line carries no IP, mailbox id or blob. The count is per process and starts at 0 on restart.

export type Deposit429Reason = 'rate_limit' | 'mailbox_cap';

declare global {
  // eslint-disable-next-line no-var
  var __deposit429Counts: Record<Deposit429Reason, number> | undefined;
}

function counts(): Record<Deposit429Reason, number> {
  if (!globalThis.__deposit429Counts) globalThis.__deposit429Counts = { rate_limit: 0, mailbox_cap: 0 };
  return globalThis.__deposit429Counts;
}

export function logDeposit429(reason: Deposit429Reason): void {
  const n = ++counts()[reason];
  console.warn(`relay deposit 429 reason=${reason} count=${n}`);
}

export function resetDeposit429Counts(): void {
  globalThis.__deposit429Counts = undefined;
}
