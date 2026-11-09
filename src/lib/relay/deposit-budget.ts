// src/lib/relay/deposit-budget.ts
// One byte budget for all deposits, per rate-limit window. Mailboxes are created on first deposit, so without this nothing bounds total storage
// except the disk watermark, which then refuses everyone until the TTLs expire. A flood can still use up the budget, so honest deposits are refused
// for as long as a flood lasts; the point is that the outage ends when the attack ends, instead of outlasting it by the whole retention.
// Charged only for bytes actually accepted. Per process, like the limiter.
//
// Default: room left before the disk watermark, divided by the windows in one retention, so a flood lasting the whole retention can't reach the
// watermark on this disk, large or small. Clamped: the ceiling bounds a big disk's exposure, the floor keeps a nearly full one able to take a little mail.
import { statfsSync } from 'node:fs';
import { mailboxConfig } from './mailbox-config';
import { dbPath } from './mailbox-store';
import { roomToWatermarkBytes, type StatfsLike } from './disk-watermark';

export const DERIVED_BUDGET_MAX = 24 * 1024 * 1024;
export const DERIVED_BUDGET_MIN = 64 * 1024; // one full-size message, so a nearly full disk can still take a note
const CHECK_MS = 30_000;

declare global {
  // eslint-disable-next-line no-var
  var __depositBudget: { windowStart: number; used: number } | undefined;
  // eslint-disable-next-line no-var
  var __depositBudgetDerived: { path: string; at: number; bytes: number } | undefined;
  // eslint-disable-next-line no-var
  var __depositBudgetLogged: boolean | undefined;
}

/** How many bytes one window may accept: the explicit setting, or derived from this disk (re-read at most every 30 s). An unreadable disk gets the ceiling, like the watermark's fail-open. */
export function depositBudgetBytes(path: string, now: number, statfs: (p: string) => StatfsLike = statfsSync): number {
  const cfg = mailboxConfig();
  if (cfg.globalDepositBytesPerWindow > 0) return cfg.globalDepositBytesPerWindow;
  const hit = globalThis.__depositBudgetDerived;
  if (hit && hit.path === path && now - hit.at < CHECK_MS) return hit.bytes;
  const room = path === ':memory:' ? null : roomToWatermarkBytes(path, statfs);
  const windows = Math.max(1, cfg.envelopeTtlMs / cfg.rateLimitWindowMs);
  const bytes = room === null ? DERIVED_BUDGET_MAX : Math.min(DERIVED_BUDGET_MAX, Math.max(DERIVED_BUDGET_MIN, Math.floor(room / windows)));
  if (!globalThis.__depositBudgetLogged && path !== ':memory:') {
    globalThis.__depositBudgetLogged = true;
    console.info(`[relay] deposit budget: ${bytes} bytes per window (derived from this disk${room === null ? ', unreadable: using the fixed default' : ''})`);
  }
  globalThis.__depositBudgetDerived = { path, at: now, bytes };
  return bytes;
}

function current(now: number, windowMs: number): { windowStart: number; used: number } {
  const s = globalThis.__depositBudget;
  if (s && now < s.windowStart + windowMs) return s;
  return (globalThis.__depositBudget = { windowStart: now, used: 0 });
}

/** What a deposit spends: its blob, or a floor, since a row costs more to store than a tiny blob does. */
export function depositCharge(blobBytes: number): number {
  return Math.max(blobBytes, 512);
}

export function depositBudgetAllows(bytes: number, now: number): boolean {
  return current(now, mailboxConfig().rateLimitWindowMs).used + bytes <= depositBudgetBytes(dbPath(), now);
}

export function chargeDepositBudget(bytes: number, now: number): void {
  current(now, mailboxConfig().rateLimitWindowMs).used += bytes;
}

/** Test seam. */
export function resetDepositBudget(): void {
  globalThis.__depositBudget = undefined;
  globalThis.__depositBudgetDerived = undefined;
  globalThis.__depositBudgetLogged = undefined;
}
