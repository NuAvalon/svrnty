/**
 * Append-only provenance for every contact the headless CLI writes (#724 follow-up; Mneme + Archie, 2026-10-30).
 * Tonight a book row with mixed keys could not be traced: admits left no record of when, from where, or with which keys.
 * Each write now leaves lines in <agent dir>/admit-log.jsonl (0600, O_APPEND, never rewritten):
 *   { ts, source: admit | join | admit-gate, fp, card_sha256, keys_sha256, result }
 *  - card_sha256: the input as received (admit: the card file's bytes; join / admit-gate: the record handed to the store).
 *  - keys_sha256: the key set as written (public_key, pq_sig, pq_kem; an absent key hashes as ''), so a row can be matched
 *    to the card it came from.
 *  - No card body, no name: hashes and the fingerprint only. A fingerprint that doesn't look like one is logged as its hash.
 * withAdmitLog writes 'admitting' BEFORE the store write (if that line can't be written, nothing is written), then
 * 'admitted', or 'failed' and rethrows. Refusals are logged by the caller with appendAdmitLog.
 */
import { appendFileSync, chmodSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

export const ADMIT_LOG = 'admit-log.jsonl';
export type AdmitSource = 'admit' | 'join' | 'admit-gate';
export type AdmitResult =
  | 'admitting'
  | 'admitted'
  | 'failed'
  | 'refused:bad-card'
  | 'refused:no-key'
  | 'refused:durable-id'
  | 'refused:unbound';
export interface AdmitProvenance {
  source: AdmitSource;
  fp: unknown;
  card_sha256: string;
  keys_sha256: string;
}

export function sha256Hex(b: string | Uint8Array): string {
  return createHash('sha256').update(b).digest('hex');
}

export function keysSha256(k: { public_key?: unknown; pq_sig_public_key?: unknown; pq_kem_public_key?: unknown } | null | undefined): string {
  const s = (v: unknown) => (typeof v === 'string' ? v : '');
  return sha256Hex(JSON.stringify([s(k?.public_key), s(k?.pq_sig_public_key), s(k?.pq_kem_public_key)]));
}

function safeFp(fp: unknown): string {
  return typeof fp === 'string' && /^[0-9a-f]{16,128}$/.test(fp) ? fp : `unparseable:${sha256Hex(JSON.stringify(fp ?? null)).slice(0, 16)}`;
}

export function appendAdmitLog(dir: string, e: AdmitProvenance & { result: AdmitResult }): void {
  const p = join(dir, ADMIT_LOG);
  const line = { ts: new Date().toISOString(), source: e.source, fp: safeFp(e.fp), card_sha256: e.card_sha256, keys_sha256: e.keys_sha256, result: e.result };
  appendFileSync(p, JSON.stringify(line) + '\n', { mode: 0o600, flag: 'a' });
  chmodSync(p, 0o600);
}

export function withAdmitLog(dir: string, prov: AdmitProvenance, write: () => void): void {
  appendAdmitLog(dir, { ...prov, result: 'admitting' });
  try {
    write();
  } catch (e) {
    appendAdmitLog(dir, { ...prov, result: 'failed' });
    throw e;
  }
  appendAdmitLog(dir, { ...prov, result: 'admitted' });
}
