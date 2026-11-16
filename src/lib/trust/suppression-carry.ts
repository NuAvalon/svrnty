// src/lib/trust/suppression-carry.ts: carrying the owner's suppression record (and the list of removed contacts) through a restore. PURE: no storage, no clock,
// no randomness. DARK: nothing outside tests imports it yet; the restore wiring comes after it is reviewed.
//
// The rules (the design ruling for the piece-2 restore gate):
//  - TIGHTEN ONLY. A record written from nothing is LOOSER than an absent one (absent reads as "suppress everyone"), so a restore may never write a global:false
//    record on its own. On a device that already holds a readable record the carried one is MERGED by tightening (persons and groups union, global OR); on a device
//    with no record the carried persons and groups are written at once with global TRUE (still dark), and a carried global:false waits for the person to confirm.
//  - A carried value is accepted ONLY by the strict parser below (refuse, never normalise, a malformed value), and the wiring reads it ONLY from a source the passphrase
//    authenticated (the vault, or a password-sealed file), never from a plaintext file.
//  - Export is all-or-nothing: a record that could not be read, or is too large to carry, or holds an entry the strict parser would refuse, is OMITTED, never truncated
//    (a truncated list would loosen the suppression). An omitted record restores dark.
//  - A REMOVE has its own list (`removed`, durable ids): a removed contact leaves no row to rebuild a latch from, so the list is what lets a restore keep it removed.
import { suppressGroup, suppressPerson, setGlobalSuppression, type SuppressionRecord } from './suppression';

/** Cap on each carried list. A list over the cap is not carried at all (export) or not accepted at all (parse); it is never cut short. */
export const CARRY_MAX_ENTRIES = 4096;

const DURABLE_ID = /^[0-9a-f]{64}$/;           // a person or a removed contact: a canonical lowercase-hex fingerprint (suppression.ts)
// A group id is opaque and owner-local (today a contact tag, so it may hold spaces or accents): any text without control characters (\p{Cc}: C0, DEL and C1), at most 128
// code points, and already in the stored form (trimmed, lowercase: suppression.ts norm()), because this parser never normalises. Format characters (ZWJ, bidi marks) stay legal:
// emoji tags need them, so whoever renders a group id must isolate it (<bdi> / dir="auto"). Accepting more text cannot loosen anything: a group entry only ever adds suppression.
const GROUP_ID = /^[^\p{Cc}]{1,128}$/u;
const groupIdOk = (s: string): boolean => GROUP_ID.test(s) && s === s.trim().toLowerCase();

export interface CarriedSuppression {
  v: 1;
  global: boolean;
  groups: string[];
  persons: string[];
  /** Durable ids of contacts the owner REMOVED, so a restore can rebuild their latches. Separate from `persons`. */
  removed: string[];
}

const KEYS = ['v', 'global', 'groups', 'persons', 'removed'];

// An index loop, not a.every(): every() skips holes, and a structured clone (IndexedDB) keeps a sparse array, so a hole must read as the non-string it is.
const listOk = (a: unknown, ok: (s: string) => boolean): a is string[] => {
  if (!Array.isArray(a) || a.length > CARRY_MAX_ENTRIES) return false;
  for (let i = 0; i < a.length; i += 1) {
    const s: unknown = a[i];
    if (typeof s !== 'string' || !ok(s)) return false;
  }
  return new Set(a).size === a.length;
};

/** The strict reader. Returns the carried record or null; null means "ignore it", never "read as empty". */
export function parseCarriedSuppression(x: unknown): CarriedSuppression | null {
  if (!x || typeof x !== 'object' || Array.isArray(x)) return null;
  const r = x as Record<string, unknown>;
  const keys = Object.keys(r);
  if (keys.length !== KEYS.length || !KEYS.every((k) => keys.includes(k))) return null;
  if (r.v !== 1 || typeof r.global !== 'boolean') return null;
  if (!listOk(r.groups, groupIdOk) || !listOk(r.persons, (s) => DURABLE_ID.test(s)) || !listOk(r.removed, (s) => DURABLE_ID.test(s))) return null;
  return { v: 1, global: r.global, groups: [...r.groups], persons: [...r.persons], removed: [...r.removed] };
}

/** The export side. `rec` is what getSuppressionRecord returned (null = unreadable or absent). Returns undefined (OMIT the field) unless the whole record can be carried. */
export function carrySuppression(rec: SuppressionRecord | null, removed: readonly string[]): CarriedSuppression | undefined {
  if (rec === null) return undefined;
  const candidate = { v: 1, global: rec.global, groups: [...rec.groups], persons: [...rec.persons], removed: [...removed] };
  return parseCarriedSuppression(candidate) ?? undefined;
}

/** A device that already holds a READABLE record: persons and groups union, global OR. Never loosens: a stale or hostile carried record can only add. Pure; no input is changed. */
export function mergeByTightening(existing: SuppressionRecord, carried: CarriedSuppression): SuppressionRecord {
  let rec: SuppressionRecord = { global: existing.global, groups: [...existing.groups], persons: [...existing.persons] };
  for (const p of carried.persons) rec = suppressPerson(rec, p);
  for (const g of carried.groups) rec = suppressGroup(rec, g);
  return setGlobalSuppression(rec, existing.global || carried.global);
}

export interface FreshDeviceWrite {
  /** What to write NOW: the carried persons and groups, with global TRUE (dark) whatever the backup said. */
  record: SuppressionRecord;
  /** True when the backup said global:false: the person may switch it off on a screen that names the backup's date, and not before. */
  globalOffWaitsForConfirm: boolean;
}

/** A device with NO record: persons and groups at once, global TRUE; a carried global:false waits for the person. */
export function freshDeviceWrite(carried: CarriedSuppression): FreshDeviceWrite {
  let rec: SuppressionRecord = { global: true, groups: [], persons: [] };
  for (const p of carried.persons) rec = suppressPerson(rec, p);
  for (const g of carried.groups) rec = suppressGroup(rec, g);
  return { record: rec, globalOffWaitsForConfirm: carried.global === false };
}

/** The person's confirmation on the dated screen: switch global OFF and change nothing else. The only path that writes global:false after a restore. */
export function confirmGlobalOff(rec: SuppressionRecord): SuppressionRecord {
  return setGlobalSuppression({ global: rec.global, groups: [...rec.groups], persons: [...rec.persons] }, false);
}

export type RemovedMerge = { ok: true; removed: string[] } | { ok: false; reason: 'too-large' };

/** Union of the removed lists (the existing ones first, then the carried ones not already there). Over the cap it REFUSES: a removed list cut short would let a deposit go to a contact the owner removed. */
export function mergeRemoved(existing: readonly string[], carried: readonly string[]): RemovedMerge {
  const out = [...existing];
  const seen = new Set(out);
  for (const id of carried) if (!seen.has(id)) { seen.add(id); out.push(id); }
  return out.length > CARRY_MAX_ENTRIES ? { ok: false, reason: 'too-large' } : { ok: true, removed: out };
}
