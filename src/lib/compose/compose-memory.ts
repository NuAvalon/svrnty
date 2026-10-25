// src/lib/compose/compose-memory.ts
// What the sign-view must REMEMBER across reloads and between tabs (Flint #1489 C1/C3). PURE: no storage, no clock of its own (every function takes `now`), so each rule
// has a test that can fail. The encrypted-store wrapper lives in client-store.ts and is thin.
//
//   C1  RESOLVED NONCES. A request the person signed OR declined (or closed as a refusal) must never raise a card again until its own expires_at, even after a
//       reload or in a second tab. Without this a replay of the same note is a second signature, or a "Don't sign" that comes back as pressure.
//   C3  NOTICE LIMIT. The passive "the portal's key changed" notice can be triggered by ANY admitted contact, so it is shown at most once per sender per 24 h.
//       The notice itself is fixed copy (PIN_COPY); it never carries the sender's text or fingerprint.
//
// Bounded on purpose: a flood of distinct nonces or senders cannot grow the record (oldest entries are evicted first).
import { isUsablePin } from './compose-inbound';

export const MEMORY_RESOLVED_CAP = 128;
export const MEMORY_NOTICED_CAP = 16;
export const NOTICE_INTERVAL_MS = 24 * 60 * 60 * 1000;

export interface ComposeMemory {
  v: 1;
  /** nonce (32 lowercase hex) -> epoch ms until which it stays resolved (the request's own expires_at). */
  resolved: Record<string, number>;
  /** sender fingerprint (full, lowercase) -> epoch ms the passive notice was last shown for it. */
  noticed: Record<string, number>;
}

const NONCE = /^[0-9a-f]{32}$/;
const isMs = (n: unknown): n is number => typeof n === 'number' && Number.isFinite(n) && n >= 0 && n < 1e14;
const plainObject = (x: unknown): x is Record<string, unknown> => typeof x === 'object' && x !== null && !Array.isArray(x);

export function emptyMemory(): ComposeMemory {
  return { v: 1, resolved: {}, noticed: {} };
}

/** Strict: exactly {v, resolved, noticed}, every key and value well formed, within the caps. Anything else is NOT a memory (the caller starts a fresh one). */
export function isComposeMemory(x: unknown): x is ComposeMemory {
  if (!plainObject(x)) return false;
  const keys = Object.keys(x).sort();
  if (keys.length !== 3 || keys[0] !== 'noticed' || keys[1] !== 'resolved' || keys[2] !== 'v') return false;
  if (x.v !== 1 || !plainObject(x.resolved) || !plainObject(x.noticed)) return false;
  const r = Object.entries(x.resolved);
  const n = Object.entries(x.noticed);
  if (r.length > MEMORY_RESOLVED_CAP || n.length > MEMORY_NOTICED_CAP) return false;
  return r.every(([k, v]) => NONCE.test(k) && isMs(v)) && n.every(([k, v]) => isUsablePin(k) && isMs(v));
}

/** Drop what is no longer needed: a resolved nonce past its expires_at (the validator refuses it as expired anyway) and a notice older than 24 h. */
export function pruneMemory(m: ComposeMemory, now: number): ComposeMemory {
  const resolved: Record<string, number> = {};
  for (const [k, v] of Object.entries(m.resolved)) if (v > now) resolved[k] = v;
  const noticed: Record<string, number> = {};
  for (const [k, v] of Object.entries(m.noticed)) if (now - v < NOTICE_INTERVAL_MS) noticed[k] = v;
  return { v: 1, resolved, noticed };
}

function evict(rec: Record<string, number>, cap: number): Record<string, number> {
  const entries = Object.entries(rec);
  if (entries.length <= cap) return rec;
  entries.sort((a, b) => a[1] - b[1]); // smallest value (soonest to lapse / oldest) first
  return Object.fromEntries(entries.slice(entries.length - cap));
}

/** Remember that `nonce` was resolved, until `expiresAtMs`. A malformed nonce or time changes nothing (and so remembers nothing: the caller must not assume it did). */
export function addResolved(m: ComposeMemory, nonce: string, expiresAtMs: number, now: number): ComposeMemory {
  if (typeof nonce !== 'string' || !NONCE.test(nonce) || !isMs(expiresAtMs)) return m;
  const base = pruneMemory(m, now);
  const prev = base.resolved[nonce];
  const resolved = evict({ ...base.resolved, [nonce]: prev === undefined ? expiresAtMs : Math.max(prev, expiresAtMs) }, MEMORY_RESOLVED_CAP);
  return { v: 1, resolved, noticed: base.noticed };
}

export function isResolved(m: ComposeMemory, nonce: string, now: number): boolean {
  const until = m.resolved[nonce];
  return until !== undefined && until > now;
}

/** True when the passive notice may be shown for this sender now (never shown for a malformed fingerprint). */
export function shouldNotice(m: ComposeMemory, senderFp: string, now: number): boolean {
  const fp = typeof senderFp === 'string' ? senderFp.toLowerCase() : '';
  if (!isUsablePin(fp)) return false;
  const last = m.noticed[fp];
  return last === undefined || now - last >= NOTICE_INTERVAL_MS || last > now; // a clock that went backwards must not silence it forever
}

export function markNoticed(m: ComposeMemory, senderFp: string, now: number): ComposeMemory {
  const fp = typeof senderFp === 'string' ? senderFp.toLowerCase() : '';
  if (!isUsablePin(fp) || !isMs(now)) return m;
  const base = pruneMemory(m, now);
  return { v: 1, resolved: base.resolved, noticed: evict({ ...base.noticed, [fp]: now }, MEMORY_NOTICED_CAP) };
}

/** Union of two memories (another tab may have written since we read): the later time wins for every key. Used before every write. */
export function mergeMemory(a: ComposeMemory, b: ComposeMemory, now: number): ComposeMemory {
  const resolved: Record<string, number> = { ...a.resolved };
  for (const [k, v] of Object.entries(b.resolved)) resolved[k] = Math.max(resolved[k] ?? 0, v);
  const noticed: Record<string, number> = { ...a.noticed };
  for (const [k, v] of Object.entries(b.noticed)) noticed[k] = Math.max(noticed[k] ?? 0, v);
  const p = pruneMemory({ v: 1, resolved, noticed }, now);
  return { v: 1, resolved: evict(p.resolved, MEMORY_RESOLVED_CAP), noticed: evict(p.noticed, MEMORY_NOTICED_CAP) };
}
