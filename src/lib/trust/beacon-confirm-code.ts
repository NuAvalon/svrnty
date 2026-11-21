// src/lib/trust/beacon-confirm-code.ts: the code two phones compare, in the same place, to confirm that each holds the other's CURRENT beacon key,
// and the one rule that turns a matching entry into a confirm. Pure: no store, no network, no clock, no randomness, no secret key.
//
// Each phone knows its own beacon public key and the copy of the other's key it holds. Both compute a 6-digit code over those two keys (with their
// generations), a session nonce and a ROLE (the phone that started the session is the 'starter', the phone that scanned the starter's QR, or typed what its screen shows, is the 'scanner').
// The pair is sorted before it is hashed, so the two phones agree on each role's code when each holds the other's current key; the role is hashed too,
// so the two roles' codes differ. A phone SHOWS the code of its own role and EXPECTS the code of the other role: the code it must be given is the one on
// the OTHER phone's screen, and the code on its own screen does not match, except by the same one-in-a-million chance. A stale or substituted key on EITHER side changes one of the two sets, so the
// codes differ, except for a chance match of about one in a million with 6 digits.
//
// A match shows that the two phones hold each other's current keys, up to a chance match of about one in a million per attempt with a 6-digit code. It does not prove who is holding either phone.
//
// The NONCE must reach the other phone only from the screen in front of it (a scan, or typed from that screen). If it travelled through a channel an
// attacker controls, the attacker could hand each side a different nonce and search for one that makes the two codes agree. This module only checks
// the nonce's length; keeping it on the screen is the session's job.

import { sha256 } from '@noble/hashes/sha2.js';

export const CONFIRM_DOMAIN = 'svrnty:beacon-confirm:v2';
export const KEY_BYTES = 32;
export const NONCE_BYTES = 16;
export const CODE_DIGITS = 6;

/** One beacon key as the code sees it: its 32 canonical bytes and its generation (a positive safe integer). */
export interface KeyView { pub: Uint8Array; gen: number }

/** The phone that started the session shows the starter's code; the phone that scanned the starter's QR (or typed what its screen shows) shows the scanner's. */
export type ConfirmRole = 'starter' | 'scanner';
export const otherRole = (r: ConfirmRole): ConfirmRole => (r === 'starter' ? 'scanner' : 'starter');
const isRole = (r: unknown): r is ConfirmRole => r === 'starter' || r === 'scanner';

export type CodeRefusal = 'own-key' | 'held-key' | 'nonce' | 'role' | 'reflected';
export type ConfirmCodeResult = { ok: true; code: string } | { ok: false; reason: CodeRefusal };

const isKey = (k: unknown): k is KeyView =>
  typeof k === 'object' && k !== null
  && (k as KeyView).pub instanceof Uint8Array && (k as KeyView).pub.length === KEY_BYTES
  && Number.isSafeInteger((k as KeyView).gen) && (k as KeyView).gen > 0;

const TWO_32 = 4294967296;

/** `pub || u64be(gen)`, 40 bytes. A generation is a safe integer, so it splits exactly into two 32-bit halves. */
function pairBytes(k: KeyView): Uint8Array {
  const out = new Uint8Array(KEY_BYTES + 8);
  out.set(k.pub, 0);
  const dv = new DataView(out.buffer);
  const hi = Math.floor(k.gen / TWO_32);
  dv.setUint32(KEY_BYTES, hi);
  dv.setUint32(KEY_BYTES + 4, k.gen - hi * TWO_32);
  return out;
}

/** A 4-byte big-endian length, then the bytes: no two different inputs can concatenate to the same string. */
function lp(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + b.length);
  new DataView(out.buffer).setUint32(0, b.length);
  out.set(b, 4);
  return out;
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  return a.length - b.length;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => compareBytes(a, b) === 0;

/**
 * The code of ONE role. `own` is this phone's own key, `held` the copy it holds of the other phone's key, `nonce` the session's 16 bytes, `role` which phone's code
 * this is: a phone shows confirmCode(..., its own role) and expects confirmCode(..., otherRole(its own role)).
 * Never throws; a refusal names the first thing wrong, in this order: own key, held key, nonce, role, reflection (the held key is this phone's own key).
 */
export function confirmCode(own: KeyView, held: KeyView, nonce: Uint8Array, role: ConfirmRole): ConfirmCodeResult {
  if (!isKey(own)) return { ok: false, reason: 'own-key' };
  if (!isKey(held)) return { ok: false, reason: 'held-key' };
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_BYTES) return { ok: false, reason: 'nonce' };
  if (!isRole(role)) return { ok: false, reason: 'role' };
  if (sameBytes(own.pub, held.pub)) return { ok: false, reason: 'reflected' };
  const [first, second] = [pairBytes(own), pairBytes(held)].sort(compareBytes);
  const input = new Uint8Array([...lp(new TextEncoder().encode(CONFIRM_DOMAIN)), ...lp(new TextEncoder().encode(role)), ...lp(first), ...lp(second), ...lp(nonce)]);
  const d = sha256(input);
  const dv = new DataView(d.buffer, d.byteOffset, d.byteLength);
  const n = BigInt(dv.getUint32(0)) * BigInt(TWO_32) + BigInt(dv.getUint32(4));
  return { ok: true, code: (n % BigInt(1000000)).toString().padStart(CODE_DIGITS, '0') };
}

/** The typed entry against the computed code: two equal strings, and the computed one a 6-digit code. No trimming and no other digit forms. */
export function codesMatch(typed: unknown, computed: unknown): boolean {
  return typeof typed === 'string' && typeof computed === 'string' && typed === computed && /^[0-9]{6}$/.test(computed);
}

export type CompareEntry = 'match' | 'mismatch';
export interface SessionKeys { own: KeyView; held: KeyView }
export type CompareDecision =
  | { confirm: true; generation: number }
  | { confirm: false; reason: 'mismatch' | 'own-changed' | 'held-changed' | 'invalid' };

const validSession = (s: unknown): s is SessionKeys => typeof s === 'object' && s !== null && isKey((s as SessionKeys).own) && isKey((s as SessionKeys).held);
const changed = (a: KeyView, b: KeyView): boolean => a.gen !== b.gen || !sameBytes(a.pub, b.pub);

/**
 * Whether a finished comparison confirms the pair. `start` is the pair of keys the session began with; `now` is the same two keys read again at the write.
 * A confirm needs a matching entry AND both keys unchanged in between; it returns the generation of the held key that was compared, which is what the
 * confirmed set records. A mismatch never confirms.
 */
export function decideConfirmFromCompare(entry: CompareEntry, start: SessionKeys, now: SessionKeys): CompareDecision {
  if (!validSession(start) || !validSession(now)) return { confirm: false, reason: 'invalid' };
  if (entry === 'mismatch') return { confirm: false, reason: 'mismatch' };
  if (entry !== 'match') return { confirm: false, reason: 'invalid' };
  if (changed(start.own, now.own)) return { confirm: false, reason: 'own-changed' };
  if (changed(start.held, now.held)) return { confirm: false, reason: 'held-changed' };
  return { confirm: true, generation: start.held.gen };
}
