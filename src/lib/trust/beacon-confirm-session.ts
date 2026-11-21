// src/lib/trust/beacon-confirm-session.ts: the session around the code two phones compare. Pure: no store, no network, no screen; the clock and the random source are injected.
// One phone starts a session and shows a session nonce (a QR and the same characters as text); the other phone takes it in by scanning the QR or typing the characters; each phone then shows the code of its own role, and
// the person types the code read off the OTHER screen (the code on a phone's own screen does not match, except by the same one-in-a-million chance). A match confirms, a miss counts, and the session ends: after the first match, after three misses, after two minutes, or when it is dropped.
// The nonce reaches this module only through the scanned QR or the typed text, and leaves it once, at creation, as the text the screen draws. The session object holds no data property for it.
import { confirmCode, codesMatch, decideConfirmFromCompare, otherRole, NONCE_BYTES, type KeyView, type SessionKeys } from './beacon-confirm-code';

export const SESSION_MS = 120_000;
export const MAX_ATTEMPTS = 3;

export type SessionStatus = 'open' | 'confirmed' | 'ended' | 'expired' | 'dropped';
export type StartRefusal = 'own-key' | 'held-key' | 'reflected' | 'no-random' | 'invalid';
export type JoinRefusal = 'own-key' | 'held-key' | 'reflected' | 'invalid' | 'not-confirm-qr' | 'malformed' | 'short';
export type OwnCode = { ok: true; code: string } | { ok: false; reason: 'wrong-contact' | 'closed' };
export type EnterResult =
  | { kind: 'confirm'; generation: number }
  | { kind: 'mismatch'; attemptsLeft: number }
  | { kind: 'ended' }
  | { kind: 'refused'; reason: 'own-changed' | 'held-changed' | 'invalid' }
  | { kind: 'malformed' }
  | { kind: 'wrong-contact' }
  | { kind: 'expired' }
  | { kind: 'closed' };

export interface ConfirmSession {
  readonly role: 'starter' | 'scanner';
  /** The code this phone shows for the contact the session belongs to. */
  ownCode(contactId: string): OwnCode;
  /** The code typed from the other screen, with the two keys read again now. Only a match with both keys unchanged confirms. */
  enter(contactId: string, typed: string, nowKeys: SessionKeys): EnterResult;
  /** Ends the session and wipes the nonce. Safe to call more than once. */
  drop(): void;
  status(): SessionStatus;
}

export type StartResult =
  | { ok: true; session: ConfirmSession; shown: { qr: string; text: string } }
  | { ok: false; reason: StartRefusal };
export type JoinResult = { ok: true; session: ConfirmSession } | { ok: false; reason: JoinRefusal };

interface SessionOptions { now?: () => number; mono?: () => number; random?: (bytes: number) => Uint8Array }

const QR_PREFIX = 'svrnty-confirm:1:';
const QR_FORM = /^svrnty-confirm:1:([A-Z2-7]{26})$/;
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const TEXT_CHARS = 26;
const SIX_DIGITS = /^[0-9]{6}$/;

const defaultNow = (): number => Date.now();
/** The second clock: one that a wall-clock change cannot move. Expiry is judged on BOTH, so a clock set back inside the two minutes does not stretch them. */
const defaultMono = (): number => globalThis.performance.now();
const defaultRandom = (bytes: number): Uint8Array => globalThis.crypto.getRandomValues(new Uint8Array(bytes));

/** 16 bytes as 26 base32 characters; the last character carries three bits and two zero bits. */
function encode(b: Uint8Array): string {
  let acc = 0;
  let bits = 0;
  let out = '';
  for (const byte of b) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(acc << (5 - bits)) & 31];
  return out;
}

/** The inverse, for exactly 26 upper-case characters of the alphabet whose two trailing bits are zero; anything else is null. */
function decode(s: string): Uint8Array | null {
  if (!/^[A-Z2-7]{26}$/.test(s)) return null;
  const out = new Uint8Array(NONCE_BYTES);
  let acc = 0;
  let bits = 0;
  let at = 0;
  for (const ch of s) {
    acc = (acc << 5) | ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out[at++] = (acc >>> (bits - 8)) & 255;
      bits -= 8;
      acc &= (1 << bits) - 1;
    }
  }
  if (acc !== 0 || at !== NONCE_BYTES) {
    out.fill(0);
    return null;
  }
  return out;
}

const isContact = (c: unknown): c is string => typeof c === 'string' && c.length > 0;

interface Clocks { now: () => number; mono: () => number; startedAt: number; monoStart: number }

/** Both clocks read once, at the start; null when either fails or gives no number. */
function readClocks(opts: SessionOptions | undefined): Clocks | null {
  const now = opts?.now ?? defaultNow;
  const mono = opts?.mono ?? defaultMono;
  let startedAt = NaN;
  let monoStart = NaN;
  try { startedAt = now(); monoStart = mono(); } catch { return null; }
  return Number.isFinite(startedAt) && Number.isFinite(monoStart) ? { now, mono, startedAt, monoStart } : null;
}

type KeyCheck = { ok: true; keys: SessionKeys } | { ok: false; reason: 'own-key' | 'held-key' | 'reflected' | 'invalid' };

/** The two keys, checked the way the code checks them, and copied: a key changed in place after the start must still be seen as changed. */
function checkKeys(keys: unknown): KeyCheck {
  if (typeof keys !== 'object' || keys === null) return { ok: false, reason: 'invalid' };
  const k = keys as SessionKeys;
  const probe = confirmCode(k.own, k.held, new Uint8Array(NONCE_BYTES), 'starter');
  if (!probe.ok) return { ok: false, reason: probe.reason === 'nonce' || probe.reason === 'role' ? 'invalid' : probe.reason };
  const copy = (v: KeyView): KeyView => ({ pub: Uint8Array.from(v.pub), gen: v.gen });
  return { ok: true, keys: { own: copy(k.own), held: copy(k.held) } };
}

function openSession(role: 'starter' | 'scanner', contact: string, start: SessionKeys, nonce: Uint8Array, clocks: Clocks): ConfirmSession {
  const { now, mono, startedAt, monoStart } = clocks;
  let state: SessionStatus = 'open';
  let misses = 0;

  const end = (next: SessionStatus): void => {
    if (state === 'open') state = next;
    nonce.fill(0);
  };
  /** Expiry is checked on every call, on both clocks: a clock that moves back, or one that fails, never brings a session back or stretches it. */
  const refresh = (): SessionStatus => {
    if (state === 'open') {
      let t = NaN;
      let m = NaN;
      try { t = now(); m = mono(); } catch { t = NaN; }
      if (!Number.isFinite(t) || !Number.isFinite(m) || t - startedAt >= SESSION_MS || m < monoStart || m - monoStart >= SESSION_MS) end('expired');
    }
    return state;
  };

  return {
    role,
    ownCode(contactId) {
      const s = refresh();
      if (s !== 'open') return { ok: false, reason: 'closed' };
      if (contactId !== contact) return { ok: false, reason: 'wrong-contact' };
      const c = confirmCode(start.own, start.held, nonce, role);
      if (!c.ok) { end('ended'); return { ok: false, reason: 'closed' }; }
      return { ok: true, code: c.code };
    },
    enter(contactId, typed, nowKeys) {
      const s = refresh();
      if (s === 'expired') return { kind: 'expired' };
      if (s !== 'open') return { kind: 'closed' };
      if (contactId !== contact) return { kind: 'wrong-contact' };
      if (typeof typed !== 'string' || !SIX_DIGITS.test(typed)) return { kind: 'malformed' };
      const c = confirmCode(start.own, start.held, nonce, otherRole(role));   // the code this phone must be given is the one on the OTHER phone's screen
      if (!c.ok) { end('ended'); return { kind: 'closed' }; }
      const d = decideConfirmFromCompare(codesMatch(typed, c.code) ? 'match' : 'mismatch', start, nowKeys);
      if (d.confirm) { end('confirmed'); return { kind: 'confirm', generation: d.generation }; }
      if (d.reason === 'mismatch') {
        misses += 1;
        if (misses >= MAX_ATTEMPTS) { end('ended'); return { kind: 'ended' }; }
        return { kind: 'mismatch', attemptsLeft: MAX_ATTEMPTS - misses };
      }
      end('ended');
      return { kind: 'refused', reason: d.reason };
    },
    drop() { end('dropped'); },
    status() { return refresh(); },
  };
}

/** The phone that starts: draws the session nonce once, and shows it as a QR and as text. */
export function startConfirmSession(contactId: string, keys: SessionKeys, opts?: SessionOptions): StartResult {
  if (!isContact(contactId)) return { ok: false, reason: 'invalid' };
  const k = checkKeys(keys);
  if (!k.ok) return { ok: false, reason: k.reason };
  const clocks = readClocks(opts);
  if (!clocks) return { ok: false, reason: 'invalid' };
  let nonce: Uint8Array;
  try {
    const drawn = (opts?.random ?? defaultRandom)(NONCE_BYTES);
    if (!(drawn instanceof Uint8Array) || drawn.length !== NONCE_BYTES || drawn.every((x) => x === 0)) return { ok: false, reason: 'no-random' };
    nonce = drawn;
  } catch {
    return { ok: false, reason: 'no-random' };
  }
  const flat = encode(nonce);
  const text = (flat.match(/.{1,5}/g) ?? []).join(' ');
  return { ok: true, session: openSession('starter', contactId, k.keys, nonce, clocks), shown: { qr: QR_PREFIX + flat, text } };
}

function join(contactId: unknown, keys: unknown, opts: SessionOptions | undefined, readNumber: () => Uint8Array | JoinRefusal): JoinResult {
  if (!isContact(contactId)) return { ok: false, reason: 'invalid' };
  const k = checkKeys(keys);
  if (!k.ok) return { ok: false, reason: k.reason };
  const nonce = readNumber();
  if (!(nonce instanceof Uint8Array)) return { ok: false, reason: nonce };
  const clocks = readClocks(opts);
  if (!clocks) { nonce.fill(0); return { ok: false, reason: 'invalid' }; }
  return { ok: true, session: openSession('scanner', contactId, k.keys, nonce, clocks) };
}

/** The phone that scans: the QR must be exactly the confirm form. */
export function joinConfirmFromScan(contactId: string, keys: SessionKeys, payload: unknown, opts?: SessionOptions): JoinResult {
  return join(contactId, keys, opts, () => {
    const m = typeof payload === 'string' ? QR_FORM.exec(payload) : null;
    return (m ? decode(m[1]) : null) ?? 'not-confirm-qr';
  });
}

/** The phone that types: the characters read off the other screen, in any case, with spaces or hyphens between them and nothing else. */
export function joinConfirmFromTyped(contactId: string, keys: SessionKeys, text: unknown, opts?: SessionOptions): JoinResult {
  return join(contactId, keys, opts, () => {
    if (typeof text !== 'string') return 'malformed';
    const flat = text.replace(/[ -]/g, '');
    if (!/^[A-Za-z2-7]*$/.test(flat)) return 'malformed';
    if (flat.length < TEXT_CHARS) return 'short';
    if (flat.length > TEXT_CHARS) return 'malformed';
    return decode(flat.toUpperCase()) ?? 'malformed';
  });
}
