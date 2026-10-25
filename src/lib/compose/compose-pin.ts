// src/lib/compose/compose-pin.ts
// The compose-key PIN: who may put a sign card in front of Peter. Pure logic (the encrypted store wrapper lives in client-store.ts and is thin).
// Spec: Flint K1-K5 (lane:portal #1035), words in compose-pin-copy.ts (Hypatia §7).
//
// THE TWO FUNCTIONS, AND WHY THERE ARE TWO:
//   decideSender()   READS the pin and an arriving sender and says what to show. It can NEVER produce a pin to persist. (K3: no auto-pin.)
//   applyPinChoice() applies one of Peter's BUTTON PRESSES to the screen he is looking at. It is the ONLY function that can create or
//                    replace a pin, and only for 'match' on a 'first-pin' or 'compare-new' screen. Every other (screen, choice) pair leaves
//                    the pin exactly as it was.
//
// WHAT A PIN IS: the FULL lowercase fingerprint (40 or 64 hex). Peter compares the first 16 against the portal page and what he was told
// out of band, but the app stores and matches the whole thing, so a different identity sharing a 16-hex prefix can never pass (see isUsablePin).
//
// K4 (honest limit): a pin narrows WHO can ask. It does not make a request safe; the safety is G1 (shown == signed) and the card itself.

import { isUsablePin, pinDisplay } from './compose-inbound';
import { PIN_COPY } from './compose-pin-copy';

export interface ComposePinRecord {
  v: 1;
  /** FULL lowercase fingerprint, 40 or 64 hex. */
  fp: string;
  /** ISO-8601 time Peter pinned it. Display/audit only; never used for a decision. */
  pinned_at: string;
}

/** Strict: exactly {v, fp, pinned_at}; fp must be a usable (full) pin; anything else is NOT a pin, so a damaged record can never pin by accident. */
export function isComposePinRecord(x: unknown): x is ComposePinRecord {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) return false;
  const keys = Object.keys(x).sort();
  if (keys.length !== 3 || keys[0] !== 'fp' || keys[1] !== 'pinned_at' || keys[2] !== 'v') return false;
  const r = x as Record<string, unknown>;
  return r.v === 1 && isUsablePin(r.fp) && typeof r.pinned_at === 'string' && r.pinned_at.length > 0 && r.pinned_at.length <= 40;
}

/** The first 16 hex in four groups of four ("abcd ef01 2345 6789"): what the first-pin and key-changed screens show Peter to compare. */
export function fp16Groups(fp: string): string {
  const s = pinDisplay(fp);
  return `${s.slice(0, 4)} ${s.slice(4, 8)} ${s.slice(8, 12)} ${s.slice(12, 16)}`;
}

export type SenderDecision =
  /** pinned, same full fp, sender-auth verified: the card may be shown. */
  | { kind: 'accept' }
  /** nothing pinned and a VERIFIED sender: offer the first-pin ceremony. Shows nothing else; pins nothing. */
  | { kind: 'first-pin'; candidate: string }
  /** pinned, but a VERIFIED sender with a DIFFERENT fp: requests blocked, offer the K3 ceremony. Pins nothing. */
  | { kind: 'key-changed'; pinned: string; candidate: string }
  /** no card, no ceremony: just the log line. */
  | { kind: 'no-card'; logLine: string };

const NO_CARD: SenderDecision = { kind: 'no-card', logLine: PIN_COPY.unpinnedLog };

/**
 * What to do with a compose request from `sender`. `sender.verified` must be exactly `true` (decryptFromContact's senderVerified): an unverified
 * sender gets NO card and NO ceremony, however it is spelled (K2: "senderVerified=true is mandatory here").
 */
export function decideSender(pin: ComposePinRecord | null | undefined, sender: { fingerprint: unknown; verified: unknown }): SenderDecision {
  if (sender.verified !== true) return NO_CARD;
  if (typeof sender.fingerprint !== 'string') return NO_CARD;
  const fp = sender.fingerprint.toLowerCase();
  if (!isUsablePin(fp)) return NO_CARD; // a prefix or junk can neither match a pin nor become a candidate
  if (!isComposePinRecord(pin)) return { kind: 'first-pin', candidate: fp }; // absent OR damaged ⇒ treated as "no pin": re-compare, never trust
  if (pin.fp === fp) return { kind: 'accept' };
  return { kind: 'key-changed', pinned: pin.fp, candidate: fp };
}

export type PinScreen =
  | { screen: 'first-pin'; candidate: string }
  | { screen: 'key-changed'; pinned: string; candidate: string }
  /** reached from key-changed via "Compare the new key": the same compare ceremony as the first pin, for the NEW key. */
  | { screen: 'compare-new'; pinned: string; candidate: string };

export type PinChoice = 'match' | 'no-match' | 'compare-new' | 'keep-blocked';

export interface PinOutcome {
  /** The pin AFTER this choice (unchanged unless Peter pressed "They match, pin it" on a compare screen). */
  pin: ComposePinRecord | null;
  /** Where the UI goes next; null = the ceremony is over. */
  next: PinScreen | null;
  /** One of PIN_COPY's keys to show as the result line, or null. */
  notice: 'pinned' | 'mismatch' | null;
}

/** The screen a decision opens, or null when there is no ceremony (accept / no-card). */
export function screenFor(d: SenderDecision): PinScreen | null {
  if (d.kind === 'first-pin') return { screen: 'first-pin', candidate: d.candidate };
  if (d.kind === 'key-changed') return { screen: 'key-changed', pinned: d.pinned, candidate: d.candidate };
  return null;
}

/**
 * Apply Peter's choice. `now` is injected (ISO string) so this stays pure. THE ONLY place a pin is created or replaced.
 * `current` is the pin as stored right now; it is returned untouched by every path except a confirmed match.
 */
export function applyPinChoice(current: ComposePinRecord | null, s: PinScreen, choice: PinChoice, nowIso: string): PinOutcome {
  const keep: PinOutcome = { pin: current, next: s, notice: null };
  if (s.screen === 'key-changed') {
    if (choice === 'compare-new') return { pin: current, next: { screen: 'compare-new', pinned: s.pinned, candidate: s.candidate }, notice: null };
    if (choice === 'keep-blocked') return { pin: current, next: null, notice: null };
    return keep; // 'match' / 'no-match' are not buttons on this screen: ignore, change nothing
  }
  // first-pin and compare-new are the same ceremony: compare 16 hex, then match or not.
  if (choice === 'match') {
    if (!isUsablePin(s.candidate)) return { pin: current, next: null, notice: 'mismatch' }; // cannot pin an unusable fp
    return { pin: { v: 1, fp: s.candidate, pinned_at: nowIso }, next: null, notice: 'pinned' };
  }
  if (choice === 'no-match') return { pin: current, next: null, notice: 'mismatch' };
  return keep; // 'compare-new' / 'keep-blocked' are not buttons here
}

/** Bounded, de-duplicated list of recent VERIFIED candidate fps (newest first) so Settings can offer "a key arrived" without letting a flood grow state. */
export const MAX_CANDIDATES = 3;
export function rememberCandidate(list: readonly string[], fp: string): string[] {
  const f = fp.toLowerCase();
  if (!isUsablePin(f)) return [...list];
  return [f, ...list.filter((x) => x !== f)].slice(0, MAX_CANDIDATES);
}
