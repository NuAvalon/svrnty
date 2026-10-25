// src/lib/compose/compose-pin.ts
// The compose-key PIN: who may put a sign card in front of Peter. Pure logic (the encrypted store wrapper lives in client-store.ts and is thin).
// Spec: Flint K1-K5 (lane:portal #1035) and his required changes P1/P2 (#1176); words in compose-pin-copy.ts (Hypatia §7, sha1 64c94d76).
//
// THE RULES THIS FILE ENFORCES, AND HOW:
//   P1  NO CEREMONY ON ARRIVAL. decideSender() reads the pin state and an arriving sender and says what to do WITH THE REQUEST. It can return only
//       accept / no-card / unpinned / blocked-changed / blocked-unreadable, and every one except accept is "no card". It never returns a screen and never
//       a record. A pin / replace / re-pin screen is opened ONLY by startCeremony(), which the Settings panel calls on Peter's own action.
//   P2  DAMAGED != ABSENT. PinState is four-way. 'unreadable' (a record that is present but cannot be read or validated) is its own BLOCKED state with
//       its own re-pin screen; it is never treated as 'absent', because that would silently reopen trust-on-first-use.
//   K3  NO AUTO-PIN. applyPinChoice() is the ONLY function that can ask for a pin to be written: its result has an explicit `write` field, and the
//       exhaustive test shows `write` is non-null in exactly three cases (first-pin/re-pin/replace, each with a confirmed "match" in a consistent state).
//
// WHAT A PIN IS: the FULL lowercase fingerprint (40 or 64 hex). Peter compares the first 16 against the portal page and what he was told out of band, but
// the app stores and matches the whole thing, so a different identity sharing a 16-hex prefix can never pass (see isUsablePin).
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

/** What the store knows. 'unreadable' = a record is PRESENT but could not be decrypted or validated (or the read itself failed): fail closed, never 'absent'. */
export type PinState =
  | { state: 'absent' }
  | { state: 'pinned'; record: ComposePinRecord }
  | { state: 'unreadable' }
  | { state: 'locked' };

/** The first 16 hex in four groups of four ("abcd ef01 2345 6789"): what the compare screens show Peter. */
export function fp16Groups(fp: string): string {
  const s = pinDisplay(fp);
  return `${s.slice(0, 4)} ${s.slice(4, 8)} ${s.slice(8, 12)} ${s.slice(12, 16)}`;
}

// ── 1. An arriving request: what to do WITH IT. Never a ceremony, never a record. ─────────────────────────────────────────────────────────────

export type SenderDecision =
  /** pinned, same full fp, sender-auth verified: the card may be shown. THE ONLY DECISION THAT SHOWS A CARD. */
  | { kind: 'accept' }
  /** unverified / junk sender / locked: nothing shown, nothing recorded. */
  | { kind: 'no-card'; logLine: string }
  /** a VERIFIED sender, nothing pinned: nothing shown; the fp is a CANDIDATE to remember (Settings may offer it). */
  | { kind: 'unpinned'; candidate: string; logLine: string }
  /** pinned, but a VERIFIED sender with a DIFFERENT fp: blocked; PASSIVE notice only (no buttons, no key shown). */
  | { kind: 'blocked-changed'; pinned: string; candidate: string; notice: string }
  /** the stored pin is unreadable: every request is blocked; PASSIVE notice only. */
  | { kind: 'blocked-unreadable'; candidate: string; notice: string };

const NO_CARD: SenderDecision = { kind: 'no-card', logLine: PIN_COPY.unpinnedLog };

/**
 * What to do with a compose request from `sender`. `sender.verified` must be exactly `true` (decryptFromContact's senderVerified): an unverified
 * sender gets NO card and records NO candidate, however "verified" is spelled (K2: senderVerified=true is mandatory here).
 */
export function decideSender(pin: PinState, sender: { fingerprint: unknown; verified: unknown }): SenderDecision {
  if (sender.verified !== true) return NO_CARD;
  if (typeof sender.fingerprint !== 'string') return NO_CARD;
  const fp = sender.fingerprint.toLowerCase();
  if (!isUsablePin(fp)) return NO_CARD; // a prefix or junk can neither match a pin nor become a candidate
  switch (pin.state) {
    case 'locked':
      return NO_CARD;
    case 'absent':
      return { kind: 'unpinned', candidate: fp, logLine: PIN_COPY.unpinnedLog };
    case 'unreadable':
      return { kind: 'blocked-unreadable', candidate: fp, notice: PIN_COPY.unreadableNotice };
    case 'pinned':
      if (!isComposePinRecord(pin.record)) return { kind: 'blocked-unreadable', candidate: fp, notice: PIN_COPY.unreadableNotice }; // defence in depth
      if (pin.record.fp === fp) return { kind: 'accept' };
      return { kind: 'blocked-changed', pinned: pin.record.fp, candidate: fp, notice: PIN_COPY.changedNotice };
    default:
      return NO_CARD; // an unknown state is never trusted
  }
}

// ── 2. Settings › Compose key: what the panel shows and which actions it offers ───────────────────────────────────────────────────────────────

export type PinAction = 'pin' | 're-pin' | 'compare-new' | 'keep-blocked';

export interface SettingsView {
  status: 'locked' | 'not-pinned' | 'pinned' | 'blocked-changed' | 'blocked-unreadable';
  /** The state line, verbatim §7; '' when locked (the panel renders nothing). */
  line: string;
  /** The actions offered right now. An action that needs a candidate is offered only when there is one to compare. */
  actions: PinAction[];
  /** The candidate those actions would act on (newest first), or null. */
  candidate: string | null;
}

/** `candidates` = recently seen VERIFIED sender fps (newest first). A candidate equal to the pin is not a change. */
export function settingsView(pin: PinState, candidates: readonly string[]): SettingsView {
  const usable = candidates.filter(isUsablePin);
  switch (pin.state) {
    case 'locked':
      return { status: 'locked', line: '', actions: [], candidate: null };
    case 'absent':
      return { status: 'not-pinned', line: PIN_COPY.stateNotPinned, actions: usable.length ? ['pin'] : [], candidate: usable[0] ?? null };
    case 'unreadable':
      return { status: 'blocked-unreadable', line: PIN_COPY.stateBlockedUnreadable, actions: usable.length ? ['re-pin'] : [], candidate: usable[0] ?? null };
    case 'pinned': {
      if (!isComposePinRecord(pin.record)) return settingsView({ state: 'unreadable' }, candidates);
      const other = usable.find((c) => c !== pin.record.fp) ?? null;
      if (other === null) return { status: 'pinned', line: `${PIN_COPY.statePinnedPrefix}${fp16Groups(pin.record.fp)}`, actions: [], candidate: null };
      return { status: 'blocked-changed', line: PIN_COPY.stateBlockedChanged, actions: ['compare-new', 'keep-blocked'], candidate: other };
    }
    default:
      return { status: 'locked', line: '', actions: [], candidate: null };
  }
}

// ── 3. Ceremonies: started ONLY by Peter's own action in Settings ─────────────────────────────────────────────────────────────────────────────

export type PinScreen =
  | { screen: 'first-pin'; candidate: string }
  | { screen: 're-pin'; candidate: string }
  | { screen: 'replace'; pinned: string; candidate: string };

/**
 * Open a compare screen. The ACTION must fit the STATE (a UI bug or a stale panel cannot open "replace" on an unpinned app, or "pin" over a damaged
 * pin), and the candidate must be a full usable fp. Anything else opens nothing. 'keep-blocked' has no screen (the panel just drops the candidate).
 */
export function startCeremony(pin: PinState, action: PinAction, candidate: string): PinScreen | null {
  if (!isUsablePin(candidate)) return null;
  if (action === 'pin' && pin.state === 'absent') return { screen: 'first-pin', candidate };
  if (action === 're-pin' && pin.state === 'unreadable') return { screen: 're-pin', candidate };
  if (action === 'compare-new' && pin.state === 'pinned' && isComposePinRecord(pin.record) && pin.record.fp !== candidate) {
    return { screen: 'replace', pinned: pin.record.fp, candidate };
  }
  return null;
}

export type PinChoice = 'match' | 'no-match';
export type PinNotice = 'pinned' | 'mismatch' | 'replaced' | 'notReplaced';

export interface PinOutcome {
  /** THE RECORD TO PERSIST NOW, or null = write nothing. This is the only way a pin is ever created or replaced. */
  write: ComposePinRecord | null;
  /** Where the UI goes next; null = the ceremony is over. */
  next: PinScreen | null;
  /** One of PIN_COPY's keys to show as the result line, or null. */
  notice: PinNotice | null;
}

/**
 * Apply Peter's choice on the screen he is looking at. `current` is the pin state AS STORED RIGHT NOW: a "match" writes only when the screen is still
 * consistent with it (first-pin <-> absent, re-pin <-> unreadable, replace <-> the same pinned key), so a stale screen can never write. `nowIso` is
 * injected so this stays pure.
 */
export function applyPinChoice(current: PinState, s: PinScreen, choice: PinChoice, nowIso: string): PinOutcome {
  const replace = s.screen === 'replace';
  const refuse: PinOutcome = { write: null, next: null, notice: replace ? 'notReplaced' : 'mismatch' };
  if (choice === 'no-match') return refuse;
  if (choice !== 'match') return { write: null, next: s, notice: null }; // not a button on this screen: change nothing
  if (!isUsablePin(s.candidate)) return refuse;
  const consistent =
    (s.screen === 'first-pin' && current.state === 'absent') ||
    (s.screen === 're-pin' && current.state === 'unreadable') ||
    (s.screen === 'replace' && current.state === 'pinned' && isComposePinRecord(current.record) && current.record.fp === s.pinned && s.pinned !== s.candidate);
  if (!consistent) return refuse;
  return { write: { v: 1, fp: s.candidate, pinned_at: nowIso }, next: null, notice: replace ? 'replaced' : 'pinned' };
}

/** Bounded, de-duplicated list of recent VERIFIED candidate fps (newest first) so Settings can offer "a key arrived" without letting a flood grow state. */
export const MAX_CANDIDATES = 3;
export function rememberCandidate(list: readonly string[], fp: string): string[] {
  const f = fp.toLowerCase();
  if (!isUsablePin(f)) return [...list];
  return [f, ...list.filter((x) => x !== f)].slice(0, MAX_CANDIDATES);
}
/** "Keep it blocked" / after a successful pin: forget a candidate. */
export function dropCandidate(list: readonly string[], fp: string): string[] {
  const f = fp.toLowerCase();
  return list.filter((x) => x !== f);
}
