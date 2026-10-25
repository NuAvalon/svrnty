// Run: npx tsx --test src/lib/compose/compose-pin.test.ts
//
// The compose-key PIN (Flint K1-K5 lane:portal #1035; his required changes P1/P2 #1176; words = Hypatia §7 sha1 64c94d76).
//   P1  an ARRIVING request can never open a ceremony or ask for a write: decideSender returns only accept / no-card / unpinned / blocked-*.
//   P2  DAMAGED != ABSENT: an unreadable pin is its own blocked state and is never offered as a first pin.
//   K3  NO auto-pin: applyPinChoice is the ONLY door, and its `write` is non-null in exactly three cases, enumerated below over state x screen x choice.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  applyPinChoice, decideSender, dropCandidate, fp16Groups, isComposePinRecord, MAX_CANDIDATES, rememberCandidate, settingsView, startCeremony,
  type ComposePinRecord, type PinAction, type PinChoice, type PinScreen, type PinState,
} from './compose-pin';
import { PIN_COPY, PIN_DEFAULT_FOCUS } from './compose-pin-copy';
import { COMPOSE_NOTE_TYPE, parseComposeNote } from './compose-inbound';

const FP_A = '0123456789abcdef'.repeat(4); // 64 hex
const FP_B = 'fedcba9876543210'.repeat(4);
const FP_C = FP_A.slice(0, 16) + 'f'.repeat(48); // same first 16 hex as A, different identity
const NOW = '2026-10-25T08:00:00.000Z';
const REC_A: ComposePinRecord = { v: 1, fp: FP_A, pinned_at: '2026-10-24T00:00:00.000Z' };
const ABSENT: PinState = { state: 'absent' };
const PINNED_A: PinState = { state: 'pinned', record: REC_A };
const UNREADABLE: PinState = { state: 'unreadable' };
const LOCKED: PinState = { state: 'locked' };
const ALL_STATES: PinState[] = [ABSENT, PINNED_A, UNREADABLE, LOCKED];
const verified = (fingerprint: unknown) => ({ fingerprint, verified: true as unknown });

test('isComposePinRecord is strict: exactly {v,fp,pinned_at}; a prefix, uppercase, wrong version, extra/missing key or non-object is NOT a pin', () => {
  assert.equal(isComposePinRecord(REC_A), true);
  assert.equal(isComposePinRecord({ ...REC_A, fp: FP_A.slice(0, 40) }), true, '40-hex full fp is usable');
  for (const bad of [
    { ...REC_A, fp: FP_A.slice(0, 16) }, { ...REC_A, fp: FP_A.toUpperCase() }, { ...REC_A, fp: FP_A.slice(0, 39) }, { ...REC_A, v: 2 },
    { ...REC_A, extra: 1 }, { v: 1, fp: FP_A }, { ...REC_A, pinned_at: '' }, { ...REC_A, pinned_at: 5 }, null, undefined, 'x', [], [REC_A],
  ]) assert.equal(isComposePinRecord(bad), false, JSON.stringify(bad));
});

test('fp16Groups shows the first 16 hex in four groups of four (what Peter compares), never more', () => {
  assert.equal(fp16Groups(FP_A), '0123 4567 89ab cdef');
  assert.equal(fp16Groups(FP_B), 'fedc ba98 7654 3210');
});

// ───────────────────────────── P1: an arriving request ─────────────────────────────

test('an UNVERIFIED sender gets no card and records NO candidate, in every pin state and however "verified" is spelled (K2)', () => {
  for (const pin of ALL_STATES) {
    for (const v of [false, 'true', 1, undefined, null, 'yes', {}]) {
      for (const fp of [FP_A, FP_B]) {
        assert.deepEqual(decideSender(pin, { fingerprint: fp, verified: v }), { kind: 'no-card', logLine: PIN_COPY.unpinnedLog });
      }
    }
  }
});

test('P1: across every state x sender, decideSender NEVER returns a screen or a record to write, and only "accept" shows a card', () => {
  const senders = [verified(FP_A), verified(FP_B), verified(FP_C), verified(FP_A.slice(0, 16)), verified(null), { fingerprint: FP_A, verified: false }];
  let accepts = 0;
  for (const pin of ALL_STATES) {
    for (const s of senders) {
      const d = decideSender(pin, s) as Record<string, unknown>;
      assert.ok(['accept', 'no-card', 'unpinned', 'blocked-changed', 'blocked-unreadable'].includes(d.kind as string), String(d.kind));
      for (const k of ['screen', 'write', 'record', 'pin', 'pinned_at', 'v', 'next', 'action']) assert.ok(!(k in d), `${k} must not appear in ${JSON.stringify(d)}`);
      if (d.kind === 'accept') accepts++;
    }
  }
  assert.equal(accepts, 1, 'exactly one (state, sender) pair shows a card: pinned A + verified A');
});

test('absent + a VERIFIED sender -> "unpinned": nothing shown, the fp (lowercased, FULL) is only a CANDIDATE, with the log line', () => {
  assert.deepEqual(decideSender(ABSENT, verified(FP_A)), { kind: 'unpinned', candidate: FP_A, logLine: PIN_COPY.unpinnedLog });
  assert.deepEqual(decideSender(ABSENT, verified(FP_A.toUpperCase())), { kind: 'unpinned', candidate: FP_A, logLine: PIN_COPY.unpinnedLog });
});

test('P2 DAMAGED != ABSENT: an unreadable pin (or a pinned state carrying a malformed record) BLOCKS and is never offered as an unpinned/first-pin state', () => {
  assert.deepEqual(decideSender(UNREADABLE, verified(FP_B)), { kind: 'blocked-unreadable', candidate: FP_B, notice: PIN_COPY.unreadableNotice });
  const damaged = { state: 'pinned', record: { ...REC_A, fp: FP_A.slice(0, 16) } } as unknown as PinState;
  assert.equal(decideSender(damaged, verified(FP_A)).kind, 'blocked-unreadable');
  assert.notEqual(decideSender(UNREADABLE, verified(FP_B)).kind, 'unpinned');
});

test('pinned + same fp (case-insensitive) -> accept; a DIFFERENT verified fp -> blocked-changed with a PASSIVE notice that shows no key', () => {
  assert.deepEqual(decideSender(PINNED_A, verified(FP_A)), { kind: 'accept' });
  assert.deepEqual(decideSender(PINNED_A, verified(FP_A.toUpperCase())), { kind: 'accept' });
  const d = decideSender(PINNED_A, verified(FP_B));
  assert.deepEqual(d, { kind: 'blocked-changed', pinned: FP_A, candidate: FP_B, notice: PIN_COPY.changedNotice });
  assert.ok(d.kind === 'blocked-changed' && !d.notice.includes(FP_B.slice(0, 8)) && !d.notice.includes(FP_A.slice(0, 8)), 'the notice names no key');
});

test('SAME FIRST 16 HEX, different identity: a verified sender that shares the compared prefix with the pin is NOT the pin (it is a key change)', () => {
  assert.equal(fp16Groups(FP_C), fp16Groups(FP_A), 'Peter would see the same 16 characters');
  assert.deepEqual(decideSender(PINNED_A, verified(FP_C)), { kind: 'blocked-changed', pinned: FP_A, candidate: FP_C, notice: PIN_COPY.changedNotice });
  const seam = parseComposeNote({ plaintext: JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: { a: 'b' } }), senderFingerprint: FP_C, senderVerified: true }, FP_A);
  assert.ok(!seam.ok && seam.code === 'wrong-sender', 'and the receive seam refuses it too');
});

test('a 16-hex prefix (or junk, or a non-string) can neither match a pin nor become a candidate', () => {
  for (const fp of [FP_A.slice(0, 16), FP_A.slice(0, 63), '', 'zz', 42, null, undefined, {}, [FP_A]]) {
    for (const pin of ALL_STATES) assert.deepEqual(decideSender(pin, verified(fp)), { kind: 'no-card', logLine: PIN_COPY.unpinnedLog });
  }
});

test('a LOCKED session shows no card and records nothing', () => {
  assert.deepEqual(decideSender(LOCKED, verified(FP_A)), { kind: 'no-card', logLine: PIN_COPY.unpinnedLog });
});

test('decideSender never mutates its input', () => {
  const pin: PinState = Object.freeze({ state: 'pinned', record: Object.freeze({ ...REC_A }) }) as PinState;
  for (const s of [verified(FP_A), verified(FP_B), { fingerprint: FP_A, verified: false }]) decideSender(pin, s);
  assert.deepEqual(pin, PINNED_A);
});

// ───────────────────────────── Settings: what is shown and offered ─────────────────────────────

test('settingsView: the state line is verbatim §7 for each state, and the actions fit the state', () => {
  assert.deepEqual(settingsView(ABSENT, []), { status: 'not-pinned', line: 'Not pinned', actions: [], candidate: null });
  assert.deepEqual(settingsView(ABSENT, [FP_B]), { status: 'not-pinned', line: 'Not pinned', actions: ['pin'], candidate: FP_B });
  assert.deepEqual(settingsView(PINNED_A, []), { status: 'pinned', line: 'Pinned: 0123 4567 89ab cdef', actions: [], candidate: null });
  assert.deepEqual(settingsView(PINNED_A, [FP_A]), settingsView(PINNED_A, []), 'a candidate equal to the pin is not a change');
  assert.deepEqual(settingsView(PINNED_A, [FP_B]), { status: 'blocked-changed', line: 'Blocked: the key changed', actions: ['compare-new', 'keep-blocked'], candidate: FP_B });
  assert.deepEqual(settingsView(UNREADABLE, []), { status: 'blocked-unreadable', line: "Blocked: your pin couldn't be read", actions: [], candidate: null });
  assert.deepEqual(settingsView(UNREADABLE, [FP_B]), { status: 'blocked-unreadable', line: "Blocked: your pin couldn't be read", actions: ['re-pin'], candidate: FP_B });
  assert.deepEqual(settingsView(LOCKED, [FP_B]), { status: 'locked', line: '', actions: [], candidate: null });
});

test('settingsView never offers "pin" over a damaged pin or "re-pin" over an absent one; unusable candidates are ignored; a malformed pinned record is unreadable', () => {
  for (const pin of [PINNED_A, UNREADABLE, LOCKED]) assert.ok(!settingsView(pin, [FP_B]).actions.includes('pin'));
  for (const pin of [PINNED_A, ABSENT, LOCKED]) assert.ok(!settingsView(pin, [FP_B]).actions.includes('re-pin'));
  assert.deepEqual(settingsView(ABSENT, ['junk', FP_B.slice(0, 16)]).actions, []);
  assert.equal(settingsView({ state: 'pinned', record: { ...REC_A, v: 9 } } as unknown as PinState, []).status, 'blocked-unreadable');
});

// ───────────────────────────── Ceremonies: only from Settings, only for a fitting action ─────────────────────────────

const ACTIONS: PinAction[] = ['pin', 're-pin', 'compare-new', 'keep-blocked'];

test('EXHAUSTIVE: startCeremony opens a screen ONLY for (pin, absent), (re-pin, unreadable) and (compare-new, pinned, a DIFFERENT key)', () => {
  let opened = 0;
  for (const st of ALL_STATES) {
    for (const a of ACTIONS) {
      for (const c of [FP_B, FP_A, FP_C, 'junk', FP_B.slice(0, 16)]) {
        const sc = startCeremony(st, a, c);
        const should =
          (a === 'pin' && st.state === 'absent' && c === FP_B) || (a === 'pin' && st.state === 'absent' && c === FP_A) || (a === 'pin' && st.state === 'absent' && c === FP_C) ||
          (a === 're-pin' && st.state === 'unreadable' && (c === FP_B || c === FP_A || c === FP_C)) ||
          (a === 'compare-new' && st.state === 'pinned' && (c === FP_B || c === FP_C));
        assert.equal(sc !== null, should, `${st.state} + ${a} + ${c.slice(0, 6)}`);
        if (sc) opened++;
      }
    }
  }
  assert.equal(opened, 3 + 3 + 2, 'pin:3 candidates, re-pin:3, compare-new:2 (B and C differ from A; A itself does not)');
  assert.deepEqual(startCeremony(PINNED_A, 'compare-new', FP_B), { screen: 'replace', pinned: FP_A, candidate: FP_B });
  assert.deepEqual(startCeremony(ABSENT, 'pin', FP_B), { screen: 'first-pin', candidate: FP_B });
  assert.deepEqual(startCeremony(UNREADABLE, 're-pin', FP_B), { screen: 're-pin', candidate: FP_B });
});

const SCREENS: PinScreen[] = [
  { screen: 'first-pin', candidate: FP_B },
  { screen: 're-pin', candidate: FP_B },
  { screen: 'replace', pinned: FP_A, candidate: FP_B },
  { screen: 'replace', pinned: FP_C, candidate: FP_B }, // STALE: the pin is no longer the one this screen was opened for
];
const CHOICES: PinChoice[] = ['match', 'no-match'];

test('EXHAUSTIVE (K3): over every state x screen x choice, a pin is WRITTEN only for a confirmed "match" on a screen that still fits the stored state', () => {
  const writes: string[] = [];
  for (const st of ALL_STATES) {
    for (const s of SCREENS) {
      for (const c of CHOICES) {
        const out = applyPinChoice(st, s, c, NOW);
        const fits =
          (s.screen === 'first-pin' && st.state === 'absent') || (s.screen === 're-pin' && st.state === 'unreadable') ||
          (s.screen === 'replace' && st.state === 'pinned' && st.record.fp === s.pinned);
        const mayWrite = c === 'match' && fits;
        assert.equal(out.write !== null, mayWrite, `${st.state} + ${s.screen} + ${c}`);
        assert.equal(out.next, null, 'a decision always ends the ceremony');
        if (out.write) writes.push(`${st.state}/${s.screen}`);
      }
    }
  }
  assert.deepEqual(writes.sort(), ['absent/first-pin', 'pinned/replace', 'unreadable/re-pin']);
});

test('the written record is the FULL candidate fp in the strict shape, and it then ACCEPTS that sender and not a 16-hex prefix', () => {
  const out = applyPinChoice(ABSENT, SCREENS[0], 'match', NOW);
  assert.deepEqual(out.write, { v: 1, fp: FP_B, pinned_at: NOW });
  assert.equal(out.write!.fp.length, 64);
  assert.equal(isComposePinRecord(out.write), true);
  const after: PinState = { state: 'pinned', record: out.write! };
  assert.equal(decideSender(after, verified(FP_B)).kind, 'accept');
  assert.equal(decideSender(after, verified(FP_B.slice(0, 16))).kind, 'no-card');
});

test('notices: first-pin/re-pin say pinned|mismatch; replace says replaced|notReplaced; a mismatch writes NOTHING and the old pin STANDS (binds the §7 sentence)', () => {
  assert.equal(applyPinChoice(ABSENT, SCREENS[0], 'match', NOW).notice, 'pinned');
  assert.equal(applyPinChoice(ABSENT, SCREENS[0], 'no-match', NOW).notice, 'mismatch');
  assert.equal(applyPinChoice(UNREADABLE, SCREENS[1], 'match', NOW).notice, 'pinned');
  assert.equal(applyPinChoice(UNREADABLE, SCREENS[1], 'no-match', NOW).notice, 'mismatch');
  assert.equal(applyPinChoice(PINNED_A, SCREENS[2], 'match', NOW).notice, 'replaced');
  const no = applyPinChoice(PINNED_A, SCREENS[2], 'no-match', NOW);
  assert.deepEqual(no, { write: null, next: null, notice: 'notReplaced' });
  assert.match(PIN_COPY.notReplaced, /The old key stays pinned and the new one stays blocked/);
  // ...and "stays blocked" is true: the new key is still a blocked-changed sender afterwards, the old one still accepted
  assert.equal(decideSender(PINNED_A, verified(FP_B)).kind, 'blocked-changed');
  assert.equal(decideSender(PINNED_A, verified(FP_A)).kind, 'accept');
});

test('a choice that is not a button on the screen changes nothing; an unusable candidate can never be written', () => {
  assert.deepEqual(applyPinChoice(ABSENT, SCREENS[0], 'keep-blocked' as unknown as PinChoice, NOW), { write: null, next: SCREENS[0], notice: null });
  const bad: PinScreen = { screen: 'first-pin', candidate: FP_B.slice(0, 16) };
  assert.deepEqual(applyPinChoice(ABSENT, bad, 'match', NOW), { write: null, next: null, notice: 'mismatch' });
});

test('candidates: newest first, de-duplicated, lowercase, bounded, unusable ignored; dropCandidate removes one', () => {
  let l: string[] = [];
  l = rememberCandidate(l, FP_A); l = rememberCandidate(l, FP_B);
  assert.deepEqual(l, [FP_B, FP_A]);
  assert.deepEqual(rememberCandidate(l, FP_A.toUpperCase()), [FP_A, FP_B]);
  assert.deepEqual(rememberCandidate(l, 'junk'), l);
  assert.deepEqual(rememberCandidate(l, FP_A.slice(0, 16)), l);
  for (let i = 0; i < 20; i++) l = rememberCandidate(l, String(i % 10).repeat(64));
  assert.equal(l.length, MAX_CANDIDATES);
  assert.deepEqual(dropCandidate([FP_A, FP_B], FP_A.toUpperCase()), [FP_B]);
});

test('CONSISTENCY with the receive seam: decideSender says accept IFF parseComposeNote\'s sender gate lets the same sender through', () => {
  const plaintext = JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: { a: 'b' } });
  for (const st of ALL_STATES) {
    for (const fp of [FP_A, FP_B, FP_C, FP_A.slice(0, 16), FP_A.toUpperCase()]) {
      for (const v of [true, false]) {
        const accept = decideSender(st, { fingerprint: fp, verified: v }).kind === 'accept';
        const seam = parseComposeNote({ plaintext, senderFingerprint: fp, senderVerified: v }, st.state === 'pinned' ? st.record.fp : null).ok;
        assert.equal(accept, seam, `${st.state} fp=${fp.slice(0, 6)}.. len=${fp.length} verified=${v}`);
      }
    }
  }
});

// ───────────────────────────── The words ─────────────────────────────

test('COPY is verbatim Hypatia §7 (sha1 64c94d76; changedNotice + candidatesHeader from the corrected doc sha1 9a7d704e), pinned literally here', () => {
  assert.deepEqual({ ...PIN_COPY }, {
    stateNotPinned: 'Not pinned',
    statePinnedPrefix: 'Pinned: ',
    stateBlockedChanged: 'Blocked: the key changed',
    stateBlockedUnreadable: "Blocked: your pin couldn't be read",
    actionPin: 'Pin the key',
    actionCompareNew: 'Compare the new key',
    actionKeepBlocked: 'Keep it blocked',
    actionRePin: 'Re-pin the key',
    firstTitle: "Pin the noosphere portal's compose key",
    firstBody: 'Sign requests will only be shown from this key. Compare these 16 characters with the noosphere page AND with what you were told separately:',
    rePinTitle: "Re-pin the noosphere portal's compose key",
    rePinBody: "Your old pin couldn't be read, so there's nothing to compare it with. Compare these 16 characters with the noosphere page AND with what you were told separately:",
    match: 'They match, pin it',
    noMatch: "They don't match",
    mismatch: "Not pinned. Don't sign anything from the portal until the characters match, and tell the fleet they didn't.",
    pinned: "Pinned. Sign requests from this key will appear here. Pinning doesn't make a request safe: always read the card before you sign.",
    replaceTitle: 'Replace the pinned compose key?',
    replaceBody: 'The old key stops working once you pin this one. Compare these 16 characters with the noosphere page AND with what you were told separately:',
    oldLabel: 'Old: ',
    replaceMatch: 'They match, replace it',
    notReplaced: "Not replaced. The old key stays pinned and the new one stays blocked. Tell the fleet the characters didn't match.",
    replaced: "Replaced. Sign requests from the new key will appear here. Pinning doesn't make a request safe: always read the card before you sign.",
    changedNotice: "A sign request arrived from a key that isn't your pinned compose key. It was blocked. If the portal told you its key changed, compare it in Settings › Compose key.",
    candidatesHeader: 'Recently seen keys. None of these is checked: compare the characters with the noosphere page AND with what you were told separately before pinning one.',
    unreadableNotice: "Your compose pin couldn't be read, so sign requests are blocked. Re-pin it in Settings › Compose key.",
    unpinnedLog: "A sign request arrived from a key you haven't pinned. It wasn't shown.",
  });
});

test('the banned words are absent everywhere, and "safe" appears only in the two K4 lines, in a negation', () => {
  const BANNED = /trust this portal|verified portal|secure connection|continue anyway|\bverified\b|\bsecure\b|\btrust(?:ed)?\b|auto-?pin/i;
  for (const [k, v] of Object.entries(PIN_COPY)) assert.doesNotMatch(v, BANNED, k);
  const withSafe = Object.entries(PIN_COPY).filter(([, v]) => /\bsafe\b/i.test(v)).map(([k]) => k).sort();
  assert.deepEqual(withSafe, ['pinned', 'replaced']);
  for (const k of ['pinned', 'replaced'] as const) assert.match(PIN_COPY[k], /doesn't make a request safe/);
});

test('"Old:" appears only on the replace screen, and default focus is always the SAFE choice, never a "match" button', () => {
  assert.equal(PIN_DEFAULT_FOCUS['settings-changed'], 'actionKeepBlocked');
  for (const k of ['first-pin', 're-pin', 'replace'] as const) assert.equal(PIN_DEFAULT_FOCUS[k], 'noMatch');
  for (const f of Object.values(PIN_DEFAULT_FOCUS)) assert.ok(!/match/i.test(f) || f === 'noMatch', f);
  const withOld = Object.entries(PIN_COPY).filter(([k, v]) => k !== 'oldLabel' && v.includes('Old: ')).map(([k]) => k);
  assert.deepEqual(withOld, [], 'no other string carries an "Old:" label');
});
