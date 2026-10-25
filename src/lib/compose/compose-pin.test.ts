// Run: npx tsx --test src/lib/compose/compose-pin.test.ts
//
// The compose-key PIN (Flint K1-K5, lane:portal #1035; words = Hypatia §7). The property that matters: NO sequence of events creates or replaces a pin
// except Peter pressing "They match, pin it" on a compare screen. decideSender can never pin; applyPinChoice is the only door, and it is enumerated here
// in full (every screen x every choice x every current pin), not sampled.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  applyPinChoice, decideSender, fp16Groups, isComposePinRecord, MAX_CANDIDATES, rememberCandidate, screenFor,
  type ComposePinRecord, type PinChoice, type PinScreen,
} from './compose-pin';
import { PIN_COPY, PIN_DEFAULT_FOCUS } from './compose-pin-copy';
import { COMPOSE_NOTE_TYPE, parseComposeNote } from './compose-inbound';

const FP_A = '0123456789abcdef'.repeat(4); // 64 hex
const FP_B = 'fedcba9876543210'.repeat(4);
const NOW = '2026-10-25T08:00:00.000Z';
const PIN_A: ComposePinRecord = { v: 1, fp: FP_A, pinned_at: '2026-10-24T00:00:00.000Z' };
const verified = (fingerprint: unknown) => ({ fingerprint, verified: true as unknown });

test('isComposePinRecord is strict: exactly {v,fp,pinned_at}; a prefix, uppercase, wrong version, extra/missing key or non-object is NOT a pin', () => {
  assert.equal(isComposePinRecord(PIN_A), true);
  assert.equal(isComposePinRecord({ ...PIN_A, fp: FP_A.slice(0, 40) }), true, '40-hex full fp is usable');
  for (const bad of [
    { ...PIN_A, fp: FP_A.slice(0, 16) }, { ...PIN_A, fp: FP_A.toUpperCase() }, { ...PIN_A, fp: FP_A.slice(0, 39) }, { ...PIN_A, v: 2 },
    { ...PIN_A, extra: 1 }, { v: 1, fp: FP_A }, { ...PIN_A, pinned_at: '' }, { ...PIN_A, pinned_at: 5 }, null, undefined, 'x', [], [PIN_A],
  ]) assert.equal(isComposePinRecord(bad), false, JSON.stringify(bad));
});

test('fp16Groups shows the first 16 hex in four groups of four (what Peter compares), never more', () => {
  assert.equal(fp16Groups(FP_A), '0123 4567 89ab cdef');
  assert.equal(fp16Groups(FP_B), 'fedc ba98 7654 3210');
});

test('an UNVERIFIED sender gets no card and NO ceremony, in every pin state and however "verified" is spelled (K2: senderVerified=true is mandatory)', () => {
  for (const pin of [null, undefined, PIN_A, { ...PIN_A, fp: 'junk' } as unknown as ComposePinRecord]) {
    for (const v of [false, 'true', 1, undefined, null, 'yes', {}]) {
      for (const fp of [FP_A, FP_B]) {
        const d = decideSender(pin, { fingerprint: fp, verified: v });
        assert.deepEqual(d, { kind: 'no-card', logLine: PIN_COPY.unpinnedLog });
      }
    }
  }
});

test('decideSender: no pin + verified sender -> first-pin ceremony for the FULL lowercase fp; a damaged pin is treated as no pin (re-compare, never trust)', () => {
  assert.deepEqual(decideSender(null, verified(FP_A)), { kind: 'first-pin', candidate: FP_A });
  assert.deepEqual(decideSender(undefined, verified(FP_A.toUpperCase())), { kind: 'first-pin', candidate: FP_A });
  assert.deepEqual(decideSender({ ...PIN_A, fp: FP_A.slice(0, 16) } as ComposePinRecord, verified(FP_B)), { kind: 'first-pin', candidate: FP_B });
});

test('decideSender: pinned + same fp (case-insensitive) -> accept; pinned + DIFFERENT verified fp -> key-changed (K3), with Old and New', () => {
  assert.deepEqual(decideSender(PIN_A, verified(FP_A)), { kind: 'accept' });
  assert.deepEqual(decideSender(PIN_A, verified(FP_A.toUpperCase())), { kind: 'accept' });
  assert.deepEqual(decideSender(PIN_A, verified(FP_B)), { kind: 'key-changed', pinned: FP_A, candidate: FP_B });
});

test('SAME FIRST 16 HEX, different identity: a verified sender that shares the compared prefix with the pin is NOT the pin (it is a key change), because the whole fp is matched', () => {
  const FP_C = FP_A.slice(0, 16) + 'f'.repeat(48);
  assert.equal(fp16Groups(FP_C), fp16Groups(FP_A), 'Peter would see the same 16 characters');
  assert.deepEqual(decideSender(PIN_A, verified(FP_C)), { kind: 'key-changed', pinned: FP_A, candidate: FP_C });
  const seam = parseComposeNote({ plaintext: JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: { a: 'b' } }), senderFingerprint: FP_C, senderVerified: true }, FP_A);
  assert.ok(!seam.ok && seam.code === 'wrong-sender', 'and the receive seam refuses it too');
});

test('a 16-hex prefix (or junk, or a non-string) can neither match a pin nor become a candidate', () => {
  for (const fp of [FP_A.slice(0, 16), FP_A.slice(0, 63), '', 'zz', 42, null, undefined, {}, [FP_A]]) {
    assert.deepEqual(decideSender(PIN_A, verified(fp)), { kind: 'no-card', logLine: PIN_COPY.unpinnedLog });
    assert.deepEqual(decideSender(null, verified(fp)), { kind: 'no-card', logLine: PIN_COPY.unpinnedLog });
  }
});

test('decideSender never mutates its input and its result carries NOTHING to persist: it cannot auto-pin (K3)', () => {
  const pin = Object.freeze({ ...PIN_A });
  for (const s of [verified(FP_A), verified(FP_B), { fingerprint: FP_A, verified: false }]) {
    const d = decideSender(pin, s) as Record<string, unknown>;
    assert.ok(!('pin' in d) && !('record' in d) && !('pinned_at' in d) && !('v' in d), `no persistable pin in ${JSON.stringify(d)}`);
    assert.deepEqual(pin, PIN_A);
  }
});

const SCREENS: PinScreen[] = [
  { screen: 'first-pin', candidate: FP_B },
  { screen: 'key-changed', pinned: FP_A, candidate: FP_B },
  { screen: 'compare-new', pinned: FP_A, candidate: FP_B },
];
const CHOICES: PinChoice[] = ['match', 'no-match', 'compare-new', 'keep-blocked'];

test('EXHAUSTIVE: across every screen x choice x current pin, a pin is created or replaced ONLY by "match" on first-pin or compare-new', () => {
  let pinning = 0;
  for (const cur of [null, PIN_A]) {
    for (const s of SCREENS) {
      for (const c of CHOICES) {
        const out = applyPinChoice(cur, s, c, NOW);
        const changed = JSON.stringify(out.pin) !== JSON.stringify(cur);
        const mayPin = c === 'match' && (s.screen === 'first-pin' || s.screen === 'compare-new');
        assert.equal(changed, mayPin, `${s.screen} + ${c} with ${cur ? 'a pin' : 'no pin'}`);
        if (mayPin) {
          pinning++;
          assert.deepEqual(out.pin, { v: 1, fp: FP_B, pinned_at: NOW });
          assert.equal(out.notice, 'pinned');
          assert.equal(out.next, null);
        }
      }
    }
  }
  assert.equal(pinning, 4, '2 screens x 2 current-pin states');
});

test('what gets stored is the FULL fingerprint (not the 16 Peter compared), and the same record shape isComposePinRecord accepts', () => {
  const out = applyPinChoice(null, SCREENS[0], 'match', NOW);
  assert.equal(out.pin!.fp.length, 64);
  assert.equal(isComposePinRecord(out.pin), true);
  assert.equal(decideSender(out.pin, verified(FP_B)).kind, 'accept');
  assert.equal(decideSender(out.pin, verified(FP_B.slice(0, 16))).kind, 'no-card');
});

test('"They don\'t match" pins nothing, shows the mismatch notice, and a replacement mismatch KEEPS the old pin', () => {
  assert.deepEqual(applyPinChoice(null, SCREENS[0], 'no-match', NOW), { pin: null, next: null, notice: 'mismatch' });
  assert.deepEqual(applyPinChoice(PIN_A, SCREENS[2], 'no-match', NOW), { pin: PIN_A, next: null, notice: 'mismatch' });
});

test('K3 rotation: "Keep it blocked" ends it with the old pin; "Compare the new key" moves to the compare ceremony and pins nothing yet', () => {
  assert.deepEqual(applyPinChoice(PIN_A, SCREENS[1], 'keep-blocked', NOW), { pin: PIN_A, next: null, notice: null });
  const cmp = applyPinChoice(PIN_A, SCREENS[1], 'compare-new', NOW);
  assert.deepEqual(cmp, { pin: PIN_A, next: { screen: 'compare-new', pinned: FP_A, candidate: FP_B }, notice: null });
  // and from there only an explicit match replaces it
  assert.deepEqual(applyPinChoice(PIN_A, cmp.next!, 'match', NOW).pin, { v: 1, fp: FP_B, pinned_at: NOW });
});

test('buttons that do not exist on a screen are ignored: you cannot "match" your way out of the key-changed screen', () => {
  const s = SCREENS[1];
  assert.deepEqual(applyPinChoice(PIN_A, s, 'match', NOW), { pin: PIN_A, next: s, notice: null });
  assert.deepEqual(applyPinChoice(PIN_A, s, 'no-match', NOW), { pin: PIN_A, next: s, notice: null });
  const f = SCREENS[0];
  assert.deepEqual(applyPinChoice(null, f, 'keep-blocked', NOW), { pin: null, next: f, notice: null });
  assert.deepEqual(applyPinChoice(null, f, 'compare-new', NOW), { pin: null, next: f, notice: null });
});

test('an unusable candidate can never be pinned, even if the UI hands one in', () => {
  const bad: PinScreen = { screen: 'first-pin', candidate: FP_B.slice(0, 16) };
  assert.deepEqual(applyPinChoice(null, bad, 'match', NOW), { pin: null, next: null, notice: 'mismatch' });
});

test('screenFor opens a ceremony only for first-pin and key-changed; accept and no-card open nothing', () => {
  assert.deepEqual(screenFor({ kind: 'first-pin', candidate: FP_B }), SCREENS[0]);
  assert.deepEqual(screenFor({ kind: 'key-changed', pinned: FP_A, candidate: FP_B }), SCREENS[1]);
  assert.equal(screenFor({ kind: 'accept' }), null);
  assert.equal(screenFor({ kind: 'no-card', logLine: 'x' }), null);
});

test('rememberCandidate: newest first, de-duplicated, lowercase, bounded, and ignores unusable fps (a flood cannot grow state)', () => {
  let l: string[] = [];
  l = rememberCandidate(l, FP_A); l = rememberCandidate(l, FP_B);
  assert.deepEqual(l, [FP_B, FP_A]);
  assert.deepEqual(rememberCandidate(l, FP_A.toUpperCase()), [FP_A, FP_B]);
  assert.deepEqual(rememberCandidate(l, 'junk'), l);
  assert.deepEqual(rememberCandidate(l, FP_A.slice(0, 16)), l);
  for (let i = 0; i < 20; i++) l = rememberCandidate(l, String(i % 10).repeat(64));
  assert.equal(l.length, MAX_CANDIDATES);
});

test('CONSISTENCY with the receive seam: decideSender says accept IFF parseComposeNote\'s sender gate lets the same sender through', () => {
  const plaintext = JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: { a: 'b' } });
  for (const pin of [null, PIN_A]) {
    for (const fp of [FP_A, FP_B, FP_A.slice(0, 16), FP_A.toUpperCase()]) {
      for (const v of [true, false]) {
        const accept = decideSender(pin, { fingerprint: fp, verified: v }).kind === 'accept';
        const seam = parseComposeNote({ plaintext, senderFingerprint: fp, senderVerified: v }, pin ? pin.fp : null).ok;
        assert.equal(accept, seam, `pin=${!!pin} fp=${fp.slice(0, 6)}.. len=${fp.length} verified=${v}`);
      }
    }
  }
});

test('COPY is verbatim Hypatia §7 (pinned literally here), and the banned words are absent everywhere', () => {
  assert.deepEqual({ ...PIN_COPY }, {
    firstTitle: "Pin the noosphere portal's compose key",
    firstBody: 'Sign requests will only be shown from this key. Compare these 16 characters with the noosphere page AND with what you were told separately:',
    match: 'They match, pin it',
    noMatch: "They don't match",
    mismatch: "Not pinned. Don't sign anything from the portal until the characters match, and tell the fleet they didn't.",
    pinned: "Pinned. Sign requests from this key will appear here. Pinning doesn't make a request safe: always read the card before you sign.",
    changed: "The portal's compose key changed. Requests from it are blocked until you compare the new key.",
    oldLabel: 'Old: ', newLabel: 'New: ',
    compareNew: 'Compare the new key', keepBlocked: 'Keep it blocked',
    unpinnedLog: "A sign request arrived from a key you haven't pinned. It wasn't shown.",
  });
  const BANNED = /trust this portal|verified portal|secure connection|continue anyway|\bverified\b|\bsecure\b|\btrust(?:ed)?\b|auto-?pin/i;
  for (const [k, v] of Object.entries(PIN_COPY)) assert.doesNotMatch(v, BANNED, k);
  const withSafe = Object.entries(PIN_COPY).filter(([, v]) => /\bsafe\b/i.test(v)).map(([k]) => k);
  assert.deepEqual(withSafe, ['pinned'], '"safe" appears only in the K4 line, in a negation');
});

test('default focus is always the SAFE choice: "Keep it blocked" on key-changed (Hypatia §7), never "They match" anywhere', () => {
  assert.equal(PIN_DEFAULT_FOCUS['key-changed'], 'keepBlocked');
  for (const f of Object.values(PIN_DEFAULT_FOCUS)) assert.notEqual(f, 'match');
});
