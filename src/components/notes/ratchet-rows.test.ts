// #720 UI half: the named ratchet rows + the reset action. Every string is Hypatia's copy v0.9 (88387ea0) by value; the NEGs are the
// copy doc's own (LOCAL never says "ask them to resend", VERDICT never says "keep trying") plus the reset surfaces' NEVER list.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { namedRow, resetButtonLabel, resetCountLine, resetDialog, resetExplainer, RESET_CANCEL, RESET_CONFIRM, type NamedRowInput } from './ratchet-rows';

const ALL: NamedRowInput[] = [
  { kind: 'local', phase: 'held' },
  { kind: 'local', phase: 'recorded' },
  { kind: 'desync', phase: 'held' },
  { kind: 'desync', phase: 'recorded' },
  { kind: 'verdict' },
  { kind: 'verdict', firstFrameRejected: true },
  { kind: 'verdict', outOfStep: true },
  { kind: 'verdict', firstFrameRejected: true, outOfStep: true },
  { kind: 'session-reset' },
];
const text = (r: { line: string; hint?: string }) => `${r.line} ${r.hint ?? ''}`;

test('LOCAL held: exact line + hint (copy v0.6/v0.7)', () => {
  assert.deepEqual(namedRow('Ana', { kind: 'local', phase: 'held' }), {
    line: "A message from Ana couldn't be opened on this device yet: this device is missing a key it needs to open it. This app will keep trying.",
    hint: 'Unlocking or restoring your keys on this device may open it.',
  });
});

test('LOCAL past the bound (v0.8 first line): metadata only, no promise the lost one comes back', () => {
  assert.deepEqual(namedRow('Ana', { kind: 'local', phase: 'recorded' }), {
    line: "A message from Ana arrived but couldn't be opened on this device.",
    hint: "This app couldn't keep the message itself, only a note that it arrived. Restoring your keys on this device may help with new messages.",
  });
});

test('VERDICT: the v0.5 dead-letter lines, also for a first-frame-rejected that is NOT out of step', () => {
  const v = {
    line: "A message from Ana arrived but couldn't be opened on this device.",
    hint: "This app couldn't keep the message itself, only a note that it arrived. Ask Ana to send it again.",
  };
  assert.deepEqual(namedRow('Ana', { kind: 'verdict' }), v);
  assert.deepEqual(namedRow('Ana', { kind: 'verdict', firstFrameRejected: true }), v);
  assert.deepEqual(namedRow('Ana', { kind: 'verdict', outOfStep: true }), v, 'out of step changes only a first-frame-rejected verdict');
});

test('R4/R6 out of step: one neutral line, only for first-frame-rejected while out of step', () => {
  assert.deepEqual(namedRow('Ana', { kind: 'verdict', firstFrameRejected: true, outOfStep: true }), {
    line: "A message from Ana couldn't be opened: your message sessions are out of step. Your next message to Ana should bring them back in step; then ask them to send it again.",
  });
});

test('session-reset: one line true on both sides + true resend advice', () => {
  assert.deepEqual(namedRow('Ana', { kind: 'session-reset' }), {
    line: "A message from Ana couldn't be opened because your message session with them was restarted.",
    hint: 'Ask Ana to send it again.',
  });
});

test('NEG: "send it again" NEVER renders for a LOCAL row (a resend fails the same way when OUR key is missing)', () => {
  for (const phase of ['held', 'recorded'] as const) assert.doesNotMatch(text(namedRow('Ana', { kind: 'local', phase })), /send it again/i);
});

test('NEG: "keep trying" NEVER renders for a VERDICT or session-reset row, nor a RECORDED one (nothing retries them)', () => {
  const notRetried = ALL.filter((r) => r.kind === 'verdict' || r.kind === 'session-reset' || ('phase' in r && r.phase === 'recorded'));
  for (const r of notRetried) assert.doesNotMatch(text(namedRow('Ana', r)), /keep trying/i, JSON.stringify(r));
});

test('DESYNC (v0.9): exact held + recorded lines', () => {
  assert.deepEqual(namedRow('Ana', { kind: 'desync', phase: 'held' }), {
    line: "A message from Ana couldn't be opened on this device yet: your message sessions are out of step. This app will keep trying.",
    hint: 'If messages from Ana keep failing to open, you can reset your message session with them.',
  });
  assert.deepEqual(namedRow('Ana', { kind: 'desync', phase: 'recorded' }), {
    line: "A message from Ana arrived but couldn't be opened on this device.",
    hint: "This app couldn't keep the message itself, only a note that it arrived. If messages from Ana keep failing, reset your message session with them, then ask them to send it again.",
  });
});

test('NEG (v0.9): a DESYNC row never says "missing a key", and never "send it again" while HELD', () => {
  for (const phase of ['held', 'recorded'] as const) assert.doesNotMatch(text(namedRow('Ana', { kind: 'desync', phase })), /missing a key/i);
  assert.doesNotMatch(text(namedRow('Ana', { kind: 'desync', phase: 'held' })), /send (it|them) again/i);
});

test('the reset action: exact button, explainer, confirm/cancel; Cancel has focus', () => {
  assert.equal(resetButtonLabel('Ana'), 'Reset message session with Ana');
  assert.equal(
    resetExplainer('Ana'),
    'Use this if messages from Ana keep failing to open. Your message session with Ana restarts the next time you send them a message. Your contact, trust and saved messages stay as they are.',
  );
  assert.equal(RESET_CONFIRM, 'Reset');
  assert.equal(RESET_CANCEL, 'Cancel');
  const d = resetDialog('Ana', 0);
  assert.equal(d.focus, 'cancel');
  assert.equal(d.title, 'Reset message session with Ana');
});

test('R2 count line: plural, singular, and NO line for 0 or junk', () => {
  assert.equal(
    resetCountLine('Ana', 3),
    "3 waiting messages from Ana can't be opened after a reset and will be discarded. Ana will need to send them again.",
  );
  assert.equal(resetCountLine('Ana', 1), "1 waiting message from Ana can't be opened after a reset and will be discarded. Ana will need to send it again.");
  for (const n of [0, -1, 1.5, Number.NaN]) assert.equal(resetCountLine('Ana', n), null, String(n));
  assert.equal(resetDialog('Ana', 2).countLine, resetCountLine('Ana', 2));
});

test('NEVER on reset surfaces: secure session, fix/repair/recover, automatically, or what the contact sees', () => {
  const surfaces = [
    resetButtonLabel('Ana'),
    resetExplainer('Ana'),
    resetCountLine('Ana', 1) ?? '',
    resetCountLine('Ana', 2) ?? '',
    text(namedRow('Ana', { kind: 'session-reset' })),
    text(namedRow('Ana', { kind: 'verdict', firstFrameRejected: true, outOfStep: true })),
  ].join('\n');
  for (const bad of [/secure session/i, /\bfix/i, /repair/i, /recover/i, /automatic/i, /Ana (will )?(sees?|is told|gets? notified)/i, /notif/i])
    assert.doesNotMatch(surfaces, bad, String(bad));
});

test('NEVER on any row: deleted, lost, corrupt, spam, forged/fake (copy R4 #6)', () => {
  const rows = ALL.map((r) => text(namedRow('Ana', r))).join('\n');
  for (const bad of [/deleted/i, /\blost\b/i, /corrupt/i, /spam/i, /forged/i, /\bfake\b/i]) assert.doesNotMatch(rows, bad, String(bad));
});
