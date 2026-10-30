// src/components/notes/held-notice.test.ts
// #720: every string is Hypatia's copy v0.5 (sha256 4f8475d1) by VALUE; the kept-line date comes only from the relay's expires_at.
// Run: npx tsx --test src/components/notes/held-notice.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_BELIEVABLE_EXPIRY_MS, formatRelayDeadline, heldNotices, relayExpiry, type HeldNoticeInput } from './held-notice';

const NOW = Date.parse('2026-10-30T12:00:00.000Z');
const DAY = 24 * 60 * 60 * 1000;
const fmt = (ms: number) => new Date(ms).toISOString().slice(0, 10);
const one = (i: HeldNoticeInput) => heldNotices([i], NOW, fmt)[0];

test('N1 each reason has the exact v0.4 text and what-to-do line', () => {
  assert.deepEqual(one({ reason: 'missing_key', count: 3, kept: 'none' }), {
    reason: 'missing_key',
    text: "3 messages couldn't be opened on this device: they were sealed to a key this device doesn't have.",
    hint: 'Restoring your keys on this device may open them.',
  });
  assert.equal(one({ reason: 'different_encryption', count: 2, kept: 'none' }).text, "2 messages arrived in a format this app can't open yet.");
  assert.equal(one({ reason: 'different_encryption', count: 2, kept: 'none' }).hint, 'Updating the app may open them.');
  assert.equal(one({ reason: 'not_verified', count: 2, kept: 'none' }).text, "2 messages couldn't be verified, so they aren't shown.");
  assert.equal(one({ reason: 'not_verified', count: 2, kept: 'none' }).hint, 'If you expected a message, ask the sender to send it again.');
  assert.equal(one({ reason: 'unknown_sender', count: 4, kept: 'none', canAdmit: true }).text, '4 messages from people not in your Gate.');
  assert.equal(one({ reason: 'expired', count: 2, kept: 'none' }).text, "2 messages arrived after their time limit and weren't accepted.");
  assert.equal('hint' in one({ reason: 'expired', count: 2, kept: 'none' }), false, 'expired has no what-to-do line');
});

test('N2 unknown_sender shows "Admit the sender" only when the verified fingerprint was kept', () => {
  assert.equal(one({ reason: 'unknown_sender', count: 2, kept: 'none', canAdmit: true }).hint, 'Admit the sender to read them.');
  assert.equal('hint' in one({ reason: 'unknown_sender', count: 2, kept: 'none' }), false);
  assert.equal('hint' in one({ reason: 'unknown_sender', count: 2, kept: 'none', canAdmit: false }), false);
});

test('N3 kept-line: with a believable relay expires_at it names that date; without one it names none; local has its own line', () => {
  const exp = new Date(NOW + 4 * DAY).toISOString();
  assert.equal(one({ reason: 'missing_key', count: 2, kept: 'relay', expiresAt: exp }).kept, "They're kept on the relay until 2026-11-03, and this app will try again.");
  assert.equal(one({ reason: 'missing_key', count: 2, kept: 'relay' }).kept, "They're still on the relay, and this app will try again.");
  assert.equal(one({ reason: 'missing_key', count: 2, kept: 'dead-lettered' }).kept, "2 messages couldn't be kept on this device, only a note that they arrived.");
  assert.equal(one({ reason: 'missing_key', count: 1, kept: 'dead-lettered' }).kept, "1 message couldn't be kept on this device, only a note that it arrived.");
  assert.equal(one({ reason: 'missing_key', count: 1, kept: 'relay' }).kept, "It's still on the relay, and this app will try again.");
  assert.equal(one({ reason: 'missing_key', count: 1, kept: 'relay', expiresAt: exp }).kept, "It's kept on the relay until 2026-11-03, and this app will try again.");
  assert.equal('kept' in one({ reason: 'missing_key', count: 2, kept: 'none' }), false);
});

test('N4 a relay date is believed only when well-formed, in the future, and not absurd; otherwise the no-date line (never a computed date)', () => {
  const noDate = "It's still on the relay, and this app will try again.";
  const futureAsObject = { toString: () => new Date(NOW + 2 * DAY).toISOString() };
  for (const bad of [undefined, null, 42, {}, new Date(NOW + 2 * DAY), futureAsObject, '', 'tomorrow', 'not a date', new Date(NOW + DAY).toISOString().replace('T', ' ').replace('Z', ' garbage'),
    new Date(NOW).toISOString(), new Date(NOW - DAY).toISOString(), new Date(NOW + MAX_BELIEVABLE_EXPIRY_MS + 1).toISOString()]) {
    assert.equal(one({ reason: 'missing_key', count: 1, kept: 'relay', expiresAt: bad }).kept, noDate, JSON.stringify(bad));
  }
  assert.notEqual(one({ reason: 'missing_key', count: 1, kept: 'relay', expiresAt: new Date(NOW + MAX_BELIEVABLE_EXPIRY_MS).toISOString() }).kept, noDate, 'exactly at the ceiling is still believed');
  assert.equal(relayExpiry(new Date(NOW + 1).toISOString(), NOW), NOW + 1);
});

test('N5 a zero, negative, fractional or non-numeric count produces NO notice (that is what clears it); nothing is invented', () => {
  for (const count of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '3' as unknown as number]) {
    assert.deepEqual(heldNotices([{ reason: 'missing_key', count, kept: 'relay' }], NOW, fmt), [], String(count));
  }
});

test('N6 several reasons: one notice each, in the given order, each with its own kept-line', () => {
  const r = heldNotices([
    { reason: 'missing_key', count: 2, kept: 'relay' },
    { reason: 'unknown_sender', count: 1, kept: 'dead-lettered', canAdmit: true },
    { reason: 'expired', count: 0, kept: 'none' },
  ], NOW, fmt);
  assert.deepEqual(r.map((n) => n.reason), ['missing_key', 'unknown_sender']);
  assert.equal(r[1].kept, "1 message couldn't be kept on this device, only a note that it arrived.", 'count 1 -> singular dead-letter line');
  assert.equal(r[0].kept, "They're still on the relay, and this app will try again.", 'count 2 -> plural kept-line');
});

test('N7 NEVER-words: no notice text, hint or kept-line contains a forbidden word (copy doc: deleted/lost/corrupt/spam/forged/fake; v0.5 removed the old not-deleted line, so there is no exception)', () => {
  const all = heldNotices(
    (['missing_key', 'different_encryption', 'not_verified', 'unknown_sender', 'expired'] as const).flatMap((reason) =>
      (['relay', 'dead-lettered', 'none'] as const).map((kept) => ({ reason, count: 2, kept, canAdmit: true, expiresAt: new Date(NOW + DAY).toISOString() }))),
    NOW, fmt);
  for (const n of all) {
    const s = [n.text, n.hint ?? '', n.kept ?? ''].join(' ');
    assert.doesNotMatch(s, /\b(deleted|lost|corrupt|spam|forged|fake)\b/i, s);
    assert.doesNotMatch(s, /different encryption used/i);
    assert.doesNotMatch(s, /nothing was deleted/i);
  }
});

test('N8 v0.4 singular forms, exact: every reason at N = 1', () => {
  const want: Record<string, [string, string | undefined]> = {
    missing_key: ["1 message couldn't be opened on this device: it was sealed to a key this device doesn't have.", 'Restoring your keys on this device may open it.'],
    different_encryption: ["1 message arrived in a format this app can't open yet.", 'Updating the app may open it.'],
    not_verified: ["1 message couldn't be verified, so it isn't shown.", 'If you expected a message, ask the sender to send it again.'],
    unknown_sender: ['1 message from someone not in your Gate.', 'Admit the sender to read it.'],
    expired: ["1 message arrived after its time limit and wasn't accepted.", undefined],
  };
  for (const [reason, [text, hint]] of Object.entries(want)) {
    const n = one({ reason: reason as never, count: 1, kept: 'none', canAdmit: true });
    assert.equal(n.text, text, reason);
    assert.equal(n.hint, hint, reason);
  }
  // N = 2 never uses a singular word, and N = 1 never says "messages".
  assert.doesNotMatch(one({ reason: 'missing_key', count: 1, kept: 'none' }).text, /messages|they|them/i);
  assert.doesNotMatch(one({ reason: 'missing_key', count: 2, kept: 'none' }).text, /\b1 message\b|\bit was\b/);
});

test('N9 the deadline shows local date AND time, truncated to the minute and never rounded up (copy v0.4)', () => {
  const o = { locale: 'en-US', timeZone: 'UTC' };
  assert.equal(formatRelayDeadline(Date.parse('2026-11-03T02:10:00.000Z'), o), 'Nov 3, 2026, 2:10 AM');
  assert.equal(formatRelayDeadline(Date.parse('2026-11-03T02:10:59.999Z'), o), 'Nov 3, 2026, 2:10 AM', '59.999 s is truncated, not rounded to 2:11');
  assert.equal(formatRelayDeadline(Date.parse('2026-11-03T02:11:00.000Z'), o), 'Nov 3, 2026, 2:11 AM');
  assert.match(formatRelayDeadline(Date.parse('2026-11-03T14:05:30.000Z'), o), /2:05\sPM$/);
  assert.notEqual(formatRelayDeadline(Date.parse('2026-11-03T23:59:59.999Z'), o), formatRelayDeadline(Date.parse('2026-11-04T00:00:00.000Z'), o), 'truncation does not cross into the next minute/day');
});

test('N10 v0.5: the dead-letter line never claims the message was kept or saved (past the bound only a note survives)', () => {
  for (const count of [1, 2, 7]) {
    const kept = one({ reason: 'missing_key', count, kept: 'dead-lettered' }).kept as string;
    assert.match(kept, /only a note that (it|they) arrived\.$/);
    assert.doesNotMatch(kept, /saved|safe|still on|kept on the relay|not deleted|try again/i);
  }
  assert.equal(JSON.stringify(heldNotices([{ reason: 'missing_key', count: 3, kept: 'dead-lettered' }], NOW, fmt)).includes('saved on this device'), false);
});
