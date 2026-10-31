// src/components/notes/cant-open-notice.test.ts
// #731: every string is Hypatia's COPY OF RECORD v1 (70c7888d) by VALUE, plus its NEGs 1-8 (Archie #188111/#188118, Flint #2594).
// Run: npx tsx --test src/components/notes/cant-open-notice.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DEAD_LETTER_REASONS, type DeadLetterReason, type DeadLetterRow } from '@/lib/sync/dead-letter';
import { CANT_OPEN_S, cantOpenNotices, groupFor } from './cant-open-notice';

const ALICE = 'a1'.repeat(32);
const BOB = 'b2'.repeat(32);
const GONE = 'c3'.repeat(32);
const NAMES: Record<string, string> = { [ALICE]: 'Alice', [BOB]: 'Bob' };
const nameFor = (fp: string) => NAMES[fp] ?? null;
let seq = 0;
const row = (reason: DeadLetterReason, extra: Partial<DeadLetterRow> = {}): DeadLetterRow => ({
  envelope_id: `e${seq++}`,
  first_seen: '2026-10-31T14:47:00.000Z',
  reason,
  blob_kind: 'hybrid-package',
  ...extra,
});
const texts = (rows: DeadLetterRow[], dismissed: string | null = null) => cantOpenNotices(rows, nameFor, dismissed).map((n) => n.text);

test('C1 no rows, or only non-message rows, → no notice at all', () => {
  assert.deepEqual(cantOpenNotices([], nameFor, null), []);
  assert.deepEqual(cantOpenNotices([row('unverified-frame'), row('unverified-frame', { fp: ALICE })], nameFor, null), []);
});

test('C2 every reason maps to exactly one group; unverified-frame to none', () => {
  const want: Record<DeadLetterReason, string | null> = {
    'unknown-format': 'U', 'decrypt-failed': 'U', 'missing-key': 'U', 'verify-failed': 'U', 'unverified-frame': null,
    'not-in-book': 'S', 'ratchet-unopenable': 'R', 'ratchet-local': 'R', 'ratchet-desync': 'R', 'session-reset': 'R', expired: 'X',
  };
  for (const r of DEAD_LETTER_REASONS) assert.equal(groupFor(r), want[r], r);
});

test('C3 U and X: exact copy, singular and plural, count only', () => {
  assert.deepEqual(texts([row('decrypt-failed'), row('missing-key'), row('verify-failed')]), [
    "3 messages couldn't be opened on this device, so svrnty can't tell who sent them. This device didn't keep them.",
  ]);
  assert.deepEqual(texts([row('unknown-format')]), ["1 message couldn't be opened on this device, so svrnty can't tell who sent it. This device didn't keep it."]);
  assert.deepEqual(texts([row('expired'), row('expired')]), ["2 messages arrived after their time limit and weren't opened."]);
  assert.deepEqual(texts([row('expired')]), ["1 message arrived after its time limit and wasn't opened."]);
});

test('C4 R: one line per (contact, reason), named, the second sentence by reason; actionable lines come first', () => {
  const out = cantOpenNotices([row('expired'), row('ratchet-unopenable', { fp: ALICE }), row('ratchet-unopenable', { fp: ALICE }), row('ratchet-local', { fp: ALICE }), row('ratchet-unopenable', { fp: BOB })], nameFor, null);
  assert.deepEqual(out, [
    { group: 'R', text: "2 messages from Alice couldn't be opened on this device. Ask Alice to send them again.", fingerprint: ALICE },
    { group: 'R', text: "1 message from Alice couldn't be opened on this device. Restoring your keys on this device may help with new messages.", fingerprint: ALICE },
    { group: 'R', text: "1 message from Bob couldn't be opened on this device. Ask Bob to send it again.", fingerprint: BOB },
    { group: 'X', text: "1 message arrived after its time limit and wasn't opened." },
  ]);
});

test('C4c NEG 2: ratchet-local never asks for a resend (both forms)', () => {
  for (const n of [1, 3]) {
    const rows = Array.from({ length: n }, () => row('ratchet-local', { fp: ALICE }));
    const [only] = cantOpenNotices(rows, nameFor, null);
    assert.doesNotMatch(only.text, /send .* again/);
    assert.match(only.text, /Restoring your keys on this device may help with new messages\.$/);
  }
});

test('C4d post-#318 reasons: desync follows resetOffered (an agent contact never sees "reset"); session-reset has its own line', () => {
  const human = cantOpenNotices([row('ratchet-desync', { fp: ALICE }), row('ratchet-desync', { fp: ALICE })], nameFor, null, () => false);
  assert.deepEqual(human.map((n) => n.text), ["2 messages from Alice couldn't be opened on this device. If messages from Alice keep failing, reset your message session with them, then ask them to send them again."]);
  const one = cantOpenNotices([row('ratchet-desync', { fp: ALICE })], nameFor, null, () => false);
  assert.match(one[0].text, /then ask them to send it again\.$/);
  const agent = cantOpenNotices([row('ratchet-desync', { fp: ALICE })], nameFor, null, (f) => f === ALICE);
  assert.deepEqual(agent.map((n) => n.text), ["1 message from Alice couldn't be opened on this device. Resetting the message session isn't available for this contact yet."]);
  assert.doesNotMatch(agent[0].text, /reset your message session/);
  const reset = cantOpenNotices([row('session-reset', { fp: BOB })], nameFor, null);
  assert.deepEqual(reset.map((n) => n.text), ["1 message from Bob couldn't be opened because your message session with them was restarted. Ask Bob to send it again."]);
});

test('C4e Rule 0 / NEG 1: a HELD row of ANY reason renders no line; a recorded one does', () => {
  for (const r of DEAD_LETTER_REASONS) {
    assert.deepEqual(cantOpenNotices([row(r, { fp: ALICE, phase: 'held' })], nameFor, null), [], r);
  }
  assert.equal(cantOpenNotices([row('ratchet-desync', { fp: ALICE, phase: 'recorded' })], nameFor, null).length, 1);
  assert.equal(cantOpenNotices([row('ratchet-desync', { fp: ALICE })], nameFor, null).length, 1, 'no phase reads as recorded');
});

test('C4f order pinned: R, L, U, X, S', () => {
  const out = cantOpenNotices([row('not-in-book'), row('expired'), row('verify-failed'), row('ratchet-local', { fp: GONE }), row('ratchet-unopenable', { fp: BOB })], nameFor, null);
  assert.deepEqual(out.map((n) => n.group), ['R', 'L', 'U', 'X', 'S']);
});

test('C4b the same contact in upper and lower case is ONE line, keyed by the normalized fingerprint', () => {
  const out = cantOpenNotices([row('ratchet-unopenable', { fp: ALICE }), row('ratchet-unopenable', { fp: ALICE.toUpperCase() })], nameFor, null);
  assert.deepEqual(out, [{ group: 'R', text: "2 messages from Alice couldn't be opened on this device. Ask Alice to send them again.", fingerprint: ALICE }]);
});

test('C5 NEG: a U or X row never shows a name or fingerprint, even if a row somehow carries one', () => {
  const out = cantOpenNotices([row('verify-failed', { fp: ALICE }), row('expired', { fp: BOB })], nameFor, null);
  for (const n of out) {
    assert.equal(n.fingerprint, undefined);
    assert.doesNotMatch(n.text, /Alice|Bob/);
    assert.doesNotMatch(n.text, /[0-9a-f]{8,}/i);
  }
});

test('C6 L = authenticated, fp present, NOT in the book now; an authenticated-reason row with NO fp is U (Flint #2594)', () => {
  const out = cantOpenNotices([row('ratchet-unopenable', { fp: GONE }), row('session-reset', { fp: GONE }), row('ratchet-local'), row('decrypt-failed')], nameFor, null);
  assert.deepEqual(out, [
    { group: 'L', text: "2 messages from people no longer in your contacts couldn't be opened on this device. This device didn't keep them." },
    { group: 'U', text: "2 messages couldn't be opened on this device, so svrnty can't tell who sent them. This device didn't keep them." },
  ]);
  assert.deepEqual(cantOpenNotices([row('ratchet-local', { fp: GONE })], nameFor, null), [
    { group: 'L', text: "1 message from someone no longer in your contacts couldn't be opened on this device. This device didn't keep it." },
  ]);
  for (const n of out) assert.doesNotMatch(n.text, /[0-9a-f]{8,}/i);
});

test('C7 S: ONE presence line, exact copy, no digit, no hex run, no name, whatever the count', () => {
  for (const n of [1, 2, 37]) {
    const rows = Array.from({ length: n }, (_, i) => row('not-in-book', { fp: i % 2 ? ALICE : GONE }));
    const out = cantOpenNotices(rows, nameFor, null);
    assert.deepEqual(out, [{ group: 'S', text: CANT_OPEN_S }]);
    assert.doesNotMatch(out[0].text, /\d/);
    assert.doesNotMatch(out[0].text, /[0-9a-f]{8,}/i);
    assert.doesNotMatch(out[0].text, /Alice/);
  }
  assert.equal(CANT_OPEN_S, "People who aren't in your contacts tried to message you. svrnty doesn't open those.");
});

test('C8 S after a dismissal: hidden until a row first seen LATER exists, then the SAME line (never "more")', () => {
  const old = row('not-in-book', { first_seen: '2026-10-31T14:00:00.000Z' });
  const dismissed = '2026-10-31T14:30:00.000Z';
  assert.deepEqual(texts([old], dismissed), []);
  const fresh = row('not-in-book', { first_seen: '2026-10-31T15:00:00.000Z' });
  assert.deepEqual(texts([old, fresh], dismissed), [CANT_OPEN_S]);
  assert.deepEqual(texts([old, fresh, row('not-in-book', { first_seen: '2026-10-31T15:05:00.000Z' })], dismissed), [CANT_OPEN_S]);
  assert.deepEqual(texts([old], 'not-a-time'), [CANT_OPEN_S], 'an unreadable dismissal hides nothing');
  assert.deepEqual(texts([row('not-in-book', { first_seen: 'garbage' })], dismissed), [CANT_OPEN_S], 'an unreadable row time counts as new');
});

test('C9 NEG copy: no "decrypt", no "lost forever", "deleted" or "blocked" in any line', () => {
  const all = cantOpenNotices(
    [row('decrypt-failed'), row('expired'), row('not-in-book'), row('ratchet-unopenable', { fp: ALICE }), row('ratchet-local', { fp: GONE }),
      row('ratchet-local', { fp: BOB }), row('ratchet-desync', { fp: BOB }), row('session-reset', { fp: ALICE })],
    nameFor,
    null,
  ).map((n) => n.text);
  assert.equal(all.length, 8);
  for (const t of all) assert.doesNotMatch(t, /decrypt|lost forever|deleted|blocked/i);
});
