// src/components/notes/cant-open-notice.test.ts
// #731: every string is Hypatia's copy (v0.1 6b627ef3 U/X/R, v0.2 c8f47555 S) by VALUE, plus the NEGs from the copy and Archie #188111/#188118.
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
    'not-in-book': 'S', 'ratchet-unopenable': 'R', 'ratchet-local': 'R', expired: 'X',
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

test('C4 R: one line per contact, named, with the resend ask; actionable lines come first', () => {
  const out = cantOpenNotices([row('expired'), row('ratchet-unopenable', { fp: ALICE }), row('ratchet-local', { fp: ALICE }), row('ratchet-unopenable', { fp: BOB })], nameFor, null);
  assert.deepEqual(out, [
    { group: 'R', text: "2 messages from Alice couldn't be opened on this device. Ask Alice to send them again.", fingerprint: ALICE },
    { group: 'R', text: "1 message from Bob couldn't be opened on this device. Ask Bob to send it again.", fingerprint: BOB },
    { group: 'X', text: "1 message arrived after its time limit and wasn't opened." },
  ]);
});

test('C5 NEG: a U or X row never shows a name or fingerprint, even if a row somehow carries one', () => {
  const out = cantOpenNotices([row('verify-failed', { fp: ALICE }), row('expired', { fp: BOB })], nameFor, null);
  for (const n of out) {
    assert.equal(n.fingerprint, undefined);
    assert.doesNotMatch(n.text, /Alice|Bob/);
    assert.doesNotMatch(n.text, /[0-9a-f]{8,}/i);
  }
});

test('C6 an R row whose sender left the book (no name) counts in U, never shows its fingerprint', () => {
  const out = cantOpenNotices([row('ratchet-unopenable', { fp: GONE }), row('ratchet-local')], nameFor, null);
  assert.deepEqual(out.map((n) => n.group), ['U']);
  assert.match(out[0].text, /^2 messages couldn't be opened/);
  assert.doesNotMatch(out[0].text, /[0-9a-f]{8,}/i);
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
    [row('decrypt-failed'), row('expired'), row('not-in-book'), row('ratchet-unopenable', { fp: ALICE })],
    nameFor,
    null,
  ).map((n) => n.text);
  assert.equal(all.length, 4);
  for (const t of all) assert.doesNotMatch(t, /decrypt|lost forever|deleted|blocked/i);
});
