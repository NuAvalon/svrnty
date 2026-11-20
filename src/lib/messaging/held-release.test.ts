// src/lib/messaging/held-release.test.ts: the pure rules the hold view stands on: what a RELEASE leaves behind (clearedHeldNote) and what the view may say about a note's age (heldExpiry), which must be the
// SAME fact the sweep acts on (heldSweepAction), not a second opinion.
//
// Run: npx tsx --test src/lib/messaging/held-release.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HOLD_AGE_LIMIT_DAYS, HOLD_EXPIRY_GRACE_DAYS, clearedHeldNote, heldAtMs, heldExpiry, heldSince, heldSweepAction, holdLimits, isHeldNote } from './held-note';

const DAY = 86_400_000;
const NOW = Date.parse('2026-06-01T12:00:00.000Z');
const iso = (ms: number): string => new Date(ms).toISOString();
const LIMIT = HOLD_AGE_LIMIT_DAYS * DAY;
const GRACE = HOLD_EXPIRY_GRACE_DAYS * DAY;
const held = (extra: Record<string, unknown> = {}) => ({ held: true as const, note_id: 'n1', thread_id: 'thr', direction: 'inbound', from_fingerprint: 'ab'.repeat(32), sent_at: '2026-05-01T00:00:00.000Z', body: 'evidence', retention: { expires_at: null }, ...extra });

test('RL1 a release clears held, held_at and expiry_seen_at TOGETHER and touches nothing else; the input is never changed', () => {
  const n = held({ held_at: iso(NOW - 40 * DAY), expiry_seen_at: iso(NOW - 8 * DAY) });
  const before = JSON.stringify(n);
  const out = clearedHeldNote(n) as Record<string, unknown>;
  for (const k of ['held', 'held_at', 'expiry_seen_at']) assert.equal(k in out, false, `no ${k} key left`);
  for (const k of ['note_id', 'thread_id', 'direction', 'from_fingerprint', 'sent_at', 'body', 'retention']) assert.deepEqual(out[k], (n as Record<string, unknown>)[k], k);
  assert.equal(Object.keys(out).length, Object.keys(n).length - 3);
  assert.equal(JSON.stringify(n), before, 'a copy: the input is untouched');
  assert.equal(isHeldNote(out), false, 'and it is an ordinary note');
});

test('RL2 a release of a note with only SOME of the keys (a legacy note, a note never stamped) still clears every one it has, and a note with none is returned equal', () => {
  assert.deepEqual(clearedHeldNote(held()), { note_id: 'n1', thread_id: 'thr', direction: 'inbound', from_fingerprint: 'ab'.repeat(32), sent_at: '2026-05-01T00:00:00.000Z', body: 'evidence', retention: { expires_at: null } });
  assert.equal('held_at' in clearedHeldNote(held({ held_at: 'junk' })), false, 'a junk stamp goes too');
  assert.equal('expiry_seen_at' in clearedHeldNote(held({ expiry_seen_at: 5 })), false);
  const ordinary = { note_id: 'o', body: 'x' };
  assert.deepEqual(clearedHeldNote(ordinary), ordinary);
});

test('RL3 heldExpiry says "expiring" only for a note the SWEEP has marked: held, a limit above 0, a held_at past the limit, a parseable mark; and the removal time is the mark plus the grace', () => {
  const marked = held({ held_at: iso(NOW - 40 * DAY), expiry_seen_at: iso(NOW - 2 * DAY) });
  assert.deepEqual(heldExpiry(marked, NOW), { expiring: true, removableAfterMs: NOW - 2 * DAY + GRACE });
  // each fact missing, one at a time
  assert.deepEqual(heldExpiry(held({ held_at: iso(NOW - 40 * DAY) }), NOW), { expiring: false }, 'past the limit but not marked yet: the view says nothing');
  assert.deepEqual(heldExpiry(held({ held_at: iso(NOW - 10 * DAY), expiry_seen_at: iso(NOW - 2 * DAY) }), NOW), { expiring: false }, 'a mark on a note that is no longer past the limit (clock put back) is not shown');
  assert.deepEqual(heldExpiry(held({ expiry_seen_at: iso(NOW - 2 * DAY) }), NOW), { expiring: false }, 'no held_at: unknown age');
  assert.deepEqual(heldExpiry(held({ held_at: 'junk', expiry_seen_at: iso(NOW - 2 * DAY) }), NOW), { expiring: false });
  assert.deepEqual(heldExpiry(held({ held_at: iso(NOW - 40 * DAY), expiry_seen_at: 'garbage' }), NOW), { expiring: false }, 'an unreadable mark');
  const notHeld = { ...marked, held: undefined };
  assert.deepEqual(heldExpiry(notHeld, NOW), { expiring: false }, 'not held');
  for (const limit of [0, -1, NaN]) assert.deepEqual(heldExpiry(marked, NOW, limit), { expiring: false }, `limit ${limit}: the off switch says nothing`);
  assert.deepEqual(heldExpiry(marked, Number.NaN), { expiring: false });
});

test('RL4 heldExpiry and the sweep cannot drift: the moment the view says a note can be removed is EXACTLY when the sweep first says delete (at and one millisecond either side), for a grid of ages and marks', () => {
  let checked = 0;
  for (const heldAgo of [LIMIT, LIMIT + 1, 31 * DAY, 90 * DAY]) {
    for (const seenAgo of [0, 1, DAY, GRACE - 1, GRACE, 40 * DAY]) {
      const n = held({ held_at: iso(NOW - heldAgo), expiry_seen_at: iso(NOW - seenAgo) });
      const e = heldExpiry(n, NOW);
      assert.equal(e.expiring, true, `held ${heldAgo} ago, marked ${seenAgo} ago`);
      if (!e.expiring) continue;
      const t = e.removableAfterMs;
      assert.notEqual(heldSweepAction(n, t - 1), 'delete', `one millisecond before the shown time: not deleted (held ${heldAgo}, marked ${seenAgo})`);
      assert.equal(heldSweepAction(n, t), 'delete', `at the shown time: deleted (held ${heldAgo}, marked ${seenAgo})`);
      assert.equal(heldSweepAction(n, t + 1), 'delete');
      checked++;
    }
  }
  assert.equal(checked, 24);
});

test('RL5 a note the view calls NOT expiring is never deleted by the sweep at the same moment (the view never hides a deletion)', () => {
  for (const heldAgo of [0, DAY, LIMIT - 1]) {
    for (const mark of [undefined, iso(NOW - 2 * DAY), 'garbage']) {
      const n = held({ held_at: iso(NOW - heldAgo), ...(mark === undefined ? {} : { expiry_seen_at: mark }) });
      assert.deepEqual(heldExpiry(n, NOW), { expiring: false });
      assert.notEqual(heldSweepAction(n, NOW), 'delete', `held ${heldAgo} ago, mark ${String(mark)}`);
    }
  }
  const unmarked = held({ held_at: iso(NOW - 90 * DAY) });
  assert.deepEqual(heldExpiry(unmarked, NOW), { expiring: false });
  assert.equal(heldSweepAction(unmarked, NOW), 'stamp-expiry', 'past the limit but unmarked: the sweep will MARK it first, never delete it');
});

test('RL6 holdLimits() is the one reader of the two constants: it returns exactly them, and the view takes the numbers it prints from it', () => {
  assert.deepEqual(holdLimits(), { limitDays: 30, graceDays: 7 });
  assert.equal(holdLimits().limitDays, HOLD_AGE_LIMIT_DAYS);
  assert.equal(holdLimits().graceDays, HOLD_EXPIRY_GRACE_DAYS);
});

test('RL7 heldAtMs reads held_at ONLY (when this device held it), never the sender\'s sent_at; heldSince sorts by held_at, then sent_at, then 0, so the list is newest-HELD first whatever the senders\' clocks say', () => {
  const a = held({ note_id: 'a', held_at: iso(NOW - 1 * DAY), sent_at: iso(NOW - 50 * DAY) });
  const b = held({ note_id: 'b', held_at: iso(NOW - 3 * DAY), sent_at: iso(NOW - 2 * DAY) });
  assert.equal(heldAtMs(a), NOW - 1 * DAY, 'held_at, not sent_at');
  assert.equal(heldAtMs(held({ sent_at: iso(NOW - 2 * DAY) })), null, 'no held_at: null, the sender\'s time is not borrowed');
  assert.equal(heldAtMs(held({ held_at: 'junk' })), null);
  assert.equal(heldSince(a), NOW - 1 * DAY);
  assert.equal(heldSince(held({ sent_at: iso(NOW - 2 * DAY) })), NOW - 2 * DAY, 'no held_at: the sender\'s time');
  assert.equal(heldSince(held({ sent_at: 'junk' })), 0, 'nothing usable: 0, sorts last');
  // a sent_at that disagrees with held_at must not decide the order: a is the NEWER held note though its sender claims it is the older one
  const order = [b, a].sort((x, y) => heldSince(y) - heldSince(x)).map((n) => n.note_id);
  assert.deepEqual(order, ['a', 'b']);
});
