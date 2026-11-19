// src/lib/messaging/held-age.test.ts: the hold's AGE LIMIT, as pure rules (held-note.ts: heldSweepAction, stampedHeldNote). The store side (the counted delete, the sweep, the unlock) is pinned in
// held-age-wiring.test.ts and run in a real browser by e2e/hold-age.spec.ts.
//
// The bar (Flint, task 946 seq 18): the age runs from the OWNER'S clock (held_at), never from sent_at or retention; the first sweep past the limit only STAMPS, and deletion needs the limit AND a grace
// after that stamp; a clock put back clears the stamp; unknown age (no held_at, or one that does not parse) is stamped and kept; a limit of 0 deletes nothing and stamps nothing as expiring.
//
// Run: npx tsx --test src/lib/messaging/held-age.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { HOLD_AGE_LIMIT_DAYS, HOLD_EXPIRY_GRACE_DAYS, heldStampsFor, heldSweepAction, stampedHeldNote } from './held-note';

const DAY = 86_400_000;
const NOW = Date.parse('2026-06-01T12:00:00.000Z');
const iso = (ms: number): string => new Date(ms).toISOString();
type Fixture = { held: true; note_id: string; sent_at: string; body: string; retention: { expires_at: string | null }; held_at?: string; expiry_seen_at?: string };
// `extra` may carry values the real row never would (a number, junk, an object): that is the point of several tests, so the fixture is cast, not checked.
const held = (extra: Record<string, unknown> = {}): Fixture => ({ held: true as const, note_id: 'n1', sent_at: '2026-05-01T00:00:00.000Z', body: 'evidence', retention: { expires_at: null }, ...extra }) as Fixture;
const LIMIT = HOLD_AGE_LIMIT_DAYS * DAY;
const GRACE = HOLD_EXPIRY_GRACE_DAYS * DAY;

test('HA1 the numbers are Peter\'s: 30 days, and a 7-day grace after the first sighting', () => {
  assert.equal(HOLD_AGE_LIMIT_DAYS, 30);
  assert.equal(HOLD_EXPIRY_GRACE_DAYS, 7);
});

test('HA2 the limit, AT and one millisecond either side: 29d stays, just under stays, exactly 30d and over only get the stamp, 31d the same, and a first sweep NEVER deletes', () => {
  const at = (ageMs: number) => heldSweepAction(held({ held_at: iso(NOW - ageMs) }), NOW);
  assert.equal(at(29 * DAY), 'keep');
  assert.equal(at(LIMIT - 1), 'keep');
  assert.equal(at(LIMIT), 'stamp-expiry', 'exactly the limit is past it');
  assert.equal(at(LIMIT + 1), 'stamp-expiry');
  assert.equal(at(31 * DAY), 'stamp-expiry');
  assert.equal(at(10 * 365 * DAY), 'stamp-expiry', 'however old, the FIRST sighting only stamps');
});

test('HA3 the grace, AT and one millisecond either side: deleted only when the limit AND a full grace after the stamp have passed', () => {
  const old = iso(NOW - 40 * DAY);
  const seen = (ago: number) => heldSweepAction(held({ held_at: old, expiry_seen_at: iso(NOW - ago) }), NOW);
  assert.equal(seen(0), 'keep');
  assert.equal(seen(GRACE - 1), 'keep');
  assert.equal(seen(GRACE), 'delete', 'exactly the grace is enough');
  assert.equal(seen(GRACE + 1), 'delete');
  assert.equal(seen(60 * DAY), 'delete');
});

test('HA4 unknown age is KEPT and the clock is started: no held_at, an empty one, one that does not parse, a number, are all stamped, never deleted (even with an old stamp)', () => {
  for (const bad of [undefined, '', 'not a date', '2026-13-45', 1700000000000, null, {}, []]) {
    const n = held(bad === undefined ? {} : { held_at: bad });
    assert.equal(heldSweepAction(n, NOW), 'stamp-held-at', JSON.stringify(bad));
    assert.equal(heldSweepAction({ ...n, expiry_seen_at: iso(NOW - 90 * DAY) }, NOW), 'stamp-held-at', `${JSON.stringify(bad)} with an old expiry stamp`);
  }
});

test('HA5 a clock that went BACK: a note no longer past the limit has its expiry stamp CLEARED; a held_at or a stamp in the FUTURE never deletes', () => {
  assert.equal(heldSweepAction(held({ held_at: iso(NOW - 29 * DAY), expiry_seen_at: iso(NOW - 8 * DAY) }), NOW), 'clear-expiry', 'put back to 29d: un-expire, delete nothing');
  assert.equal(heldSweepAction(held({ held_at: iso(NOW - (LIMIT - 1)), expiry_seen_at: iso(NOW - 8 * DAY) }), NOW), 'clear-expiry', 'one millisecond short of the limit');
  assert.equal(heldSweepAction(held({ held_at: iso(NOW + DAY) }), NOW), 'keep', 'a held_at in the future stays');
  assert.equal(heldSweepAction(held({ held_at: iso(NOW + DAY), expiry_seen_at: iso(NOW - 8 * DAY) }), NOW), 'clear-expiry', 'a future held_at is not past the limit, so a stamp is cleared');
  assert.equal(heldSweepAction(held({ held_at: iso(NOW - 40 * DAY), expiry_seen_at: iso(NOW + DAY) }), NOW), 'keep', 'a stamp in the future stays: nothing is deleted');
  assert.equal(heldSweepAction(held({ held_at: iso(NOW - 40 * DAY), expiry_seen_at: 'garbage' }), NOW), 'stamp-expiry', 'an unreadable stamp is made again, never trusted');
});

test('HA6 the clock jumps FORWARD and stays: nothing is deleted on the first sweep, the note is deleted only a full grace later (the +1 year, then +7 days sequence)', () => {
  const n0 = held({ held_at: iso(NOW - DAY) });   // a young note
  const jump = NOW + 365 * DAY;
  const a1 = heldSweepAction(n0, jump);
  assert.equal(a1, 'stamp-expiry', 'a wrong date a year ahead: stamp only');
  const n1 = stampedHeldNote(n0, a1, jump);
  assert.equal(heldSweepAction(n1, jump + GRACE - 1), 'keep', 'a day short of the grace');
  assert.equal(heldSweepAction(n1, jump + GRACE), 'delete', '7 days of the wrong date later: deleted');
  assert.equal(heldSweepAction(n1, NOW), 'clear-expiry', 'the clock is put right before the grace ends: the mark is cleared');
  assert.equal(heldSweepAction(stampedHeldNote(n1, 'clear-expiry', NOW), NOW), 'keep', 'and then it is just a young note again');
});

test('HA7 a limit of 0 (or negative, or not a number) is the OFF SWITCH: nothing deleted, NOTHING STAMPED AS EXPIRING, whatever the note', () => {
  const notes = [held(), held({ held_at: iso(NOW - 400 * DAY) }), held({ held_at: iso(NOW - 400 * DAY), expiry_seen_at: iso(NOW - 90 * DAY) }), held({ held_at: 'junk' })];
  for (const limit of [0, -1, NaN, -0.5]) for (const n of notes) assert.equal(heldSweepAction(n, NOW, limit), 'keep', `limit ${limit}`);
  assert.equal(heldSweepAction(notes[2], Number.NaN), 'keep', 'a clock that is not a number deletes nothing');
  assert.equal(heldSweepAction(notes[2], NOW, 30, 7), 'delete', 'control: the same note is deleted with the real limit');
});

test('HA8 nothing the SENDER controls matters: a backdated sent_at and an expired retention do not age a note; the age is held_at alone', () => {
  const n = held({ held_at: iso(NOW - DAY), sent_at: '2000-01-01T00:00:00.000Z', retention: { expires_at: '2000-01-02T00:00:00.000Z' } });
  assert.equal(heldSweepAction(n, NOW), 'keep');
  const old = held({ held_at: iso(NOW - 40 * DAY), sent_at: iso(NOW + 400 * DAY), retention: { expires_at: null } });
  assert.equal(heldSweepAction(old, NOW), 'stamp-expiry', 'and a forward-dated sent_at does not keep an old held_at young');
});

test('HA9 only a note that is held EXACTLY true is ever touched: an ordinary note (even one carrying look-alike stamps) and a look-alike held value are left alone', () => {
  const stamps = { held_at: iso(NOW - 400 * DAY), expiry_seen_at: iso(NOW - 90 * DAY) };
  const ordinary = { note_id: 'o', ...stamps };
  const asString = { held: 'true', ...stamps };
  const asNumber = { held: 1, ...stamps };
  const asFalse = { held: false, ...stamps };
  for (const n of [ordinary, asString, asNumber, asFalse]) assert.equal(heldSweepAction(n, NOW), 'keep', JSON.stringify(n));
});

test('HA10 stampedHeldNote: each stamping action changes exactly its own field, on a copy; keep and delete return the note as it is', () => {
  const n = held({ held_at: iso(NOW - 40 * DAY), expiry_seen_at: iso(NOW - 8 * DAY) });
  const before = JSON.stringify(n);
  const s1 = stampedHeldNote(held({ expiry_seen_at: iso(NOW - 9 * DAY) }), 'stamp-held-at', NOW);
  assert.equal(s1.held_at, iso(NOW));
  assert.equal('expiry_seen_at' in s1, false, 'a stamp made against an unknown age is forgotten');
  const s2 = stampedHeldNote(held({ held_at: iso(NOW - 40 * DAY) }), 'stamp-expiry', NOW);
  assert.equal(s2.expiry_seen_at, iso(NOW));
  assert.equal(s2.held_at, iso(NOW - 40 * DAY), 'the age clock is not restarted by the expiry stamp');
  const s3 = stampedHeldNote(n, 'clear-expiry', NOW);
  assert.equal('expiry_seen_at' in s3, false);
  assert.equal(s3.held_at, n.held_at);
  for (const a of ['keep', 'delete'] as const) assert.deepEqual(stampedHeldNote(n, a, NOW), n);
  assert.equal(JSON.stringify(n), before, 'the input is never changed');
  for (const x of [s1, s2, s3]) { assert.equal(x.body, 'evidence'); assert.equal(x.held, true); assert.equal(x.sent_at, '2026-05-01T00:00:00.000Z'); }
});

test('HA12 heldStampsFor: a NEW held note starts its clock on the owner\'s clock; a redelivery KEEPS the stamps it has; a prior with no usable held_at starts fresh (and forgets a stale expiry stamp)', () => {
  assert.deepEqual(heldStampsFor(undefined, NOW), { held_at: iso(NOW) });
  assert.deepEqual(heldStampsFor(null, NOW), { held_at: iso(NOW) });
  const prior = held({ held_at: iso(NOW - 20 * DAY), expiry_seen_at: iso(NOW - 3 * DAY) });
  assert.deepEqual(heldStampsFor(prior, NOW), { held_at: iso(NOW - 20 * DAY), expiry_seen_at: iso(NOW - 3 * DAY) }, 'a resend does not restart the age or the grace');
  assert.deepEqual(heldStampsFor(held({ held_at: iso(NOW - 20 * DAY) }), NOW), { held_at: iso(NOW - 20 * DAY) });
  for (const bad of [{}, { held_at: 'junk' }, { held_at: '' }, { held_at: 5 }, { held_at: 'junk', expiry_seen_at: iso(NOW - 9 * DAY) }]) assert.deepEqual(heldStampsFor(held(bad), NOW), { held_at: iso(NOW) }, JSON.stringify(bad));
  const notHeld = { note_id: 'o', held_at: iso(NOW - 20 * DAY) };
  assert.deepEqual(heldStampsFor(notHeld, NOW), { held_at: iso(NOW) }, 'a prior that is not held exactly true is not a held note: fresh clock');
  assert.deepEqual(heldStampsFor(held({ held_at: iso(NOW - 20 * DAY), expiry_seen_at: 7 }), NOW), { held_at: iso(NOW - 20 * DAY) }, 'a stamp that is not a string is not carried');
});

// ── the numbers are read in ONE place (Archie's ruling: one named constant each, never scattered) ─────────────────────────────────────────────────────────────────────────────────
const ROOT = process.cwd();
const walk = (dir: string): string[] =>
  readdirSync(join(ROOT, dir)).flatMap((name) => {
    const rel = `${dir}/${name}`;
    if (statSync(join(ROOT, rel)).isDirectory()) return walk(rel);
    return /\.(ts|tsx)$/.test(name) && !/\.test\./.test(name) ? [rel] : [];
  });
const code = (rel: string): string => readFileSync(join(ROOT, rel), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');

test('HA11 each number is named in held-note.ts only (its declaration and the one default that reads it), and by no other source file', () => {
  const sources = [...walk('src'), ...walk('app')];
  for (const name of ['HOLD_AGE_LIMIT_DAYS', 'HOLD_EXPIRY_GRACE_DAYS']) {
    const where: Record<string, number> = {};
    for (const f of sources) { const n = (code(f).match(new RegExp(`\\b${name}\\b`, 'g')) || []).length; if (n) where[f] = n; }
    assert.deepEqual(where, { 'src/lib/messaging/held-note.ts': 2 }, `${name}: the declaration and the one default parameter`);
  }
});
