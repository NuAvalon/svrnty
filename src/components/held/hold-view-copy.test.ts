// Run: npx tsx --test src/components/held/hold-view-copy.test.ts
// The words on the hold view are the copy owner's, byte for byte (ledger rows 335a-335i4 and 316a): pinned by length and sha256 prefix, and by what the rows forbid and require.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as copy from './hold-view-copy';

const h = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 16);

// [row, template, length, sha256 prefix]: the ledger's own numbers (rows 335 and 316a), checked against the file before this was written.
const ROWS: Array<[string, string, number, string]> = [
  ['335a/335b1 title + entry', copy.HOLD_VIEW_TITLE, 13, '7ddea045e35a1c25'],
  ['335b2 intro', copy.HOLD_VIEW_INTRO, 100, '90f3a9deed15742a'],
  ['335c age line', copy.HOLD_VIEW_AGE_LINE, 102, '04860d0eb76f2b23'],
  ['316a cap line', copy.HOLD_VIEW_CAP_LINE, 165, '01723c8a6dc21b7a'],
  ['335d empty', copy.HOLD_VIEW_EMPTY, 17, '09361c24e2218949'],
  ['335e1 arrived', copy.HOLD_VIEW_ARRIVED, 25, '2c098c744d85944f'],
  ['335e2 sent by their clock', copy.HOLD_VIEW_SENT_BY_THEIR_CLOCK, 33, 'd6d581a4b235b997'],
  ['335f expiring', copy.HOLD_VIEW_EXPIRING, 38, 'f3711066f33a610d'],
  ['335g1 move one', copy.HOLD_VIEW_MOVE_ONE, 13, '6e4275ea7b1f7306'],
  ['335g2 move all', copy.HOLD_VIEW_MOVE_ALL, 17, 'dc183884d96864f7'],
  ['335g3 moved one', copy.HOLD_VIEW_MOVED_ONE, 44, 'de425f254a10f998'],
  ['335g4 moved all', copy.HOLD_VIEW_MOVED_ALL, 54, '0787b436e8f6a49d'],
  ['335h1 delete one', copy.HOLD_VIEW_DELETE_ONE, 6, 'e2d0a54968ead24e'],
  ['335h2 delete all', copy.HOLD_VIEW_DELETE_ALL, 10, '978111835dfadd7a'],
  ['335h3 confirm delete one', copy.HOLD_VIEW_CONFIRM_DELETE_ONE, 39, 'ef7e4cbc002e4bca'],
  ['335h4 confirm delete all', copy.HOLD_VIEW_CONFIRM_DELETE_ALL, 60, '79dc9cb06b3402ee'],
  ['335i1 failed delete one', copy.HOLD_VIEW_FAILED_DELETE_ONE, 40, '00120e5e45f32d86'],
  ['335i2 failed move one', copy.HOLD_VIEW_FAILED_MOVE_ONE, 38, '5ec60e7754f94249'],
  ['335i3 failed delete all', copy.HOLD_VIEW_FAILED_DELETE_ALL, 47, '4abc03eb8cde6dd3'],
  ['335i4 failed move all', copy.HOLD_VIEW_FAILED_MOVE_ALL, 45, 'b0302797d650f352'],
];

test('HVC1 every template is the copy owner\'s bytes (length + sha256 prefix) and plain ASCII with straight apostrophes', () => {
  assert.equal(ROWS.length, 20);
  for (const [name, text, len, sha] of ROWS) {
    assert.equal(text.length, len, `${name}: length`);
    assert.equal(h(text), sha, `${name}: sha256 prefix`);
    assert.ok(/^[\x20-\x7e]+$/.test(text), `${name}: ASCII`);
  }
});

test('HVC2 the entry label is exactly "Held messages" and carries no digit, no count, no placeholder: the view is the only place numbers appear', () => {
  assert.equal(copy.HOLD_VIEW_ENTRY, 'Held messages');
  assert.equal(copy.HOLD_VIEW_ENTRY, copy.HOLD_VIEW_TITLE);
  assert.doesNotMatch(copy.HOLD_VIEW_ENTRY, /\d|\{|\}|\(|\)/);
});

test('HVC3 fill() puts each value in once, never searches an inserted value again, and a hole or an unused value THROWS', () => {
  assert.equal(copy.fill('a {x} b {x}', { x: '{y}' }), 'a {y} b {y}', 'a value that looks like a placeholder stays as it is');
  assert.equal(copy.fill('a {x}', { x: '$& $1' }), 'a $& $1', 'no replacement-pattern surprises');
  assert.throws(() => copy.fill('a {x} {y}', { x: 1 }), /no value for \{y\}/);
  assert.throws(() => copy.fill('a {x}', { x: 1, z: 2 }), /\{z\} is not in this sentence/);
  assert.equal(copy.fill('no holes', {}), 'no holes');
});

test('HVC4 every filler leaves no brace behind and says the right thing for a named contact and for one with no name', () => {
  const named = copy.holdViewIntro('Robin');
  assert.equal(named, 'These arrived while you had Robin frozen. Opening, moving or deleting them sends nothing to Robin.');
  for (const none of [null, undefined, '', '   ']) assert.equal(copy.holdViewIntro(none), 'These arrived while you had this person frozen. Opening, moving or deleting them sends nothing to this person.');
  const all = [
    copy.holdViewIntro('A'), copy.holdViewAgeLine(30, 7) ?? '', copy.holdViewCapLine(500), copy.holdViewArrived('Mon 12:00'), copy.holdViewSentByTheirClock('Sun 09:00'), copy.holdViewExpiring('1 June'),
    copy.holdViewMovedOne('A'), copy.holdViewMovedAll(3, 'A'), copy.holdViewConfirmDeleteAll(3, 'A'), copy.holdViewFailedDeleteAll(2), copy.holdViewFailedMoveAll(2),
  ];
  for (const s of all) assert.doesNotMatch(s, /[{}]/, s);
  assert.equal(copy.holdViewAgeLine(30, 7), 'Notes held here longer than 30 days are marked expiring, then removed at least 7 days later.');
  assert.equal(copy.holdViewCapLine(500), "We keep up to 500 notes from each person you've frozen. After that, new notes from them aren't kept, and they stop getting delivery receipts, so they could notice.");
  assert.equal(copy.holdViewMovedAll(3, 'Robin'), 'Moved 3 notes to your inbox. Robin is still frozen.');
  assert.equal(copy.holdViewConfirmDeleteAll(12, null), "Delete all 12 held notes from this person? This can't be undone.");
});

test('HVC5 the age line is LEFT OUT when the limit is 0 (nothing is removed, so nothing is said), negative, or not a number', () => {
  for (const d of [0, -1, NaN, Infinity * 0]) assert.equal(copy.holdViewAgeLine(d, 7), null, String(d));
  assert.notEqual(copy.holdViewAgeLine(1, 7), null);
});

test('HVC6 a failure for ONE note says nothing was changed; a failure for ALL never does (a loop can stop part-way) and says how many are still here', () => {
  for (const one of [copy.HOLD_VIEW_FAILED_DELETE_ONE, copy.HOLD_VIEW_FAILED_MOVE_ONE]) assert.match(one, /Nothing was changed\.$/);
  for (const all of [copy.HOLD_VIEW_FAILED_DELETE_ALL, copy.HOLD_VIEW_FAILED_MOVE_ALL]) {
    assert.doesNotMatch(all, /nothing was changed/i);
    assert.match(all, /\{k\} are still here\.$/);
  }
  assert.equal(copy.holdViewFailedDeleteAll(0), "Some notes weren't deleted. 0 are still here.");
});

test('HVC7 the confirm offers Cancel and Delete, the age and cap lines are two separate sentences, and the sender\'s time is labelled as THEIRS', () => {
  assert.equal(copy.HOLD_VIEW_CONFIRM_CANCEL, 'Cancel');
  assert.equal(copy.HOLD_VIEW_CONFIRM_DELETE, 'Delete');
  assert.match(copy.HOLD_VIEW_SENT_BY_THEIR_CLOCK, /by their clock$/);
  assert.match(copy.HOLD_VIEW_EXPIRING, /^Expiring\. Can be removed after \{date\}\.$/, '"Can be removed after", never "will be removed on"');
});

test('HVC8 none of the forbidden phrases (row 335k) appears in any template or any filled sentence', () => {
  const forbidden = [/they won'?t know/i, /silently/i, /secretly/i, /safely stored/i, /forever/i, /\bprivate\b/i];
  const filled = [copy.holdViewIntro('Robin'), copy.holdViewAgeLine(30, 7) ?? '', copy.holdViewCapLine(500), copy.holdViewMovedAll(2, 'Robin'), copy.holdViewConfirmDeleteAll(2, 'Robin')];
  for (const [name, text] of ROWS) for (const f of forbidden) assert.doesNotMatch(text, f, `${name}: ${f}`);
  for (const s of filled) for (const f of forbidden) assert.doesNotMatch(s, f, s);
});
