// Run: npx tsx --test src/components/relay/relay-holds-copy.test.ts
// The words on the "what the relay holds" panel are the copy owner's, byte for byte: pinned by length and sha256 prefix, and by what the wording forbids.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as copy from './relay-holds-copy';

const h = (s: string): string => createHash('sha256').update(s).digest('hex').slice(0, 16);

// [constant, template, length, sha256 prefix]: the copy owner's own numbers, checked against these strings before this was written.
const ROWS: Array<[string, string, number, string]> = [
  ['RELAY_OVER_ONE', copy.RELAY_OVER_ONE, 110, 'ed32c8c265cfcaf2'],
  ['RELAY_OVER_MANY', copy.RELAY_OVER_MANY, 112, '85a8418248e6304e'],
  ['RELAY_UNDER_ONE', copy.RELAY_UNDER_ONE, 100, '1b7c2b612e03712e'],
  ['RELAY_UNDER_MANY', copy.RELAY_UNDER_MANY, 103, '2790e43d50ae243e'],
  ['RELAY_REPAIR_WARNING', copy.RELAY_REPAIR_WARNING, 109, 'e9fa5106c2671af8'],
  ['RELAY_COULD_NOT_CHECK', copy.RELAY_COULD_NOT_CHECK, 92, '547bab26794cd244'],
  ['RELAY_NO_LIST', copy.RELAY_NO_LIST, 89, '2cff53eb21f7f84f'],
  ['RELAY_BOOK_DAMAGED', copy.RELAY_BOOK_DAMAGED, 117, '3ad5425a3d99d0f4'],
  ['RELAY_UNKNOWN_SENDER', copy.RELAY_UNKNOWN_SENDER, 28, '1723d169cc1ac731'],
  ['RELAY_REPAIR_BUTTON', copy.RELAY_REPAIR_BUTTON, 6, '1196b6c538ecc61a'],
  ['RELAY_REPAIRED', copy.RELAY_REPAIRED, 36, '58c18f827cc97a99'],
  ['RELAY_REPAIR_FAILED', copy.RELAY_REPAIR_FAILED, 94, 'dc5dd76d3e6c930e'],
  ['RELAY_REPAIR_GONE', copy.RELAY_REPAIR_GONE, 67, '32f9307b0aa83069'],
  ['RELAY_CHECKED_NOW', copy.RELAY_CHECKED_NOW, 17, '8291e345581b88d9'],
  ['RELAY_CHECKED_MINUTES', copy.RELAY_CHECKED_MINUTES, 20, '5a6f32a7a65bf53d'],
  ['RELAY_CHECKED_HOUR', copy.RELAY_CHECKED_HOUR, 25, '9948a8eb28db0b5d'],
  ['RELAY_NO_KEY_ONE', copy.RELAY_NO_KEY_ONE, 109, '510701924dfebdc2'],
  ['RELAY_NO_KEY_MANY', copy.RELAY_NO_KEY_MANY, 112, '87bacd95606ad33a'],
  ['RELAY_PANEL_TITLE', copy.RELAY_PANEL_TITLE, 20, '2308930139ab8186'],
  ['RELAY_REFRESH_BUTTON', copy.RELAY_REFRESH_BUTTON, 11, 'fb7099ad8e818d42'],
  ['RELAY_ALL_MATCH', copy.RELAY_ALL_MATCH, 55, '787255c26ff7013d'],
  ['RELAY_BY_DESIGN', copy.RELAY_BY_DESIGN, 101, '02a58139d08b6b74'],
];

test('RHC1 every template is the copy owner\'s bytes (length + sha256 prefix) and plain ASCII with straight apostrophes', () => {
  assert.equal(ROWS.length, 22);
  for (const [name, text, len, sha] of ROWS) {
    assert.equal(text.length, len, `${name}: length`);
    assert.equal(h(text), sha, `${name}: sha256 prefix`);
    assert.ok(/^[\x20-\x7e]+$/.test(text), `${name}: ASCII`);
  }
});

test('RHC2 the matching lines say nothing about notes, delivery or reaching the owner: the allowed list gates private matching, not delivery', () => {
  for (const t of [copy.RELAY_NO_KEY_ONE, copy.RELAY_NO_KEY_MANY, copy.RELAY_ALL_MATCH, copy.RELAY_BOOK_DAMAGED, copy.RELAY_OVER_ONE, copy.RELAY_OVER_MANY, copy.RELAY_UNDER_ONE, copy.RELAY_UNDER_MANY, copy.RELAY_REPAIR_WARNING, copy.RELAY_REPAIRED, copy.RELAY_REPAIR_FAILED, copy.RELAY_REPAIR_GONE]) {
    assert.doesNotMatch(t, /\bnotes?\b|messag|deliver|reach/i, t);
  }
  // the ONE line that names notes is the by-design line, and it says they cannot be counted per person
  assert.match(copy.RELAY_BY_DESIGN, /notes can't be counted per person/);
});

test('RHC3 the over and under lines pick the singular for exactly 1, the plural for the rest, and NOTHING for 0 (an empty diff shows no line)', () => {
  assert.equal(copy.overListedLine(0), null);
  assert.equal(copy.overListedLine(1), copy.RELAY_OVER_ONE);
  assert.equal(copy.overListedLine(2), "The relay still lists 2 people your contacts don't allow. They'll be taken off automatically at a later check.");
  assert.equal(copy.underListedLine(0), null);
  assert.equal(copy.underListedLine(1), copy.RELAY_UNDER_ONE);
  assert.equal(copy.underListedLine(7), "7 people your contacts allow aren't listed at the relay, so private matches with them can't complete.");
  for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    assert.throws(() => copy.overListedLine(bad), /count/);
    assert.throws(() => copy.underListedLine(bad), /count/);
  }
});

test('RHC4 the "checked" line: under a minute is "just now", 1..59 whole minutes say the minutes, an hour or more says so; a clock that went backwards reads "just now"; a non-number THROWS', () => {
  assert.equal(copy.checkedLine(0), 'Checked just now.');
  assert.equal(copy.checkedLine(59_999), 'Checked just now.');
  assert.equal(copy.checkedLine(60_000), 'Checked 1 min ago.');
  assert.equal(copy.checkedLine(60_000 * 59 + 59_999), 'Checked 59 min ago.');
  assert.equal(copy.checkedLine(60_000 * 60), 'Checked over an hour ago.');
  assert.equal(copy.checkedLine(60_000 * 60 * 30), 'Checked over an hour ago.');
  assert.equal(copy.checkedLine(-5_000), 'Checked just now.', 'a clock that moved back is not a negative age');
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, undefined as unknown as number]) assert.throws(() => copy.checkedLine(bad), /age/);
});

test('RHC5 the repair lines fill the contact\'s name, a nameless contact reads "this person" mid-sentence and "This person" at the start, and no brace is left behind', () => {
  assert.equal(copy.repairedLine('Robin'), 'Robin is listed at the relay again.');
  assert.equal(copy.repairFailedLine('Robin'), "The relay didn't confirm, so Robin still isn't listed. Nothing else changed. Try again later.");
  assert.equal(copy.repairGoneLine('Robin'), "Your contacts no longer allow Robin, so there's nothing to repair.");
  for (const none of [null, undefined, '', '   ']) {
    assert.equal(copy.repairedLine(none), 'This person is listed at the relay again.', 'at the start of the sentence');
    assert.equal(copy.repairFailedLine(none), "The relay didn't confirm, so this person still isn't listed. Nothing else changed. Try again later.", 'mid-sentence');
    assert.equal(copy.repairGoneLine(none), "Your contacts no longer allow this person, so there's nothing to repair.", 'mid-sentence');
  }
  for (const s of [copy.repairedLine('A'), copy.repairFailedLine('A'), copy.repairGoneLine('A'), copy.overListedLine(3) ?? '', copy.underListedLine(3) ?? '', copy.checkedLine(120_000)]) assert.doesNotMatch(s, /[{}]/, s);
});

test('RHC6 the unknown-sender label never carries a fingerprint, a digit or a placeholder: nothing about the listed value may reach the screen', () => {
  assert.equal(copy.RELAY_UNKNOWN_SENDER, 'Someone not in your contacts');
  assert.doesNotMatch(copy.RELAY_UNKNOWN_SENDER, /\d|\{|\}|[0-9a-f]{8}/i);
});

test('RHC7 there is no string for who-added-me: it is NEVER shown', () => {
  const names = Object.keys(copy).join(' ');
  assert.doesNotMatch(names, /inbound|added.?me|who.?added/i);
});

test('RHC8 a row label is the contact\'s name, or "This person" for a nameless one (the row starts its own line)', () => {
  assert.equal(copy.rowLabel('Robin'), 'Robin');
  assert.equal(copy.rowLabel('  Robin  '), 'Robin');
  for (const none of [null, undefined, '', '   ']) assert.equal(copy.rowLabel(none), 'This person');
});

test('RHC9 the entry label is exactly the panel title and carries no digit, no count and no placeholder: the numbers appear only after the owner opened the panel', () => {
  assert.equal(copy.RELAY_PANEL_TITLE, 'What the relay lists');
  assert.doesNotMatch(copy.RELAY_PANEL_TITLE, /\d|\{|\}|\(|\)/);
  assert.equal(copy.RELAY_ENTRY, copy.RELAY_PANEL_TITLE);
  assert.equal(copy.RELAY_REFRESH_BUTTON, 'Check again');
});

test('RHC10 the key-less line: nothing for 0, the singular for exactly 1, the plural for the rest, no brace left, and a bad count THROWS', () => {
  assert.equal(copy.noKeyLine(0), null);
  assert.equal(copy.noKeyLine(1), copy.RELAY_NO_KEY_ONE);
  assert.equal(copy.noKeyLine(3), "3 people your contacts allow have no key yet, so the relay can't list them. Nothing to fix here until they do.");
  assert.doesNotMatch(copy.noKeyLine(3) ?? '', /[{}]/);
  for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) assert.throws(() => copy.noKeyLine(bad), /count/);
});
