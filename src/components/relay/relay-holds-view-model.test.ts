// Run: npx tsx --test src/components/relay/relay-holds-view-model.test.ts
// WHAT THE PANEL SAYS, in order, for each state: the spec of the screen, pinned line by line. The component only renders these.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { viewLines } from './relay-holds-view-model';
import * as copy from './relay-holds-copy';
import type { PanelModel } from './relay-holds-model';

const ok = (o: Partial<{ overCount: number; under: Array<{ fp: string; label: string; name: string | null }>; noKeyCount: number }> = {}): PanelModel => ({ kind: 'ok', overCount: 0, under: [], noKeyCount: 0, ...o });
const ids = (m: PanelModel, at: number | undefined, now = 100_000): string[] => viewLines(m, at, now).lines.map((l) => l.id);

test('RHV1 the three states that carry no diff say ONE line each: could not check, the relay keeps no list, the book is damaged: no rows, no checked line, no by-design line', () => {
  for (const [kind, text] of [['unknown', copy.RELAY_COULD_NOT_CHECK], ['no-list', copy.RELAY_NO_LIST], ['book-damaged', copy.RELAY_BOOK_DAMAGED]] as const) {
    const v = viewLines({ kind } as PanelModel, 50_000, 100_000);
    assert.deepEqual(v.lines, [{ id: kind, text }], kind);
    assert.deepEqual(v.rows, [], `${kind}: no Repair rows`);
  }
});

test('RHV2 an ok read with NOTHING to report: the nothing-differs line sits immediately before "Checked ...", then the by-design line, in that order', () => {
  const v = viewLines(ok(), 100_000 - 3 * 60_000, 100_000);
  assert.deepEqual(v.lines.map((l) => l.id), ['allmatch', 'checked', 'bydesign']);
  assert.equal(v.lines[0].text, copy.RELAY_ALL_MATCH);
  assert.equal(v.lines[1].text, 'Checked 3 min ago.');
  assert.equal(v.lines[2].text, copy.RELAY_BY_DESIGN);
});

test('RHV3 over-listed, under-listed and key-less lines appear in that order; each is absent for 0; the nothing-differs line is absent as soon as any of the three is not 0', () => {
  const rows = [{ fp: 'a'.repeat(64), label: 'Robin', name: 'Robin' }];
  assert.deepEqual(ids(ok({ overCount: 2, under: rows, noKeyCount: 1 }), 1), ['over', 'under', 'nokey', 'checked', 'bydesign']);
  assert.deepEqual(ids(ok({ overCount: 1 }), 1), ['over', 'checked', 'bydesign']);
  assert.deepEqual(ids(ok({ under: rows }), 1), ['under', 'checked', 'bydesign']);
  assert.deepEqual(ids(ok({ noKeyCount: 2 }), 1), ['nokey', 'checked', 'bydesign'], 'the key-less line shows even when the diff is otherwise empty, and then "exactly" must NOT');
  assert.ok(!ids(ok({ noKeyCount: 2 }), 1).includes('allmatch'));
});

test('RHV4 the under-listed ROWS are exactly the model\'s, each with its label and the name for the repair lines; no fingerprint is in any line text', () => {
  const rows = [{ fp: 'a'.repeat(64), label: 'Robin', name: 'Robin' }, { fp: 'b'.repeat(64), label: 'This person', name: null }];
  const v = viewLines(ok({ under: rows }), 1, 2);
  assert.deepEqual(v.rows, rows);
  for (const l of v.lines) assert.doesNotMatch(l.text, /[0-9a-f]{40}/i, l.id);
});

test('RHV5 "Checked ..." comes only from a read time: with no time there is no checked line, and a future time (clock moved back) reads "just now"', () => {
  assert.ok(!ids(ok(), undefined).includes('checked'));
  assert.equal(viewLines(ok(), 200_000, 100_000).lines.find((l) => l.id === 'checked')?.text, 'Checked just now.');
});

test('RHV6 an ok read with no read time has NO nothing-differs line: that line is only ever shown beside the "Checked" line that dates it', () => {
  assert.ok(!ids(ok(), undefined).includes('allmatch'));
});

test('RHV7 the repair outcome lines: repaired / failed / gone use the contact\'s real name (a nameless one reads "this person" mid-sentence), unreadable is the could-not-check line, refused and busy say nothing', async () => {
  const { repairLine } = await import('./relay-holds-view-model');
  assert.equal(repairLine({ kind: 'repaired' }, 'Robin'), 'Robin is listed at the relay again.');
  assert.equal(repairLine({ kind: 'repaired' }, null), 'This person is listed at the relay again.');
  assert.equal(repairLine({ kind: 'failed' }, null), "The relay didn't confirm, so this person still isn't listed. Nothing else changed. Try again later.");
  assert.equal(repairLine({ kind: 'gone' }, 'Robin'), "Your contacts no longer allow Robin, so there's nothing to repair.");
  assert.equal(repairLine({ kind: 'unreadable' }, 'Robin'), copy.RELAY_COULD_NOT_CHECK);
  assert.equal(repairLine({ kind: 'refused' }, 'Robin'), null);
  assert.equal(repairLine({ kind: 'busy' }, 'Robin'), null);
});

test('RHV8 a book that is not whole at the press says nothing of its own: the panel the screen reloads shows the damaged-list line, and a second copy of it would be a duplicate', async () => {
  const { repairLine } = await import('./relay-holds-view-model');
  assert.equal(repairLine({ kind: 'damaged' }, 'Robin'), null);
  assert.equal(repairLine({ kind: 'unreadable' }, 'Robin'), copy.RELAY_COULD_NOT_CHECK, 'an unreadable flag is still the could-not-check line');
});
