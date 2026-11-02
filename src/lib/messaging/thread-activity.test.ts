import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ACTIVITY_FUTURE_SLACK_MS, nextLastActivity, needsLastActivityHeal, healedLastActivity, readLastActivity, activityMs } from './thread-activity';
import { sortFieldPeople, mergeFieldPeople, type FieldPerson } from '../../components/notes/notes-field';
import type { NoteThread } from './types';

const NOW = Date.parse('2026-10-31T14:30:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();

describe('thread last_activity_at (chat-list order)', () => {
  it('the slack is the 5 minutes R5 (session-adopt-policy FUTURE_SLACK_MS) allows', () => {
    assert.equal(ACTIVITY_FUTURE_SLACK_MS, 300_000);
  });
  it('a first note sets the activity to its sent time', () => {
    assert.equal(nextLastActivity(undefined, '2026-10-30T10:00:00.000Z', NOW), '2026-10-30T10:00:00.000Z');
  });
  it('a newer note advances the activity', () => {
    assert.equal(nextLastActivity('2026-10-29T00:00:00.000Z', '2026-10-30T10:00:00.000Z', NOW), '2026-10-30T10:00:00.000Z');
  });
  it('NEG: an older backlog note never moves a contact down', () => {
    assert.equal(nextLastActivity('2026-10-30T12:00:00.000Z', '2026-10-24T07:00:00.000Z', NOW), '2026-10-30T12:00:00.000Z');
  });
  it('a note within the slack still counts', () => {
    const at = iso(NOW + ACTIVITY_FUTURE_SLACK_MS - 1000);
    assert.equal(nextLastActivity('2026-10-30T12:00:00.000Z', at, NOW), at);
  });
  it('NEG: a 2099 note is stored clamped, never raw', () => {
    assert.equal(nextLastActivity('2026-10-30T12:00:00.000Z', '2099-01-01T00:00:00.000Z', NOW), iso(NOW + ACTIVITY_FUTURE_SLACK_MS));
  });
  it('NEG: a 2099 note does not sit above a genuine newer note once real time passes it', () => {
    const stored = nextLastActivity('2026-10-30T12:00:00.000Z', '2099-01-01T00:00:00.000Z', NOW);
    const later = NOW + 20 * 60_000;
    const genuine = iso(later - 1000);
    // other contact's genuine note, processed later, outranks the clamped 2099 one in the list
    const people: FieldPerson[] = [
      { fingerprint: 'liar', name: 'liar', threadId: 'a', preview: '', lastAt: nextLastActivity(stored, '2026-10-30T12:00:00.000Z', later), sendable: true },
      { fingerprint: 'honest', name: 'honest', threadId: 'b', preview: '', lastAt: nextLastActivity(undefined, genuine, later), sendable: true },
    ];
    assert.deepEqual(sortFieldPeople(people).map((p) => p.name), ['honest', 'liar']);
  });
  it('a legacy stored value already in the far future heals instead of sticking', () => {
    assert.equal(nextLastActivity('2099-01-01T00:00:00.000Z', '2026-10-30T10:00:00.000Z', NOW), iso(NOW + ACTIVITY_FUTURE_SLACK_MS));
  });
  it('an unparsable sent time counts as now, an unparsable stored value is ignored', () => {
    assert.equal(nextLastActivity('garbage', 'not-a-date', NOW), iso(NOW));
  });
  it('draining an out-of-order backlog never moves a contact down', () => {
    const arrivals: [string, string][] = [
      ['contact-a', '2026-10-30T10:00:00Z'], ['contact-b', '2026-10-30T12:00:00Z'], ['contact-b', '2026-10-24T07:00:00Z'],
      ['contact-a', '2026-10-25T08:00:00Z'], ['contact-c', '2026-10-29T09:00:00Z'],
    ];
    const last = new Map<string, string>();
    for (const [who, at] of arrivals) {
      const before = last.get(who);
      const after = nextLastActivity(before, at, NOW);
      if (before) assert.ok(Date.parse(after) >= Date.parse(before), `${who} moved down`);
      last.set(who, after);
    }
    assert.equal(last.get('contact-b'), '2026-10-30T12:00:00.000Z');
  });
});

// ── A thread already pinned in the future: heal it once, lower, to where its real messages put it ─────────────────────────────────────────
const PIN = '2099-01-01T00:00:00.000Z';
const CEIL = iso(NOW + ACTIVITY_FUTURE_SLACK_MS);

describe('healedLastActivity (a thread pinned by the older overwrite rule)', () => {
  it('lands at the newest PLAUSIBLE message time, not at the ceiling and not at the pin', () => {
    assert.equal(healedLastActivity(PIN, ['2026-10-29T10:00:00.000Z', '2026-10-30T12:00:00.000Z', PIN], NOW), '2026-10-30T12:00:00.000Z');
  });
  it('notes at hand but none plausible (the pinning note is the only one): now, never the sender\'s date and never the thread created_at', () => {
    assert.equal(healedLastActivity(PIN, [PIN], NOW), iso(NOW));
    assert.equal(healedLastActivity(PIN, [], NOW), iso(NOW));
  });
  it('notes not available: now + slack, the ceiling every other path clamps to', () => {
    assert.equal(healedLastActivity(PIN, null, NOW), CEIL);
  });
  it('NEG: a value at or below the ceiling is never rewritten (at the ceiling exactly, now, the past)', () => {
    for (const stored of [CEIL, iso(NOW), '2026-10-01T00:00:00.000Z']) {
      assert.equal(healedLastActivity(stored, ['2026-10-30T12:00:00.000Z'], NOW), null, stored);
      assert.equal(needsLastActivityHeal(stored, NOW), false, stored);
    }
    assert.equal(needsLastActivityHeal(iso(NOW + ACTIVITY_FUTURE_SLACK_MS + 1), NOW), true, 'one ms past the ceiling is a pin');
  });
  it('NEG: an unreadable stored value is not healed and does not throw', () => {
    for (const stored of ['', 'not a date', 'undefined']) assert.equal(healedLastActivity(stored, null, NOW), null);
  });
  it('it only ever LOWERS: whatever the notes say, the result is below the stored value', () => {
    const combos: Array<readonly string[] | null> = [null, [], [PIN], ['2027-01-01T00:00:00.000Z'], ['2026-10-30T12:00:00.000Z', PIN], ['garbage']];
    for (const stored of [PIN, '2026-11-02T00:00:00.000Z', iso(NOW + ACTIVITY_FUTURE_SLACK_MS + 1)]) {
      for (const notes of combos) {
        const out = healedLastActivity(stored, notes, NOW);
        assert.ok(out !== null && Date.parse(out) < Date.parse(stored), `${stored} / ${JSON.stringify(notes)} -> ${out}`);
      }
    }
  });
  it('two loads do not keep moving it: the healed value is not healed again, even much later', () => {
    const first = healedLastActivity(PIN, null, NOW)!;
    assert.equal(healedLastActivity(first, null, NOW), null);
    assert.equal(healedLastActivity(first, null, NOW + 3_600_000), null);
  });
  it('the pin dissolves by itself: 6 minutes after the heal, a note in another thread sorts ABOVE the healed one', () => {
    const healed = healedLastActivity(PIN, null, NOW)!;
    const later = NOW + 6 * 60_000;
    const other = nextLastActivity('2026-10-30T09:00:00.000Z', iso(later), later);
    const thread = (id: string, fp: string, at: string): NoteThread => ({
      thread_id: id, kind: 'direct', participants: [{ fingerprint: fp, kind: 'human', display_name: id }], created_at: at, last_activity_at: at, retention: { expires_at: null },
    });
    const people = mergeFieldPeople({ ownerFp: 'me', threads: [thread('pinned', 'fp-p', healed), thread('other', 'fp-o', other)], names: [], sendable: new Set(['fp-p', 'fp-o']), previews: {}, nowMs: later });
    assert.deepEqual(sortFieldPeople(people).map((p) => p.threadId), ['other', 'pinned']);
  });
});

describe('readLastActivity / mergeFieldPeople (the backstop when a heal could not be written)', () => {
  it('a stored value past now + slack is shown as now + slack; one at or below is returned as the SAME string', () => {
    assert.equal(readLastActivity(PIN, NOW), CEIL);
    assert.equal(readLastActivity('2026-10-30T12:00:00Z', NOW), '2026-10-30T12:00:00Z');
    assert.equal(readLastActivity(CEIL, NOW), CEIL);
  });
  it('an unreadable value sorts last', () => {
    assert.equal(readLastActivity('garbage', NOW), '1970-01-01T00:00:00.000Z');
  });
  it('the people list never carries a far-future lastAt, and the stored thread is not changed', () => {
    const thread: NoteThread = { thread_id: 't', kind: 'direct', participants: [{ fingerprint: 'fp-x', kind: 'human', display_name: 'X' }], created_at: PIN, last_activity_at: PIN, retention: { expires_at: null } };
    const people = mergeFieldPeople({ ownerFp: 'me', threads: [thread], names: [], sendable: new Set(['fp-x']), previews: {}, nowMs: NOW });
    assert.equal(people[0].lastAt, CEIL);
    assert.equal(thread.last_activity_at, PIN, 'reading never rewrites the stored value');
  });
});

describe('sorting compares times, not text (an older build can have stored an offset or no milliseconds)', () => {
  // As text '2026-10-30T12:00:00+05:00' sorts AFTER '2026-10-30T09:00:00.000Z', but it is 07:00Z, so it is the OLDER one.
  const OFFSET = '2026-10-30T12:00:00+05:00';
  const ZULU = '2026-10-30T09:00:00.000Z';
  it('activityMs orders them by the instant, and an unreadable value is 0', () => {
    assert.ok(activityMs(ZULU, NOW) > activityMs(OFFSET, NOW));
    assert.equal(activityMs('garbage', NOW), 0);
    assert.equal(activityMs(PIN, NOW), NOW + ACTIVITY_FUTURE_SLACK_MS, 'a far-future value is bounded');
  });
  it('sortFieldPeople (the order the user sees) puts the later instant first whatever the text looks like', () => {
    const p = (id: string, at: string): FieldPerson => ({ fingerprint: id, name: id, threadId: id, preview: '', lastAt: at, sendable: true });
    assert.deepEqual(sortFieldPeople([p('offset', OFFSET), p('zulu', ZULU)]).map((x) => x.threadId), ['zulu', 'offset']);
    assert.deepEqual(sortFieldPeople([p('zulu', ZULU), p('offset', OFFSET)]).map((x) => x.threadId), ['zulu', 'offset']);
    assert.deepEqual(sortFieldPeople([p('nomillis', '2026-10-30T09:00:01Z'), p('zulu', ZULU)]).map((x) => x.threadId), ['nomillis', 'zulu'], 'one second later, no milliseconds');
  });
});
