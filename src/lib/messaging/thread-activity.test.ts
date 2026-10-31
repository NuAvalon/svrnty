import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { ACTIVITY_FUTURE_SLACK_MS, nextLastActivity } from './thread-activity';
import { sortFieldPeople, type FieldPerson } from '../../components/notes/notes-field';

const NOW = Date.parse('2026-10-31T14:30:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();

describe('thread last_activity_at (chat-list order)', () => {
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
      ['mneme', '2026-10-30T10:00:00Z'], ['ember', '2026-10-30T12:00:00Z'], ['ember', '2026-10-24T07:00:00Z'],
      ['mneme', '2026-10-25T08:00:00Z'], ['archie', '2026-10-29T09:00:00Z'],
    ];
    const last = new Map<string, string>();
    for (const [who, at] of arrivals) {
      const before = last.get(who);
      const after = nextLastActivity(before, at, NOW);
      if (before) assert.ok(Date.parse(after) >= Date.parse(before), `${who} moved down`);
      last.set(who, after);
    }
    assert.equal(last.get('ember'), '2026-10-30T12:00:00.000Z');
  });
});
