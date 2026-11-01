import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { NoteThread } from '../../lib/messaging/types';
import {
  filterFieldPeople,
  formatNoteClock,
  formatNoteDay,
  formatNoteListWhen,
  mergeFieldPeople,
  previewLine,
  sortFieldPeople,
  threadPeerFp,
} from './notes-field';

function thread(peer: string, id: string, name = 'Ada'): NoteThread {
  return {
    thread_id: id,
    kind: 'direct',
    participants: [
      { fingerprint: 'owner', kind: 'human', display_name: 'Me' },
      { fingerprint: peer, kind: 'human', display_name: name },
    ],
    created_at: '2026-01-01T00:00:00.000Z',
    last_activity_at: '2026-01-02T00:00:00.000Z',
    retention: { expires_at: null },
  };
}

describe('thread field people', () => {
  it('lists direct threads first, then unused sendable contacts', () => {
    const people = mergeFieldPeople({
      ownerFp: 'owner',
      threads: [thread('aaa', 't1')],
      names: [
        { fingerprint: 'aaa', name: 'Ada' },
        { fingerprint: 'bbb', name: 'Bob' },
      ],
      sendable: new Set(['aaa', 'bbb']),
      previews: { t1: 'hello from the field' },
    });
    assert.equal(people.length, 2);
    assert.equal(people[0].fingerprint, 'aaa');
    assert.equal(people[0].threadId, 't1');
    assert.equal(people[0].preview, 'hello from the field');
    assert.equal(people[1].fingerprint, 'bbb');
    assert.equal(people[1].threadId, null);
  });

  it('keeps a galaxy-focused peer even when they are not sendable', () => {
    const people = mergeFieldPeople({
      ownerFp: 'owner',
      threads: [],
      names: [{ fingerprint: 'ccc', name: 'Nikola Tesla' }],
      sendable: new Set(),
      previews: {},
      extraFp: 'ccc',
    });
    assert.equal(people.length, 1);
    assert.equal(people[0].name, 'Nikola Tesla');
    assert.equal(people[0].sendable, false);
  });

  it('uses the star-sheet name when the book has no key-bound fingerprint', () => {
    const people = mergeFieldPeople({
      ownerFp: 'owner',
      threads: [],
      names: [],
      sendable: new Set(),
      previews: {},
      extraFp: '7e51a00000000000000000000000000000000008',
      extraName: 'Nikola Tesla',
    });
    assert.equal(people[0].name, 'Nikola Tesla');
  });

  it('does not invent unread counts or presence in the preview', () => {
    assert.equal(previewLine('  a sealed note  '), 'a sealed note');
    assert.doesNotMatch(previewLine('a sealed note'), /\b\d+\b/);
  });

  it('resolves the peer fingerprint on a direct thread', () => {
    assert.equal(threadPeerFp(thread('peer-1', 't'), 'owner'), 'peer-1');
  });

  it('sorts conversations by last note, then unused people by name', () => {
    const older = thread('aaa', 't1', 'Ada');
    older.last_activity_at = '2026-01-01T00:00:00.000Z';
    const newer = thread('ccc', 't2', 'Cara');
    newer.last_activity_at = '2026-02-01T00:00:00.000Z';
    const people = mergeFieldPeople({
      ownerFp: 'owner',
      threads: [older, newer],
      names: [
        { fingerprint: 'aaa', name: 'Ada' },
        { fingerprint: 'bbb', name: 'Bob' },
        { fingerprint: 'ccc', name: 'Cara' },
      ],
      sendable: new Set(['aaa', 'bbb', 'ccc']),
      previews: {},
    });
    const sorted = sortFieldPeople(people);
    assert.deepEqual(sorted.map((p) => p.name), ['Cara', 'Ada', 'Bob']);
  });

  it('search matches recipient name, not a message dump', () => {
    const people = mergeFieldPeople({
      ownerFp: 'owner',
      threads: [thread('aaa', 't1'), thread('bbb', 't2', 'Bob')],
      names: [
        { fingerprint: 'aaa', name: 'Ada' },
        { fingerprint: 'bbb', name: 'Bob' },
      ],
      sendable: new Set(['aaa', 'bbb']),
      previews: { t1: 'hello', t2: 'later' },
    });
    const hit = filterFieldPeople(people, '  ada  ');
    assert.equal(hit.length, 1);
    assert.equal(hit[0].name, 'Ada');
    assert.equal(filterFieldPeople(people, 'zzz').length, 0);
  });
});

describe('formatNoteListWhen — contact-list buckets', () => {
  const yesterdayWord = () =>
    new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' }).format(-1, 'day');

  function localIso(now: Date, daysAgo: number, hour = 15, minute = 12): string {
    const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - daysAgo, hour, minute, 0);
    return d.toISOString();
  }

  it('same local day renders as a clock (formatNoteClock)', () => {
    const now = new Date(2026, 9, 31, 15, 12, 0);
    const iso = new Date(2026, 9, 31, 9, 4, 0).toISOString();
    assert.equal(formatNoteListWhen(iso, now), formatNoteClock(iso));
  });

  it('midnight boundary: 00:01 today is a clock; 23:59 yesterday is relative yesterday', () => {
    const now = new Date(2026, 9, 31, 10, 0, 0);
    const today = new Date(2026, 9, 31, 0, 1, 0).toISOString();
    const yest = new Date(2026, 9, 30, 23, 59, 0).toISOString();
    assert.equal(formatNoteListWhen(today, now), formatNoteClock(today));
    assert.equal(formatNoteListWhen(yest, now), yesterdayWord());
    assert.notEqual(formatNoteListWhen(yest, now), formatNoteClock(yest));
  });

  it('6 local days ago is a weekday; 7 local days ago is a date, not a clock', () => {
    const now = new Date(2026, 9, 31, 15, 12, 0);
    const six = localIso(now, 6);
    const seven = localIso(now, 7);
    const sixDate = new Date(six);
    assert.equal(formatNoteListWhen(six, now), sixDate.toLocaleDateString(undefined, { weekday: 'short' }));
    assert.notEqual(formatNoteListWhen(seven, now), formatNoteClock(seven));
    assert.equal(
      formatNoteListWhen(seven, now),
      new Date(seven).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
    );
  });

  it('NEG: a note from 8 days ago never renders as only a clock', () => {
    const now = new Date(2026, 9, 31, 15, 12, 0);
    const iso = localIso(now, 8);
    const got = formatNoteListWhen(iso, now);
    assert.notEqual(got, formatNoteClock(iso));
    assert.doesNotMatch(got, /^\d{1,2}:\d{2}/);
  });

  it('Dec 31 → Jan 1 is yesterday, not a year-stamped date', () => {
    const now = new Date(2026, 0, 1, 12, 0, 0);
    const iso = new Date(2025, 11, 31, 18, 0, 0).toISOString();
    assert.equal(formatNoteListWhen(iso, now), yesterdayWord());
    assert.doesNotMatch(formatNoteListWhen(iso, now), /2025/);
  });

  it('older different year includes the year', () => {
    const now = new Date(2026, 0, 8, 12, 0, 0);
    const iso = new Date(2025, 11, 31, 18, 0, 0).toISOString();
    assert.equal(
      formatNoteListWhen(iso, now),
      new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }),
    );
  });

  it('NEG: a future lastAt within 5 minutes renders as a time, never Tomorrow', () => {
    const now = new Date(2026, 9, 31, 23, 58, 0);
    const iso = new Date(now.getTime() + 2 * 60 * 1000).toISOString();
    const got = formatNoteListWhen(iso, now);
    assert.equal(got, formatNoteClock(iso));
    assert.doesNotMatch(got, /tomorrow/i);
  });

  it('keeps in-thread day headings on formatNoteDay (year always present)', () => {
    const iso = new Date(2026, 9, 24, 15, 12, 0).toISOString();
    const now = new Date(2026, 9, 31, 15, 12, 0);
    assert.notEqual(formatNoteDay(iso), formatNoteListWhen(iso, now));
    assert.match(formatNoteDay(iso), /2026/);
  });
});
