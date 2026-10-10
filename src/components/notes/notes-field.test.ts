import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import type { NoteThread } from '../../lib/messaging/types';
import { filterFieldPeople, mergeFieldPeople, previewLine, sortFieldPeople, threadPeerFp } from './notes-field';

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
