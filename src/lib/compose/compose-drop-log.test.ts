// Run: npx tsx --test src/lib/compose/compose-drop-log.test.ts
// The dropped-request log line (Hypatia 2e479849, Archie #1473, Flint #1474 (2)): fixed text + ONE safe token; nothing from the request can reach it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { emptyQueue, enqueue } from './compose-queue';
import { DROPPED_THREAD_LINE, dropLogLine, NO_TOKEN, refFromText, safeRef } from './compose-drop-log';

const T0 = new Date('2026-10-25T07:20:00.000Z');
const post = (thread: string) => ({ purpose: 'svrnty-loom-post-v1', fleet: 'autobots', thread, body: 'hello', nonce: '0'.repeat(31) + '1',
  issued_at: '2026-10-25T07:20:00.000Z', expires_at: '2026-10-25T07:25:00.000Z', origin: 'noosphere.nuavalon.com' });
const TEMPLATE = (t: string) => `A sign request arrived that couldn't be shown: its thread name contains hidden characters. Nothing was signed. (ref ${t})`;

test('the line is Hypatia\'s string, byte for byte, with the token in place', () => {
  assert.equal(DROPPED_THREAD_LINE('abcd1234'), TEMPLATE('abcd1234'));
  assert.equal(DROPPED_THREAD_LINE('abcd1234'), "A sign request arrived that couldn't be shown: its thread name contains hidden characters. Nothing was signed. (ref abcd1234)");
});

test('NEG (Flint): a thread id carrying U+202E / zero-width / ANSI ESC is DROPPED by the real queue and the log line is byte-identical to the template except the token', () => {
  for (const hostile of ['lane:o‮ps', 'lane:o​ps', 'lane:\u001b[31mops', 'lane:o⁦ps⁩', 'lane:\u{E0041}ops']) {
    const { result, state } = enqueue(emptyQueue(), post(hostile), T0);
    assert.deepEqual(state.pending, [], 'no card');
    assert.equal(result.outcome, 'dropped');
    if (result.outcome !== 'dropped') continue;
    const line = dropLogLine(result.code, 'note-42');
    assert.equal(line, TEMPLATE('note-42'), JSON.stringify(hostile));
    // the hostile thread id appears nowhere in the line, and the line holds no control or format character at all
    assert.equal(line!.includes(hostile), false);
    assert.doesNotMatch(line!, /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁯﻿]|\ud800-\udfff/u);
    assert.doesNotMatch(line!, /\u001b/);
  }
});

test('the token is the ONLY variable part: a hostile or empty token is replaced by "-", never echoed or repaired', () => {
  for (const bad of ['evil‮token', 'a b', '', 'x'.repeat(65), 'tok\u001b[0m', '​', 'a/b', 'a\nb']) {
    assert.equal(safeRef(bad), NO_TOKEN, JSON.stringify(bad));
    assert.equal(DROPPED_THREAD_LINE(bad), TEMPLATE(NO_TOKEN));
  }
  for (const good of ['note-42', 'abcd1234', 'n_1-2', 'A'.repeat(64)]) assert.equal(safeRef(good), good);
  assert.equal(safeRef(undefined as unknown as string), NO_TOKEN);
  assert.equal(safeRef(42 as unknown as string), NO_TOKEN);
});

test('refFromText: 8 lowercase hex chars (sha256 prefix) and a different text gives a different token; the plaintext itself is never in it', () => {
  const a = refFromText('{"type":"x"}'); const b = refFromText('{"type":"y"}');
  assert.match(a, /^[0-9a-f]{8}$/); assert.notEqual(a, b);
  assert.equal(refFromText(''), 'e3b0c442');
});

test('only the THREAD drop has a line; every other drop code returns null (a counter, never a display)', () => {
  const codes = ['not-an-object','unknown-purpose','unknown-field','missing-field','not-a-string','bad-fleet','bad-origin','bad-task-thread','bad-target','bad-dag-node','bad-nonce','bad-time','window-not-forward','window-too-long','expired','issued-in-future','empty','refused-characters','over-cap'] as const;
  for (const c of codes) assert.equal(dropLogLine(c, 't'), null, c);
  assert.notEqual(dropLogLine('bad-thread', 't'), null);
});

test('the function takes a CODE and a token and nothing else, so request text has no path in', () => {
  assert.equal(dropLogLine.length, 2);
  assert.equal(DROPPED_THREAD_LINE.length, 1);
});
