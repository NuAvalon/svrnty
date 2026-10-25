// Run: npx tsx --test src/lib/compose/compose-receive.test.ts
// The note-open pipeline with the REAL pin logic, parser, validator and queue. Every branch of what the host does with an accepted inbound note.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { receiveComposeNote, isComposeShaped, type AcceptedInboundNote, type ReceiveEvent } from './compose-receive';
import { emptyQueue, current, QUEUE_CAP, type QueueState } from './compose-queue';
import { COMPOSE_NOTE_TYPE, COMPOSE_NOTE_MAX_CHARS } from './compose-inbound';
import type { PinState } from './compose-pin';
import { DROPPED_THREAD_LINE } from './compose-drop-log';
import { PIN_COPY } from './compose-pin-copy';

const NOW = new Date('2026-10-25T07:20:00.000Z');
const PORTAL = 'ab'.repeat(32);
const OTHER = 'cd'.repeat(32);
const PINNED: PinState = { state: 'pinned', record: { v: 1, fp: PORTAL, pinned_at: '2026-10-25T00:00:00.000Z' } };
const nonceN = (n: number) => n.toString(16).padStart(32, '0');
const req = (n = 1, over: Record<string, string> = {}) => ({ purpose: 'svrnty-loom-post-v1', fleet: 'autobots', thread: 'lane:ops', body: `hello ${n}`, nonce: nonceN(n),
  issued_at: '2026-10-25T07:20:00.000Z', expires_at: '2026-10-25T07:25:00.000Z', origin: 'noosphere.nuavalon.com', ...over });
const noteBody = (r: unknown) => JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: r });
const note = (over: Partial<AcceptedInboundNote> = {}): AcceptedInboundNote => ({ note_id: 'note-1', from_fingerprint: PORTAL, body: noteBody(req()), direction: 'inbound', authenticatedByAcceptance: true, ...over });
const run = (n: AcceptedInboundNote, pin: PinState = PINNED, q: QueueState = emptyQueue()) => receiveComposeNote(n, pin, q, NOW);
const kind = (e: ReceiveEvent) => e.kind;

test('the happy path: a pinned, verified sender\'s valid request becomes ONE sign card', () => {
  const { queue, event } = run(note());
  assert.equal(kind(event), 'queued');
  const item = current(queue, NOW)!;
  assert.equal(item.kind, 'sign');
  assert.equal(item.kind === 'sign' && item.request.object.body, 'hello 1');
});

test('PLAIN CHAT is ignored entirely: no card, no candidate, no log, the queue is untouched (also non-JSON, JSON arrays, other types, and oversize)', () => {
  const bodies = ['hi there', '{"type":"chat","request":{}}', '[1,2]', '{', '', JSON.stringify({ request: req() }), 'x'.repeat(COMPOSE_NOTE_MAX_CHARS + 1), '{"type":"' + COMPOSE_NOTE_TYPE + '"' + ' '.repeat(COMPOSE_NOTE_MAX_CHARS)];
  for (const body of bodies) {
    const q = emptyQueue();
    const r = run(note({ body }), PINNED, q);
    assert.equal(kind(r.event), 'ignored', body.slice(0, 30));
    assert.equal(r.queue, q);
  }
  assert.equal(isComposeShaped(noteBody(req())), true);
  assert.equal(isComposeShaped(undefined), false);
  // VALID, compose-shaped JSON padded past the cap: only the length bound can refuse this (every other test body above fails for another reason too)
  const padded = noteBody(req()) + ' '.repeat(COMPOSE_NOTE_MAX_CHARS);
  assert.ok(padded.length > COMPOSE_NOTE_MAX_CHARS && JSON.parse(padded).type === COMPOSE_NOTE_TYPE, 'precondition: it really is valid compose-shaped JSON');
  assert.equal(isComposeShaped(padded), false);
  assert.equal(kind(run(note({ body: padded })).event), 'ignored');
});

test('an OUTBOUND note (our own copy) and a note that does not carry the acceptance mark are never a request', () => {
  assert.equal(kind(run(note({ direction: 'outbound' })).event), 'ignored');
  assert.equal(kind(run(note({ authenticatedByAcceptance: false as unknown as true })).event), 'ignored');
});

test('UNPINNED: a compose-shaped note from a verified sender makes a CANDIDATE and the fixed log line, and NO card', () => {
  const { queue, event } = run(note(), { state: 'absent' });
  assert.deepEqual(event, { kind: 'unpinned', candidate: PORTAL, logLine: PIN_COPY.unpinnedLog });
  assert.deepEqual(queue.pending, []);
});

test('LOCKED store: no card, no candidate, the fixed line', () => {
  const { queue, event } = run(note(), { state: 'locked' });
  assert.equal(event.kind, 'no-card');
  assert.deepEqual(queue.pending, []);
});

test('PINNED but a DIFFERENT verified key: blocked with the passive notice, no card, and the note is never parsed', () => {
  const { queue, event } = run(note({ from_fingerprint: OTHER }));
  assert.deepEqual(event, { kind: 'blocked', notice: PIN_COPY.changedNotice, candidate: OTHER });
  assert.deepEqual(queue.pending, []);
});

test('an UNREADABLE pin blocks everything with the passive notice', () => {
  const { queue, event } = run(note(), { state: 'unreadable' });
  assert.deepEqual(event, { kind: 'blocked', notice: PIN_COPY.unreadableNotice, candidate: PORTAL });
  assert.deepEqual(queue.pending, []);
});

test('the sender comes from the ENVELOPE, never the note: a request whose own text names the pinned key but arrives from another key is blocked', () => {
  const sneaky = note({ from_fingerprint: OTHER, body: JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: req(), from_fingerprint: PORTAL }) });
  assert.equal(kind(run(sneaky).event), 'blocked');
});

test('a pinned sender\'s compose-shaped note that is MALFORMED is a bad-note (a code for a counter), no card: extra top-level key, wrong shape, duplicate key, lone surrogate', () => {
  const lone = `{"type":"${COMPOSE_NOTE_TYPE}","request":${JSON.stringify(req()).replace('hello 1', '\\ud800')}}`;
  const cases = [JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: req(), extra: 1 }), `{"type":"${COMPOSE_NOTE_TYPE}","type":"${COMPOSE_NOTE_TYPE}","request":{}}`, JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: [1] }), lone];
  for (const body of cases) {
    const r = run(note({ body }));
    assert.equal(kind(r.event), 'bad-note', body.slice(0, 50));
    assert.deepEqual(r.queue.pending, []);
  }
  assert.equal((run(note({ body: lone })).event as { code?: string }).code, 'wrong-shape');
});

test('the same request twice (a replay or a redelivery) makes ONE card; the second is a duplicate', () => {
  const a = run(note());
  const b = run(note({ note_id: 'note-2' }), PINNED, a.queue);
  assert.equal(kind(b.event), 'duplicate');
  assert.equal(b.queue.pending.length, 1);
});

test('the queue is bounded: the 6th distinct request is `full`, not a 6th card', () => {
  let q = emptyQueue();
  for (let i = 1; i <= QUEUE_CAP; i++) q = run(note({ note_id: `n${i}`, body: noteBody(req(i)) }), PINNED, q).queue;
  const r = run(note({ note_id: 'n6', body: noteBody(req(6)) }), PINNED, q);
  assert.equal(kind(r.event), 'full');
  assert.equal(r.queue.pending.length, QUEUE_CAP);
});

test('a thread id with a hidden character is DROPPED with no card, and the log line is the fixed template with the NOTE ID as the token (never the thread id)', () => {
  for (const evil of ['lane:o‮ps', 'lane:o​ps', 'lane:\u001b[31mops']) {
    const r = run(note({ note_id: 'note-77', body: noteBody(req(1, { thread: evil })) }));
    assert.equal(kind(r.event), 'dropped');
    assert.deepEqual(r.queue.pending, []);
    const line = (r.event as { logLine: string | null }).logLine;
    assert.equal(line, DROPPED_THREAD_LINE('note-77'));
    assert.equal(line!.includes(evil), false);
  }
  // a note id that is not plainly safe is replaced, never echoed
  const bad = run(note({ note_id: 'n‮x', body: noteBody(req(1, { thread: 'lane:o​ps' })) }));
  assert.equal((bad.event as { logLine: string | null }).logLine, DROPPED_THREAD_LINE('-'));
});

test('other drops (expired, wrong origin, unknown field) have NO log line and no card', () => {
  for (const over of [{ origin: 'evil.example' } as Record<string, string>, { expires_at: '2026-10-25T07:19:00.000Z', issued_at: '2026-10-25T07:14:00.000Z' } as Record<string, string>]) {
    const r = run(note({ body: noteBody(req(1, over)) }));
    assert.equal(kind(r.event), 'dropped');
    assert.equal((r.event as { logLine: string | null }).logLine, null);
    assert.deepEqual(r.queue.pending, []);
  }
});

test('hidden characters in the BODY give a Close-only REFUSAL card (the one refusal that has a card)', () => {
  const r = run(note({ body: noteBody(req(1, { body: 'pay‮now' })) }));
  assert.equal(kind(r.event), 'queued');
  const item = current(r.queue, NOW)!;
  assert.equal(item.kind, 'refusal');
  assert.equal(item.kind === 'refusal' && item.shownText, 'pay‮now');
});
