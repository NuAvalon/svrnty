// Run: npx tsx --test src/lib/compose/compose-note-cap.test.ts
//
// Pins the plaintext cap COMPOSE_NOTE_MAX_CHARS = 4096 (Athena, lane:portal #1163) to MEASUREMENTS, so a later change to a field maximum or to the cost
// function fails here instead of silently eating the headroom. Athena's numbers (451 wrapper, 3351 compact, 3429 indent-2) were reproduced independently.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { COMPOSE_NOTE_MAX_CHARS, COMPOSE_NOTE_TYPE, parseComposeNote } from './compose-inbound';
import { alwaysRefused, composeCost } from './compose-rules';
import { validateComposeRequest } from './compose-request';

const NOW = new Date('2026-10-25T07:20:00.000Z');
const FP = 'a'.repeat(64);
const t = (n: number) => 't'.repeat(n);

/** The largest LEGAL task request: every fixed field at its maximum, `dag_node` present, title+body spending the whole 2900 cost cap. */
function maxTask(title: string, body: string): Record<string, string> {
  return {
    purpose: 'svrnty-loom-task-v1', fleet: 'autobots', thread: 'lane:orch', title, body,
    target: t(64), dag_node: t(64), nonce: 'a'.repeat(32),
    issued_at: '2026-10-25T07:20:00.000Z', expires_at: '2026-10-25T07:25:00.000Z', origin: 'noosphere.nuavalon.com',
  };
}
const noteOf = (req: unknown, space = 0) => JSON.stringify({ type: COMPOSE_NOTE_TYPE, request: req }, null, space);
const parse = (plaintext: string) => parseComposeNote({ plaintext, senderFingerprint: FP, senderVerified: true }, FP);

test('the cap is exactly the portal\'s stated number, 4096 UTF-16 units (not above it: Flint)', () => {
  assert.equal(COMPOSE_NOTE_MAX_CHARS, 4096);
});

test('the largest LEGAL note (all fixed fields at max, title+body at the 2900 cost cap) is accepted by the validator and measures 451 wrapper + 2900 text = 3351 compact, 3429 indent-2', () => {
  const req = maxTask('x'.repeat(100), 'y'.repeat(2800));
  assert.equal(composeCost(req.title) + composeCost(req.body), 2900);
  assert.equal(validateComposeRequest(req, NOW).ok, true, 'the maximal request is legal');
  const empty = noteOf(maxTask('', ''));
  assert.equal(empty.length, 451, 'wrapper with empty title/body');
  assert.equal(noteOf(req).length, 3351);
  assert.equal(noteOf(req, 2).length, 3429);
  assert.ok(noteOf(req).length <= COMPOSE_NOTE_MAX_CHARS);
  assert.ok(noteOf(req, 2).length <= COMPOSE_NOTE_MAX_CHARS, 'even pretty-printed it fits');
  assert.equal(parse(noteOf(req)).ok, true, 'and the seam accepts it');
});

test('the field maxima this measurement assumes are the validator\'s real ones: a 65-char target or dag_node is REFUSED, 64 accepted', () => {
  assert.equal(validateComposeRequest(maxTask('x', 'y'), NOW).ok, true);
  const r1 = validateComposeRequest({ ...maxTask('x', 'y'), target: t(65) }, NOW);
  const r2 = validateComposeRequest({ ...maxTask('x', 'y'), dag_node: t(65) }, NOW);
  assert.ok(!r1.ok && r1.refusal.code === 'bad-target');
  assert.ok(!r2.ok && r2.refusal.code === 'bad-dag-node');
});

test('PROPERTY over every acceptable code point: composeCost(ch) >= the JSON units it adds when written RAW (what JSON.stringify and the compact portal emit)', () => {
  let checked = 0;
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue; // lone surrogates are not text
    if (alwaysRefused(cp)) continue; // refused outright: never enters a note
    const ch = String.fromCodePoint(cp);
    const units = JSON.stringify(ch).length - 2; // minus the quotes
    if (composeCost(ch) < units) assert.fail(`U+${cp.toString(16)}: cost ${composeCost(ch)} < raw JSON units ${units}`);
    checked++;
  }
  assert.ok(checked > 1_100_000, `walked the whole code space (${checked})`);
});

test('the property is NOT claimed for \\u-escaped ASCII (cost 1, 6 units on the wire): such a note can exceed the cap and is refused too-long BEFORE any parse (fail closed)', () => {
  // negative control for the property above: it does fail for escaped ASCII, so the raw-only claim is the honest one.
  assert.ok(composeCost('A') < '\\u0041'.length);
  const escapedBody = '\\u0041'.repeat(700); // 700 cost-1 chars, 4200 units
  const note = `{"type":"${COMPOSE_NOTE_TYPE}","request":{"body":"${escapedBody}"}}`;
  assert.ok(note.length > COMPOSE_NOTE_MAX_CHARS);
  const r = parse(note);
  assert.ok(!r.ok && r.code === 'too-long');
});

test('boundary: exactly 4096 is allowed, 4097 is refused (the ceiling is inclusive)', () => {
  const base = noteOf(maxTask('x', 'y'));
  assert.equal(parse(base.padEnd(COMPOSE_NOTE_MAX_CHARS, ' ')).ok, true);
  const over = parse(base.padEnd(COMPOSE_NOTE_MAX_CHARS + 1, ' '));
  assert.ok(!over.ok && over.code === 'too-long');
});
