// #720 T2b: the retry schedule of a held ratchet-desync envelope. Memory only; pure clock arithmetic.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHoldBackoff, FIRST_WINDOW_MS, SLOW_EVERY_MS, MAX_TRACKED } from './hold-backoff';

const T0 = Date.parse('2026-10-30T12:00:00.000Z');
const MIN = 60_000;

test('B1 an envelope never seen as a desync hold is always due', () => {
  assert.equal(createHoldBackoff().due('a', T0), true);
});

test('B2 first hour: due on EVERY poll, however close together; the boundary minute still counts as the first hour', () => {
  const b = createHoldBackoff();
  b.attempted('a', 'fp1', T0);
  for (const dt of [0, 1, 30 * MIN, 59 * MIN, FIRST_WINDOW_MS - 1]) {
    assert.equal(b.due('a', T0 + dt), true, `+${dt}ms`);
    b.attempted('a', 'fp1', T0 + dt); // each poll tries it again; `last` moves but `first` does not
  }
});

test('B3 after the first hour: NOT due until an hour after the LAST try, then due again (and the clock restarts from that try)', () => {
  const b = createHoldBackoff();
  b.attempted('a', 'fp1', T0);
  b.attempted('a', 'fp1', T0 + 59 * MIN); // last try inside the first hour
  assert.equal(b.due('a', T0 + 61 * MIN), false, '2 min after the last try, past the first hour: wait');
  assert.equal(b.due('a', T0 + 59 * MIN + SLOW_EVERY_MS - 1), false);
  assert.equal(b.due('a', T0 + 59 * MIN + SLOW_EVERY_MS), true, 'an hour after the last try');
  b.attempted('a', 'fp1', T0 + 120 * MIN);
  assert.equal(b.due('a', T0 + 150 * MIN), false, 'the schedule restarts from the new try');
  assert.equal(b.due('a', T0 + 180 * MIN), true);
});

test('B4 due() is read-only: asking any number of times never moves the schedule (only attempted() does)', () => {
  const b = createHoldBackoff();
  b.attempted('a', 'fp1', T0);
  b.attempted('a', 'fp1', T0 + 59 * MIN); // the last try
  for (let i = 0; i < 5; i++) assert.equal(b.due('a', T0 + 100 * MIN), false, `ask #${i}: 41 min after the last try`);
  assert.equal(b.due('a', T0 + 59 * MIN + SLOW_EVERY_MS), true, 'still due exactly an hour after the LAST try, not later');
});

test('B5 the remembered fingerprint survives a later attempt that has none, and is replaced by one that has', () => {
  const b = createHoldBackoff();
  b.attempted('a', 'fp1', T0);
  b.attempted('a', undefined, T0 + MIN);
  assert.equal(b.fpOf('a'), 'fp1');
  b.attempted('a', 'fp2', T0 + 2 * MIN);
  assert.equal(b.fpOf('a'), 'fp2');
});

test('B6 forget() ends one id\'s schedule (it is due like a fresh one); other ids are untouched', () => {
  const b = createHoldBackoff();
  for (const id of ['a', 'b']) { b.attempted(id, 'fp1', T0); b.attempted(id, 'fp1', T0 + 59 * MIN); } // first sight T0, last try T0+59m
  assert.equal(b.due('a', T0 + 100 * MIN), false); assert.equal(b.due('b', T0 + 100 * MIN), false);
  b.forget('a');
  assert.equal(b.due('a', T0 + 100 * MIN), true, 'forgotten: fresh');
  assert.equal(b.due('b', T0 + 100 * MIN), false, 'the other id keeps its schedule');
  assert.equal(b.size(), 1);
});

test('B7 keepOnly() drops the ids the relay no longer holds and keeps the rest', () => {
  const b = createHoldBackoff();
  for (const id of ['a', 'b', 'c']) b.attempted(id, 'fp', T0);
  b.keepOnly(new Set(['b']));
  assert.equal(b.size(), 1);
  assert.equal(b.fpOf('b'), 'fp'); assert.equal(b.fpOf('a'), undefined);
});

test('B8 clear() forgets everything; the map is bounded: past MAX_TRACKED a new id is not tracked and stays due (status quo)', () => {
  const b = createHoldBackoff();
  for (let i = 0; i < MAX_TRACKED + 25; i++) b.attempted(`id${i}`, 'fp', T0);
  assert.equal(b.size(), MAX_TRACKED);
  assert.equal(b.due(`id${MAX_TRACKED + 5}`, T0 + 90 * MIN), true, 'untracked: retried every poll, never starved');
  b.clear();
  assert.equal(b.size(), 0);
});

test('W1 static wiring: the poll\'s consume deps carry the shared holdBackoff (else the schedule silently never runs), and a session lock clears it', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('./live-book-poll.ts', import.meta.url), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');
  const body = src.slice(src.indexOf('export async function buildConsumeDeps('));
  assert.match(body, /deadLetter: buildDeadLetterSink\(owner\),\s*holdBackoff,/, 'buildConsumeDeps must hand consume the module holdBackoff');
  assert.match(src, /onSessionLock\(\(\) => holdBackoff\.clear\(\)\)/);
  assert.match(src, /import \{ holdBackoff \} from '@\/lib\/sync\/hold-backoff'/);
});
