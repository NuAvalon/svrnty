// Validator for an inbound portal sign-request (spec v0.7 §1/§6/§7/§8; defaults from Archie lane:portal #994).
// Run: npx --no-install tsx --test src/lib/compose/compose-request.test.ts
// Anchored to the SHARED fixture: its three objects must be accepted, and every text vector must get the same verdict through the validator that the
// rules module gives (so a rule dropped in the validator cannot hide behind a rules-module test).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { COMPOSE_CAP } from './compose-rules';
import {
  COMPOSE_MAX_FUTURE_SKEW_MS,
  COMPOSE_MAX_WINDOW_MS,
  validateComposeRequest,
  type RefusalCode,
} from './compose-request';

const fx = JSON.parse(readFileSync(join(__dirname, 'compose-vectors-v1.json'), 'utf8'));
const NOW = new Date('2026-10-25T03:02:00.000Z'); // inside the fixture objects' 03:00 -> 03:05 window
const POST = fx.preimage[0].object as Record<string, string>;
const HOSTILE = fx.preimage[1].object as Record<string, string>;
const TASK = fx.preimage[2].object as Record<string, string>;
const clone = <T>(o: T): T => JSON.parse(JSON.stringify(o));
const text = (hex: string[]): string => String.fromCodePoint(...hex.map((h) => parseInt(h, 16)));

function code(raw: unknown, now: Date = NOW): RefusalCode | 'OK' {
  const r = validateComposeRequest(raw, now);
  return r.ok ? 'OK' : r.refusal.code;
}
const withField = (base: Record<string, string>, patch: Record<string, unknown>) => ({ ...clone(base), ...patch });
const without = (base: Record<string, string>, k: string) => {
  const c = clone(base);
  delete c[k];
  return c;
};

test('the fixture objects are accepted: post, hostile-JSON post (quotes, backslash, CJK, emoji ZWJ), task; kind and a fresh copy come back', () => {
  for (const [obj, kind] of [[POST, 'post'], [HOSTILE, 'post'], [TASK, 'task']] as const) {
    const r = validateComposeRequest(obj, NOW);
    assert.equal(r.ok, true, `${kind}`);
    if (!r.ok) continue;
    assert.equal(r.request.kind, kind);
    assert.deepEqual(r.request.object, obj);
    assert.notEqual(r.request.object, obj, 'a fresh object, not the caller\'s');
  }
});

test('does not mutate its input, and a frozen input is fine', () => {
  const frozen = Object.freeze(clone(POST));
  assert.equal(code(frozen), 'OK');
  const before = JSON.stringify(POST);
  validateComposeRequest(POST, NOW);
  assert.equal(JSON.stringify(POST), before);
});

test('shape: not an object / unknown purpose / unknown field / missing field / non-string value; strict, no extra keys', () => {
  for (const bad of [null, undefined, 'x', 7, [], [POST]]) assert.equal(code(bad), 'not-an-object', JSON.stringify(bad));
  assert.equal(code(withField(POST, { purpose: 'svrnty-loom-post-v2' })), 'unknown-purpose');
  assert.equal(code(without(POST, 'purpose')), 'unknown-purpose');
  assert.equal(code(withField(POST, { mentions: 'peter' })), 'unknown-field', 'an unknown key could smuggle content into the signed bytes');
  assert.equal(code(withField(POST, { title: 'x' })), 'unknown-field', 'a post has no title');
  assert.equal(code(withField(TASK, { extra: 'x' })), 'unknown-field');
  for (const k of ['fleet', 'thread', 'body', 'nonce', 'issued_at', 'expires_at', 'origin']) assert.equal(code(without(POST, k)), 'missing-field', `post without ${k}`);
  for (const k of ['title', 'target', 'body', 'thread']) assert.equal(code(without(TASK, k)), 'missing-field', `task without ${k}`);
  for (const v of [5, null, true, ['a'], { a: 1 }]) assert.equal(code(withField(POST, { body: v })), 'not-a-string', JSON.stringify(v));
});

test('fixed fields: fleet, origin, thread charset (bidi / zero-width / space refused), nonce = 32 lowercase hex', () => {
  assert.equal(code(withField(POST, { fleet: 'weft' })), 'OK');
  for (const f of ['Autobots', 'weft ', '', 'both']) assert.equal(code(withField(POST, { fleet: f })), 'bad-fleet', JSON.stringify(f));
  assert.equal(code(withField(POST, { origin: 'noosphere.nuavalon.com.evil.test' })), 'bad-origin');
  assert.equal(code(withField(POST, { origin: 'Noosphere.nuavalon.com' })), 'bad-origin');
  for (const t of ['', 'x'.repeat(65), 'lane portal', 'la‮ne', 'la​ne', 'lane\n', 'lané']) assert.equal(code(withField(POST, { thread: t })), 'bad-thread', JSON.stringify(t));
  assert.equal(code(withField(POST, { thread: 'x'.repeat(64) })), 'OK');
  for (const n of ['', 'ABCDEF0123456789ABCDEF0123456789', '0011', 'g'.repeat(32), `${'0'.repeat(32)}0`]) assert.equal(code(withField(POST, { nonce: n })), 'bad-nonce', JSON.stringify(n));
});

test('time: exact ISO ms Z and a real instant; window in (0, 5 min]; expired and future-issued are refused at the exact boundaries', () => {
  for (const t of ['2026-10-25T03:00:00Z', '2026-10-25 03:00:00.000Z', '2026-10-25T03:00:00.000+00:00', '2026-02-31T03:00:00.000Z', 'soon', '']) {
    assert.equal(code(withField(POST, { issued_at: t })), 'bad-time', `issued ${JSON.stringify(t)}`);
    assert.equal(code(withField(POST, { expires_at: t })), 'bad-time', `expires ${JSON.stringify(t)}`);
  }
  assert.equal(code(withField(POST, { expires_at: POST.issued_at })), 'window-not-forward');
  assert.equal(code(withField(POST, { expires_at: '2026-10-25T02:59:59.999Z' })), 'window-not-forward');
  assert.equal(COMPOSE_MAX_WINDOW_MS, 300_000);
  assert.equal(code(withField(POST, { expires_at: '2026-10-25T03:05:00.000Z' })), 'OK', 'exactly 5 min is allowed');
  assert.equal(code(withField(POST, { expires_at: '2026-10-25T03:05:00.001Z' })), 'window-too-long');
  assert.equal(code(POST, new Date('2026-10-25T03:04:59.999Z')), 'OK');
  assert.equal(code(POST, new Date('2026-10-25T03:05:00.000Z')), 'expired', 'expires_at == now is expired');
  assert.equal(code(POST, new Date('2026-10-25T03:07:00.000Z')), 'expired');
  const issued = Date.parse(POST.issued_at);
  assert.equal(COMPOSE_MAX_FUTURE_SKEW_MS, 60_000);
  assert.equal(code(POST, new Date(issued - COMPOSE_MAX_FUTURE_SKEW_MS)), 'OK', 'issued exactly 60 s ahead of the phone is allowed');
  assert.equal(code(POST, new Date(issued - COMPOSE_MAX_FUTURE_SKEW_MS - 1)), 'issued-in-future');
});

test('text: every fixture text vector gets the same verdict through the validator (refused indices, flag addendum, mention hint)', () => {
  let refusedSeen = 0;
  let allowedSeen = 0;
  for (const v of fx.text) {
    const body = text(v.input_cps);
    const r = validateComposeRequest(withField(POST, { body }), NOW);
    if (body.trim() === '') continue; // none in the fixture; guarded so a future all-whitespace vector is judged by the empty rule
    if (v.receiver_rejects) {
      refusedSeen++;
      assert.equal(r.ok, false, `${v.id} must be refused`);
      if (!r.ok) {
        assert.equal(r.refusal.code, 'refused-characters', v.id);
        assert.equal(r.refusal.field, 'body');
        assert.deepEqual(r.refusal.indices, v.refused_indices, `${v.id}: indices`);
        assert.equal(r.refusal.flagAddendum, v.flag_addendum, `${v.id}: flag addendum`);
      }
    } else {
      allowedSeen++;
      assert.equal(r.ok, true, `${v.id} must pass`);
      if (r.ok) assert.equal(r.request.mentionsHint, v.mention_hint, `${v.id}: mention hint`);
    }
  }
  assert.ok(refusedSeen >= 15 && allowedSeen >= 8, `covered ${refusedSeen} refused / ${allowedSeen} allowed`);
});

test('text: a refused character in a TASK title or body is refused too, naming the field; the app never rewrites it', () => {
  const t = withField(TASK, { title: 'pe​ter' });
  const r = validateComposeRequest(t, NOW);
  assert.equal(r.ok, false);
  if (!r.ok) assert.deepEqual([r.refusal.code, r.refusal.field, r.refusal.indices], ['refused-characters', 'title', [2]]);
  assert.equal(code(withField(TASK, { body: 'a\tb' })), 'refused-characters');
  assert.equal(code(withField(TASK, { body: 'a\r\nb' })), 'refused-characters');
  assert.equal(code(withField(POST, { body: 'two\nlines are fine' })), 'OK');
});

test('empty: an empty or all-whitespace body / title is refused (decided, never rewritten)', () => {
  for (const b of ['', ' ', '   ', '\n', ' \n ']) assert.equal(code(withField(POST, { body: b })), 'empty', JSON.stringify(b));
  assert.equal(code(withField(TASK, { title: ' ' })), 'empty');
  assert.equal(code(withField(POST, { body: ' x ' })), 'OK', 'surrounding spaces are signed as received');
});

test('cap: every cost-boundary vector, as a POST body; and the TASK cap is title + body TOTAL (Archie #994 Q1)', () => {
  const build = (r: { repeat: string; times: number; then_ascii_a: number }) => String.fromCodePoint(parseInt(r.repeat, 16)).repeat(r.times) + 'a'.repeat(r.then_ascii_a);
  for (const v of fx.cost) {
    const body = build(v.recipe);
    const r = validateComposeRequest(withField(POST, { body }), NOW);
    assert.equal(r.ok, v.within_cap, `${v.id}`);
    if (r.ok) assert.equal(r.request.cost, v.cost);
    // A vector that is ONLY newlines is all-whitespace, so the empty rule refuses it before the cap is looked at (either way it is refused).
    else if (body.trim() === '') assert.equal(r.refusal.code, 'empty', `${v.id}: all-whitespace is refused as empty`);
    else assert.deepEqual([r.refusal.code, r.refusal.cost], ['over-cap', v.cost], `${v.id}`);
  }
  // A newline-heavy body that is NOT blank still reaches the cap: 'a' + 967 newlines = 1 + 3*967 = 2902.
  const nl = validateComposeRequest(withField(POST, { body: 'a' + '\n'.repeat(967) }), NOW);
  assert.equal(nl.ok, false);
  if (!nl.ok) assert.deepEqual([nl.refusal.code, nl.refusal.cost], ['over-cap', 2902]);
  // Task: the SUM counts. A 2000-cost body alone is fine; with a 901-cost title it is over.
  assert.equal(code(withField(TASK, { title: 'a'.repeat(900), body: 'a'.repeat(2000) })), 'OK');
  const r = validateComposeRequest(withField(TASK, { title: 'a'.repeat(901), body: 'a'.repeat(2000) }), NOW);
  assert.equal(r.ok, false);
  if (!r.ok) assert.deepEqual([r.refusal.code, r.refusal.cost], ['over-cap', 2901]);
  assert.equal(COMPOSE_CAP, 2900);
});

test('task: thread must be lane:orch; target = "route" or the thread-id charset; dag_node optional with that charset', () => {
  assert.equal(code(withField(TASK, { thread: 'lane:portal' })), 'bad-task-thread');
  assert.equal(code(withField(TASK, { target: 'athena' })), 'OK');
  assert.equal(code(withField(TASK, { target: 'route' })), 'OK');
  for (const t of ['', 'ath ena', 'ath​ena', 'x'.repeat(65)]) assert.equal(code(withField(TASK, { target: t })), 'bad-target', JSON.stringify(t));
  assert.equal(code(withField(TASK, { dag_node: 'node:651' })), 'OK');
  assert.equal(code(withField(TASK, { dag_node: 'bad node' })), 'bad-dag-node');
  assert.equal(code(withField(POST, { dag_node: 'node:651' })), 'unknown-field', 'a post has no dag_node');
});

test('the refusal never echoes request text: every Refusal carries only a code, a field NAME and numbers', () => {
  const hostile = '<script>alert(1)</script>';
  for (const patch of [{ body: `${hostile}‮` }, { thread: hostile }, { fleet: hostile }, { origin: hostile }, { nonce: hostile }, { issued_at: hostile }]) {
    const r = validateComposeRequest(withField(POST, patch), NOW);
    assert.equal(r.ok, false);
    if (!r.ok) assert.doesNotMatch(JSON.stringify(r.refusal), /script|alert/);
  }
  // An unknown KEY is request text too: the refusal must carry neither the key nor any field name for it.
  const unk = validateComposeRequest(withField(POST, { [hostile]: 'x' }), NOW);
  assert.equal(unk.ok, false);
  if (!unk.ok) {
    assert.equal(unk.refusal.code, 'unknown-field');
    assert.equal(unk.refusal.field, undefined);
    assert.doesNotMatch(JSON.stringify(unk.refusal), /script|alert/);
  }
  // Every field NAME a refusal can carry is one of ours.
  const OURS = new Set(['purpose', 'fleet', 'thread', 'body', 'title', 'target', 'dag_node', 'nonce', 'issued_at', 'expires_at', 'origin']);
  for (const patch of [{ body: 5 }, { fleet: 'x' }, { thread: ' ' }, { nonce: 'x' }, { issued_at: 'x' }, { expires_at: 'x' }, { origin: 'x' }, { body: '\u202E' }]) {
    const r = validateComposeRequest(withField(POST, patch), NOW);
    if (!r.ok && r.refusal.field !== undefined) assert.ok(OURS.has(r.refusal.field), `field ${r.refusal.field}`);
  }
});
