// The receive seam's pure half (Flint #996 Q3; wire shape = Archie's proposal lane:portal #1032).
// Run: npx --no-install tsx --test src/lib/compose/compose-inbound.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { COMPOSE_NOTE_MAX_CHARS, COMPOSE_NOTE_TYPE, hasDuplicateJsonKeys, isUsablePin, parseComposeNote, pinDisplay, type InboundRefusalCode } from './compose-inbound';
import { validateComposeRequest } from './compose-request';

const fx = JSON.parse(readFileSync(join(__dirname, 'compose-vectors-v1.json'), 'utf8'));
const POST = fx.preimage[0].object as Record<string, string>;
const TASK = fx.preimage[2].object as Record<string, string>;
const NOW = new Date('2026-10-25T03:02:00.000Z');
const PIN64 = 'ab'.repeat(32);
const PIN40 = 'cd'.repeat(20);
const note = (request: unknown, extra: Record<string, unknown> = {}, type: unknown = COMPOSE_NOTE_TYPE) => JSON.stringify({ type, request, ...extra });
const ok = (over: Partial<{ plaintext: string; senderFingerprint: string; senderVerified: boolean }> = {}) => ({
  plaintext: note(POST),
  senderFingerprint: PIN64,
  senderVerified: true,
  ...over,
});
const code = (r: ReturnType<typeof parseComposeNote>): InboundRefusalCode | 'OK' => (r.ok ? 'OK' : r.code);

test('accepts the proposed shape from the pinned, verified sender and hands back the RAW request (the validator is the next gate, not this)', () => {
  for (const [req, pin] of [[POST, PIN64], [TASK, PIN64], [POST, PIN40]] as const) {
    const r = parseComposeNote(ok({ plaintext: note(req), senderFingerprint: pin }), pin);
    assert.equal(r.ok, true);
    if (r.ok) {
      assert.deepEqual(r.raw, req);
      assert.equal(validateComposeRequest(r.raw, NOW).ok, true, 'and the validator accepts what the seam hands on');
    }
  }
  assert.equal(COMPOSE_NOTE_TYPE, 'svrnty-compose-request-v1');
});

test('SENDER GATE comes first and reads nothing inside the note: no pin, bad pin, unverified, or a different sender are all refused, even for a perfect note', () => {
  for (const none of [null, undefined, '']) assert.equal(code(parseComposeNote(ok(), none)), 'no-pinned-sender', String(none));
  for (const bad of ['ab'.repeat(8), 'AB'.repeat(32), 'zz'.repeat(32), `${PIN64}0`, 'ab'.repeat(31)]) {
    assert.equal(code(parseComposeNote(ok(), bad)), 'bad-pin', `a prefix / uppercase / non-hex / odd-length pin is not usable: ${bad}`);
  }
  assert.equal(code(parseComposeNote(ok({ senderVerified: false }), PIN64)), 'sender-not-verified');
  assert.equal(code(parseComposeNote(ok({ senderVerified: undefined as unknown as boolean }), PIN64)), 'sender-not-verified', 'only a literal true counts');
  assert.equal(code(parseComposeNote(ok({ senderFingerprint: 'ef'.repeat(32) }), PIN64)), 'wrong-sender');
  // A prefix of the pin is a DIFFERENT identity.
  assert.equal(code(parseComposeNote(ok({ senderFingerprint: PIN64.slice(0, 16) }), PIN64)), 'wrong-sender');
  assert.equal(code(parseComposeNote(ok({ senderFingerprint: undefined as unknown as string }), PIN64)), 'wrong-sender');
  // Sender-gate refusals do not depend on the plaintext at all (garbage in, same code out).
  assert.equal(code(parseComposeNote(ok({ plaintext: '\u0000not json', senderVerified: false }), PIN64)), 'sender-not-verified');
});

test('the sender comes from the ENVELOPE, never from the note: a note that CLAIMS the pinned sender but arrives from someone else is refused', () => {
  const forged = note(POST, {}, COMPOSE_NOTE_TYPE).replace('{', `{"from":"${PIN64}",`);
  assert.equal(code(parseComposeNote(ok({ plaintext: forged, senderFingerprint: 'ef'.repeat(32) }), PIN64)), 'wrong-sender');
  // Even a claim of the right sender inside a note from the right sender adds an extra key, which is refused as the wrong shape.
  assert.equal(code(parseComposeNote(ok({ plaintext: forged }), PIN64)), 'wrong-shape');
});

test('fingerprint comparison is case-insensitive on the ENVELOPE side only (the pin itself must already be lowercase)', () => {
  assert.equal(code(parseComposeNote(ok({ senderFingerprint: PIN64.toUpperCase() }), PIN64)), 'OK');
});

test('shape: not JSON / not an object / extra key / missing key / wrong type / non-object request / over-long', () => {
  const p = (plaintext: string) => code(parseComposeNote(ok({ plaintext }), PIN64));
  for (const bad of ['', 'nope', '{', 'undefined']) assert.equal(p(bad), 'not-json', JSON.stringify(bad));
  for (const bad of ['null', '[]', '7', '"x"', 'true']) assert.equal(p(bad), 'wrong-shape', bad);
  assert.equal(p(note(POST, { also: 1 })), 'wrong-shape', 'any other top-level key is refused');
  assert.equal(p(JSON.stringify({ type: COMPOSE_NOTE_TYPE })), 'wrong-shape', 'request missing');
  assert.equal(p(JSON.stringify({ request: POST })), 'wrong-shape', 'type missing');
  assert.equal(p(note(POST, {}, 'svrnty-compose-request-v2')), 'wrong-type');
  assert.equal(p(note(POST, {}, 5)), 'wrong-type');
  for (const req of [null, 'x', 7, [POST], true]) assert.equal(p(note(req)), 'wrong-shape', JSON.stringify(req));
  assert.equal(p(note(POST).padEnd(COMPOSE_NOTE_MAX_CHARS + 1, ' ')), 'too-long');
  assert.equal(p(note(POST).padEnd(COMPOSE_NOTE_MAX_CHARS, ' ')), 'OK', 'exactly the ceiling is allowed');
});

test('a __proto__ key does not poison anything: the seam passes the raw request on (it only checks the envelope) and the VALIDATOR refuses it as an unknown key', () => {
  const evil = '{"type":"svrnty-compose-request-v1","request":{"__proto__":{"polluted":"yes"}}}';
  const r = parseComposeNote(ok({ plaintext: evil }), PIN64);
  assert.equal(r.ok, true, 'the seam only checks the envelope; the VALIDATOR is the gate for the request body');
  if (r.ok) assert.equal(validateComposeRequest(r.raw, NOW).ok, false);
  assert.equal(({} as Record<string, unknown>).polluted, undefined, 'Object.prototype is untouched');
});

test('pin helpers: only a full lowercase fingerprint is a pin; the display string is the first 16 hex Peter compares', () => {
  assert.equal(isUsablePin(PIN64), true);
  assert.equal(isUsablePin(PIN40), true);
  for (const bad of [null, undefined, 5, '', 'ab', 'AB'.repeat(32), `${PIN64}0`, `${PIN64.slice(0, 16)}`, 'g'.repeat(64)]) assert.equal(isUsablePin(bad), false, String(bad));
  assert.equal(pinDisplay(PIN64), PIN64.slice(0, 16));
  assert.equal(pinDisplay(PIN64).length, 16);
});

test('DUPLICATE KEYS (Flint #1035): JSON.parse keeps the last one silently, so a duplicate anywhere in the note is refused', () => {
  const p = (plaintext: string) => code(parseComposeNote(ok({ plaintext }), PIN64));
  // Top level and inside the request; the request body is what the person reads, so the LAST duplicate must never be the one shown.
  const goodReq = JSON.stringify(POST);
  assert.equal(p(`{"type":"${COMPOSE_NOTE_TYPE}","type":"${COMPOSE_NOTE_TYPE}","request":${goodReq}}`), 'duplicate-key');
  assert.equal(p(`{"type":"${COMPOSE_NOTE_TYPE}","request":${goodReq},"request":${goodReq}}`), 'duplicate-key');
  const dupBody = goodReq.replace('}', ',"body":"the LAST one wins in JSON.parse"}');
  assert.equal(p(`{"type":"${COMPOSE_NOTE_TYPE}","request":${dupBody}}`), 'duplicate-key');
  // Control: JSON.parse really would have accepted that and shown the wrong body (so the refusal is doing real work).
  assert.equal((JSON.parse(dupBody) as Record<string, string>).body, 'the LAST one wins in JSON.parse');
  // Escaped spellings of the same name collide.
  assert.equal(p(`{"type":"${COMPOSE_NOTE_TYPE}","request":${goodReq.replace('"body"', '"\\u0062ody"').replace('}', ',"body":"x"}')}}`), 'duplicate-key');
  assert.equal(p(`{"type":"${COMPOSE_NOTE_TYPE}","request":${goodReq}}`), 'OK', 'control: the same note without a duplicate passes');
});

test('hasDuplicateJsonKeys: nested, arrays, escapes, strings that look like JSON, __proto__, whitespace; and fail-closed on what it cannot read', () => {
  const yes = ['{"a":1,"a":2}', '{ "a" : 1 , "a" : 2 }', '{"a":1,"\\u0061":2}', '{"x":{"a":1,"a":2}}', '[{"a":1,"a":2}]', '{"__proto__":1,"__proto__":2}', '{"k":[1,{"z":0,"z":1}]}', '{"\\ud83d\\ude00":1,"😀":2}', '{"a":1}{"b":2}', '{"a":1,}'];
  const no = ['{}', '[]', '{"a":1,"b":2}', '{"a":{"a":1}}', '[{"a":1},{"a":2}]', '{"a":"{\\"b\\":1,\\"b\\":2}"}', '{"a":[1,2,3],"b":null,"c":true,"d":-1.5e3}', ' {"a" : [ ] , "b" : { } } ', '"just a string"', '7'];
  for (const t of yes) assert.equal(hasDuplicateJsonKeys(t), true, t);
  for (const t of no) assert.equal(hasDuplicateJsonKeys(t), false, t);
  for (const t of ['', '{', '{"a"', '{"a":}', 'nul', '{"a":1', '[1,2', '{"a":1 "b":2}']) assert.equal(hasDuplicateJsonKeys(t), true, `fail closed on ${JSON.stringify(t)}`);
});

// compose-words v1 W4 (Flint lane:portal #1465): a request string with a lone surrogate is refused as wrong-shape, because TS and Python escape it differently
// and two honest sides would then show different check-words. Raw JSON can say it with an escape such as "\ud800".
test('W4: a LONE surrogate in a request value or key is refused as wrong-shape (JSON \\uD800 escapes); a valid surrogate PAIR still passes', () => {
  const withBody = (escaped: string) => `{"type":"${COMPOSE_NOTE_TYPE}","request":${JSON.stringify({ ...POST, body: 'X' }).replace('"X"', `"${escaped}"`)}}`;
  for (const bad of ['\\ud800', 'a\\udc00b', 'x\\ud83dy', '\\udc00\\ud800']) {
    assert.equal(code(parseComposeNote(ok({ plaintext: withBody(bad) }), PIN64)), 'wrong-shape', bad);
  }
  assert.equal(code(parseComposeNote(ok({ plaintext: withBody('\\ud83d\\ude00') }), PIN64)), 'OK', 'a valid pair (U+1F600) passes the parser');
  // a lone surrogate in a KEY (the validator would refuse unknown-field, but the parser must not hand the words a divergent string either)
  const keyed = `{"type":"${COMPOSE_NOTE_TYPE}","request":${JSON.stringify(POST).replace('"body"', '"bo\\ud800dy"')}}`;
  assert.equal(code(parseComposeNote(ok({ plaintext: keyed }), PIN64)), 'wrong-shape');
  // the sender gate still comes first: an unpinned app says no-pinned-sender, not wrong-shape
  assert.equal(code(parseComposeNote(ok({ plaintext: withBody('\\ud800') }), null)), 'no-pinned-sender');
});
