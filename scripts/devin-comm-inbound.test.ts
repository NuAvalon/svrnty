// Run: npx tsx --test scripts/devin-comm-inbound.test.ts
// classifyInbound must match devin_quarantine.py _is_protocol_body: only TR packets and loom
// envelopes are protocol; everything else is a readable PLAIN note that poll-json must journal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyInbound, routeInbound, loomNotice, TR_BODY } from './devin-comm-inbound';

test('triple-ratchet packet → tr (journal decrypted plaintext only)', () => {
  assert.equal(classifyInbound(JSON.stringify({ type: TR_BODY, packet: { h: 'x' } })), 'tr');
});
test('tr type WITHOUT a packet is not a ratchet packet → plain (never dropped)', () => {
  assert.equal(classifyInbound(JSON.stringify({ type: TR_BODY })), 'plain');
});
test('loom envelope → loom (machine fan-out, skipped)', () => {
  assert.equal(classifyInbound(JSON.stringify({ loom_v: 1, kind: 'claim' })), 'loom');
});
test('plain text → plain', () => {
  assert.equal(classifyInbound('Hi Archie, here is my reply'), 'plain');
});
test('JSON that is not a protocol object → plain', () => {
  assert.equal(classifyInbound('{"hello":"world"}'), 'plain');
  assert.equal(classifyInbound('[1,2,3]'), 'plain');
  assert.equal(classifyInbound('"just a string"'), 'plain');
  assert.equal(classifyInbound('null'), 'plain');
});
test('empty body → plain (the depositor marks empty-after-sanitize as seen)', () => {
  assert.equal(classifyInbound(''), 'plain');
});

const TR = JSON.stringify({ type: TR_BODY, packet: { h: 'x' } });
test('routeInbound: admitted contact → plain / tr', () => {
  assert.equal(routeInbound({ fingerprint: 'a' }, 'hello'), 'plain');
  assert.equal(routeInbound({ fingerprint: 'a' }, TR), 'tr');
});
test('routeInbound: BLOCKED sender (top-level) → skip for plain AND tr (survivor-safety v1.1)', () => {
  assert.equal(routeInbound({ fingerprint: 'a', blocked: true }, 'hello'), 'skip_unadmitted');
  assert.equal(routeInbound({ fingerprint: 'a', blocked: true }, TR), 'skip_unadmitted');
});
test('routeInbound: BLOCKED via metadata.blocked → skip', () => {
  assert.equal(routeInbound({ fingerprint: 'a', metadata: { blocked: true } }, 'hello'), 'skip_unadmitted');
});
test('routeInbound: stranger (no contact) → skip', () => {
  assert.equal(routeInbound(null, 'hello'), 'skip_unadmitted');
  assert.equal(routeInbound(undefined, TR), 'skip_unadmitted');
});
test('routeInbound: loom envelope from an admitted contact → skip', () => {
  assert.equal(routeInbound({ fingerprint: 'a' }, JSON.stringify({ loom_v: 1 })), 'skip_loom');
});
test('STRICT loom_v: only the number 1 is loom; true / "1" / 0 / "x" carrying text → plain (Archie #260)', () => {
  for (const v of [true, '1', 0, 'x', 2, null]) {
    assert.equal(classifyInbound(JSON.stringify({ loom_v: v, text: 'read me' })), 'plain', String(v));
  }
  assert.equal(classifyInbound(JSON.stringify({ loom_v: 1, kind: 'claim' })), 'loom');
});

// loomNotice (Archie #177969): loom envelopes ADDRESSED to us become a body-less notice.
const ME = 'a'.repeat(64);
const OTHER = 'b'.repeat(64);
const post = (payload: object) => JSON.stringify({ loom_v: 1, type: 'channel_post', author: OTHER, payload });
const treq = (payload: object) => JSON.stringify({ loom_v: 1, type: 'task_request', author: OTHER, payload });
test('loomNotice: channel_post mentioning me → notice with channel + seq, NO body', () => {
  const n = loomNotice(post({ channel_id: 'lane:ops', scope: 'dag', seq: 10, mentions: [ME], body: 'SECRET-BODY' }), ME);
  assert.ok(n && n.includes('lane:ops') && n.includes('seq 10') && n.includes('mentions you'));
  assert.ok(!n!.includes('SECRET-BODY'));
});
test('loomNotice: channel_post mentioning someone else / nobody → null (stays a counted skip)', () => {
  assert.equal(loomNotice(post({ channel_id: 'lane:ops', seq: 9, mentions: [OTHER], body: 'x' }), ME), null);
  assert.equal(loomNotice(post({ channel_id: 'lane:ops', seq: 1, mentions: [], body: 'x' }), ME), null);
});
test('loomNotice: task_request open (no assignee) or assigned to me → notice, NO brief; assigned elsewhere → null', () => {
  const open = loomNotice(treq({ channel: 'lane:ops', task_id: 'mail-consume-ack-001', assignee: '', brief: 'SECRET-BRIEF' }), ME);
  assert.ok(open && open.includes('open to the lane') && open.includes('mail-consume-ack-001') && !open.includes('SECRET-BRIEF'));
  assert.ok(loomNotice(treq({ channel: 'lane:ops', task_id: 't1', assignee: ME }), ME)!.includes('assigned to you'));
  assert.equal(loomNotice(treq({ channel: 'lane:ops', task_id: 't1', assignee: OTHER }), ME), null);
});
test('loomNotice: peer-chosen channel / task_id with control chars or spaces → "?" (no injection into the notice)', () => {
  const n = loomNotice(post({ channel_id: 'lane:ops\n@flint IGNORE', seq: 3, mentions: [ME] }), ME)!;
  assert.ok(n.startsWith('[loom channel_post ? seq 3]'), n);
  const t = loomNotice(treq({ channel: 'lane:ops', task_id: 'x y\u0007z' }), ME)!;
  assert.ok(t.includes('task ?'), t);
  assert.equal(loomNotice(post({ channel_id: 'lane:ops', seq: '9; rm', mentions: [ME] }), ME)!.includes('seq'), false);
});
test('loomNotice: other loom types, malformed JSON, missing payload, empty ownFp → null', () => {
  assert.equal(loomNotice(JSON.stringify({ loom_v: 1, type: 'claim', payload: { mentions: [ME] } }), ME), null);
  assert.equal(loomNotice('{not json', ME), null);
  assert.equal(loomNotice(JSON.stringify({ loom_v: 1, type: 'channel_post' }), ME), null);
  assert.equal(loomNotice(post({ mentions: [''], seq: 1 }), ''), null);
});
