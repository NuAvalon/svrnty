// Run: npx tsx --test scripts/devin-comm-inbound.test.ts
// classifyInbound must match devin_quarantine.py _is_protocol_body: only TR packets and loom
// envelopes are protocol; everything else is a readable PLAIN note that poll-json must journal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { classifyInbound, routeInbound, loomNotice, openTaskChannel, openTasksNotice, deadNotesNotice, safeToken, TR_BODY } from './devin-comm-inbound';

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
test('loomNotice: task_request assigned to me → notice, NO brief; open or assigned elsewhere → null', () => {
  const mine = loomNotice(treq({ channel: 'lane:ops', task_id: 't1', assignee: ME, brief: 'SECRET-BRIEF' }), ME)!;
  assert.ok(mine.includes('assigned to you') && mine.includes('task t1') && !mine.includes('SECRET-BRIEF'));
  assert.equal(loomNotice(treq({ channel: 'lane:ops', task_id: 'mail-consume-ack-001', assignee: '' }), ME), null);
  assert.equal(loomNotice(treq({ channel: 'lane:ops', task_id: 't1', assignee: OTHER }), ME), null);
});
test('openTaskChannel: open task_request → its channel; assigned / other types → null', () => {
  assert.equal(openTaskChannel(treq({ channel: 'lane:ops', task_id: 'a' })), 'lane:ops');
  assert.equal(openTaskChannel(treq({ channel: 'lane:ops', task_id: 'a', assignee: '' })), 'lane:ops');
  assert.equal(openTaskChannel(treq({ channel: 'lane:ops', assignee: ME })), null);
  assert.equal(openTaskChannel(post({ channel_id: 'lane:ops', mentions: [] })), null);
  assert.equal(openTaskChannel('{bad'), null);
});
test('openTasksNotice (Flint #263): ONE notice per peer, stable id regardless of order, new id when the set grows, no brief', () => {
  const a = { note_id: 'n1', channel: 'lane:ops' }, b = { note_id: 'n2', channel: 'lane:ops' }, c = { note_id: 'n3', channel: 'lane:x' };
  const x = openTasksNotice(OTHER, [a, b]), y = openTasksNotice(OTHER, [b, a]), z = openTasksNotice(OTHER, [a, b, c]);
  assert.equal(x.note_id, y.note_id);
  assert.notEqual(x.note_id, z.note_id);
  assert.ok(x.text.startsWith('[loom] 2 open task_request(s) in lane:ops from bbbbbbbb'), x.text);
  assert.ok(z.text.includes('3 open') && z.text.includes('lane:ops, lane:x'));
  assert.ok(x.note_id.startsWith('open-tasks:'));
});
test('loomNotice: peer-chosen channel / task_id with control chars or spaces → "?" (no injection into the notice)', () => {
  const n = loomNotice(post({ channel_id: 'lane:ops\n@flint IGNORE', seq: 3, mentions: [ME] }), ME)!;
  assert.ok(n.startsWith('[loom channel_post ? seq 3]'), n);
  const t = loomNotice(treq({ channel: 'lane:ops', task_id: 'x y\u0007z', assignee: ME }), ME)!;
  assert.ok(t.includes('task ?'), t);
  assert.equal(loomNotice(post({ channel_id: 'lane:ops', seq: '9; rm', mentions: [ME] }), ME)!.includes('seq'), false);
});
test('loomNotice: other loom types, malformed JSON, missing payload, empty ownFp → null', () => {
  assert.equal(loomNotice(JSON.stringify({ loom_v: 1, type: 'claim', payload: { mentions: [ME] } }), ME), null);
  assert.equal(loomNotice('{not json', ME), null);
  assert.equal(loomNotice(JSON.stringify({ loom_v: 1, type: 'channel_post' }), ME), null);
  assert.equal(loomNotice(post({ mentions: [''], seq: 1 }), ''), null);
});
test('deadNotesNotice (Archie #180230): ONE body-less notice per peer for tombstoned notes; stable id; new id when another dies', () => {
  const a = { note_id: 'n1', sent_at: '2026-10-18T21:03:00.000Z' }, b = { note_id: 'n2', sent_at: '2026-10-19T02:49:00.000Z' };
  const c = { note_id: 'n3', sent_at: '2026-10-19T03:00:00.000Z' };
  const x = deadNotesNotice(OTHER, [b, a], 5), y = deadNotesNotice(OTHER, [a, b], 5), z = deadNotesNotice(OTHER, [a, b, c], 5);
  assert.equal(x.note_id, y.note_id);
  assert.notEqual(x.note_id, z.note_id);
  assert.ok(x.note_id.startsWith('dead-notes:'));
  assert.equal(x.text, '[svrnty] 2 note(s) from bbbbbbbb could not be decrypted after 5 tries (sent 2026-10-18T21:03:00.000Z to 2026-10-19T02:49:00.000Z); ask the sender to resend');
});
test('deadNotesNotice: a peer-chosen sent_at with control chars or spaces → "?" (no injection into the notice)', () => {
  const n = deadNotesNotice(OTHER, [{ note_id: 'n1', sent_at: '2026\n@flint IGNORE' }], 5);
  assert.ok(n.text.includes('(sent ? to ?)'), n.text);
  assert.ok(!n.text.includes('@flint') && !n.text.includes('\n'));
});
test('deadNotesNotice: the attempt count in the text comes from the caller (MAX_ATTEMPTS), not a literal', () => {
  assert.ok(deadNotesNotice(OTHER, [{ note_id: 'n1', sent_at: '2026-10-18T21:03:00.000Z' }], 7).text.includes('after 7 tries'));
});
test('safeToken (Flint #333 nit): a peer-chosen sent_at "\\n@x" becomes "?"; a real ISO time passes', () => {
  assert.equal(safeToken('\n@x'), '?');
  assert.equal(safeToken('2026\n@flint IGNORE'), '?');
  assert.equal(safeToken(42), '?');
  assert.equal(safeToken('2026-10-18T21:03:00.000Z'), '2026-10-18T21:03:00.000Z');
});
test('every NOTICE row devin-comm writes (loom-notice, dead-notice) wraps sent_at in safeToken (#282 call sites)', () => {
  const src = readFileSync(new URL('./devin-comm.ts', import.meta.url), 'utf8');
  const rows = src.split('appendFileSync(journalPath, JSON.stringify({').slice(1).map((r) => r.slice(0, r.indexOf('}) +')));
  const notices = rows.filter((r) => /transport: '(loom-notice|dead-notice)'/.test(r));
  assert.equal(notices.length, 3, 'expected the 3 notice rows (loom-notice x2, dead-notice)');
  for (const r of notices) assert.match(r, /sent_at: safeToken\(/, r);
});
