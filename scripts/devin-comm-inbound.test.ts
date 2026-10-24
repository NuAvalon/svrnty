// Run: npx tsx --test scripts/devin-comm-inbound.test.ts
// classifyInbound must match devin_quarantine.py _is_protocol_body: only TR packets and loom
// envelopes are protocol; everything else is a readable PLAIN note that poll-json must journal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyInbound, routeInbound, TR_BODY } from './devin-comm-inbound';

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
