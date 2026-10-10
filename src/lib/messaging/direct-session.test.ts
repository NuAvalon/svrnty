// Run: npx tsx --test src/lib/messaging/direct-session.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isTripleRatchetBody, TRIPLE_RATCHET_BODY } from './direct-session';

test('isTripleRatchetBody only matches the 1:1 packet wrapper', () => {
  assert.equal(isTripleRatchetBody('hello'), false);
  assert.equal(isTripleRatchetBody('{"type":"svrnty-note-v0"}'), false);
  assert.equal(
    isTripleRatchetBody(JSON.stringify({ type: TRIPLE_RATCHET_BODY, packet: { header: {}, nonce: '', ct: '' } })),
    true,
  );
});
