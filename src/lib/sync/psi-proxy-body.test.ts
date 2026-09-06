// NEGATIVE: device-local tags/blocked/group labels never copy onto the PSI proxy body.
// Run: npx tsx --test src/lib/sync/psi-proxy-body.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pickPsiBody } from './psi-proxy-body';

test('NEGATIVE: pickPsiBody drops tags, blocked, group labels, and metadata', () => {
  const forwarded = pickPsiBody({
    initiator_fingerprint: 'aa'.repeat(32),
    responder_fingerprint: 'bb'.repeat(32),
    blinded_set: ['x', 'y'],
    signature: '1:sig',
    tags: ['family', 'secret-group-label'],
    blocked: true,
    metadata: { tags: ['family'], blocked: true, notes: 'nope' },
    disclosed_circle: ['ghost'],
    they_trust: ['ghost'],
    group: 'book-club',
  });
  assert.deepEqual(Object.keys(forwarded).sort(), [
    'blinded_set',
    'initiator_fingerprint',
    'responder_fingerprint',
    'signature',
  ]);
  const json = JSON.stringify(forwarded);
  assert.equal(json.includes('family'), false);
  assert.equal(json.includes('secret-group-label'), false);
  assert.equal(json.includes('blocked'), false);
  assert.equal(json.includes('book-club'), false);
  assert.equal(json.includes('disclosed_circle'), false);
});
