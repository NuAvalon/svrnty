// src/lib/relay/claim-registry.test.ts
// Layer (A) claim-registry — status-only (Archie bearer-not-registry): claimed-flag + per-mailbox
// redeemed-jti, keyed by mailbox_id ONLY (no fp / sub / token body). Idempotent re-claim.
// Distinct mailbox_ids per test (the registry is a process-global singleton — same posture as the store).
// Run: PATH=~/.nvm/versions/node/v22.22.1/bin:$PATH npx tsx --test claim-registry.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isMailboxClaimed, isJtiRedeemed, recordClaim } from './claim-registry';

test('unclaimed by default', () => {
  assert.equal(isMailboxClaimed('mbx_unseen'), false);
  assert.equal(isJtiRedeemed('mbx_unseen', 'j'), false);
});

test('recordClaim flips claimed + records the jti', () => {
  const mbx = 'mbx_A';
  recordClaim(mbx, 'jti-A');
  assert.equal(isMailboxClaimed(mbx), true);
  assert.equal(isJtiRedeemed(mbx, 'jti-A'), true);
  assert.equal(isJtiRedeemed(mbx, 'jti-OTHER'), false, 'a different jti is not redeemed');
  assert.equal(isMailboxClaimed('mbx_B'), false, 'a different mailbox stays unclaimed (per-mailbox status)');
});

test('idempotent: re-claim same mailbox (same or new jti) stays claimed, records jti', () => {
  const mbx = 'mbx_idem';
  recordClaim(mbx, 'jti-1');
  recordClaim(mbx, 'jti-1'); // re-present same jti → no-op, still claimed
  assert.equal(isMailboxClaimed(mbx), true);
  assert.equal(isJtiRedeemed(mbx, 'jti-1'), true);
  recordClaim(mbx, 'jti-2'); // a second token for an already-claimed mailbox → still claimed, jti recorded
  assert.equal(isJtiRedeemed(mbx, 'jti-2'), true);
  assert.equal(isMailboxClaimed(mbx), true);
});

test('status-only: the public API accepts ONLY (mailbox_id, jti) — no fp/sub/token surface', () => {
  // Compile-time + shape guarantee: recordClaim's signature is (mailboxId, jti) — there is no parameter
  // to pass an identity fp, a sub, or a token body. The registry cannot store a {token↔fp↔mailbox} map
  // because that data never reaches it. (Criterion-2 holds by construction; this test pins the surface.)
  assert.equal(recordClaim.length, 2, 'recordClaim takes exactly (mailboxId, jti) — no identity surface');
  assert.equal(isMailboxClaimed.length, 1, 'lookups are by mailbox_id only');
});
