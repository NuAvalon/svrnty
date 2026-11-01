// Run: npx tsx --test src/components/notes/notes-status.test.ts
//
// Honesty-guard enforcement (Flint [[green-only-if-enforced]], delivered-receipt req #3): "Delivered"
// may render ONLY for a VERIFIED delivered status. Every unverified path stays the floor.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { outboundStatus, statusLabel, statusIsHonest, statusIsHonestFloor } from './notes-status.js';
import { NOTES_COPY } from './notes-copy.js';

test('outboundStatus: delivered ONLY when the verified flag is true; else the floor', () => {
  assert.equal(outboundStatus(true, false), 'sent-unconfirmed');
  assert.equal(outboundStatus(false, false), 'not-sent');
  assert.equal(outboundStatus(true), 'sent-unconfirmed'); // default delivered=false
  assert.equal(outboundStatus(true, true), 'delivered');
  assert.equal(outboundStatus(false, true), 'delivered');
});

test('statusLabel maps delivered → the delivered copy; floor otherwise', () => {
  assert.equal(statusLabel('delivered'), NOTES_COPY.delivered);
  assert.equal(statusLabel('sent-unconfirmed'), NOTES_COPY.sentToRelay);
  assert.equal(statusLabel('not-sent'), NOTES_COPY.notSent);
  assert.equal(statusLabel('inbound'), '');
});

test('statusIsHonest: "Delivered" is honest ONLY for the verified delivered status (Flint 3-case)', () => {
  // valid receipt → delivered status + delivered copy → honest
  assert.equal(statusIsHonest('delivered', NOTES_COPY.delivered), true);
  // no-receipt → floor status + floor copy → honest
  assert.equal(statusIsHonest('sent-unconfirmed', NOTES_COPY.sentToRelay), true);
  assert.equal(statusIsHonest('not-sent', NOTES_COPY.notSent), true);
  // forged/unverified trying to show Delivered on a NON-delivered status → DISHONEST (rejected → floor)
  assert.equal(statusIsHonest('sent-unconfirmed', 'Delivered'), false);
  assert.equal(statusIsHonest('sent-unconfirmed', NOTES_COPY.delivered), false);
  assert.equal(statusIsHonest('not-sent', NOTES_COPY.delivered), false);
  // delivered status cannot smuggle Read/Expired or any non-delivered text
  assert.equal(statusIsHonest('delivered', 'Read'), false);
  assert.equal(statusIsHonest('delivered', 'Expired'), false);
  assert.equal(statusIsHonest('delivered', 'Delivered · Read'), false);
});

test('statusIsHonestFloor (back-compat): the pure floor still forbids Delivered/Read/Expired', () => {
  assert.equal(statusIsHonestFloor('Delivered'), false);
  assert.equal(statusIsHonestFloor('Read'), false);
  assert.equal(statusIsHonestFloor('Expired'), false);
  assert.equal(statusIsHonestFloor(NOTES_COPY.sentToRelay), true);
  assert.equal(statusIsHonestFloor(NOTES_COPY.notSent), true);
  assert.equal(statusIsHonestFloor(NOTES_COPY.delivered), false); // 'Delivered' rejected by the pure floor
});
