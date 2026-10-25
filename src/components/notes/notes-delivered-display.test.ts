// src/components/notes/notes-delivered-display.test.ts
//
// TG-1 anchor, part B (Hypatia #706, Flint #705): "Delivered" renders IFF note.delivered === true; every unverified path
// renders the floor "Sent · unconfirmed.". Part A (receipt-seam.test.ts) proves note.delivered is only ever set after a
// verified receipt; this proves the glass shows "Delivered" for nothing else. notes-status.test.ts already covers the pure
// functions; this adds the one link it cannot see: how the inbox turns a stored note into a status.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NOTES_COPY } from './notes-copy';
import { outboundStatus, statusLabel, statusIsHonest, type NoteBubbleStatus } from './notes-status';

const here = dirname(fileURLToPath(import.meta.url));
const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');

test('the label is "Delivered" for the delivered status and for NOTHING else (every status, both deposit outcomes)', () => {
  const rows: Array<[boolean, boolean, NoteBubbleStatus, string]> = [
    [true, false, 'sent-unconfirmed', NOTES_COPY.sentUnconfirmed],   // deposited, no verified receipt: the floor
    [false, false, 'not-sent', NOTES_COPY.notSent],                  // never deposited: not sent
    [true, true, 'delivered', NOTES_COPY.delivered],                 // only a verified receipt graduates it
  ];
  for (const [deposited, deliveredFlag, status, label] of rows) {
    assert.equal(outboundStatus(deposited, deliveredFlag), status);
    assert.equal(statusLabel(status), label);
    assert.equal(statusIsHonest(status, label), true);
    assert.equal(/\bDelivered\b/.test(label), status === 'delivered', `"Delivered" only for the delivered status (${status})`);
  }
  // the floor strings can never be passed off as honest for a delivered claim, nor "Delivered" for a floor status
  assert.equal(statusIsHonest('sent-unconfirmed', NOTES_COPY.delivered), false);
  assert.equal(statusIsHonest('not-sent', NOTES_COPY.delivered), false);
  assert.equal(statusIsHonest('inbound', NOTES_COPY.delivered), false);
  assert.equal(statusLabel('inbound'), '');
});

test('the inbox derives the status from note.delivered === true (STRICT), in exactly one place', () => {
  const inbox = stripComments(readFileSync(join(here, 'NotesInbox.tsx'), 'utf8'));
  const calls = inbox.match(/outboundStatus\(/g) ?? [];
  assert.equal(calls.length, 1, 'one call site derives the outbound status');
  assert.match(inbox, /outboundStatus\(\s*true\s*,\s*note\.delivered\s*===\s*true\s*\)/, 'a truthy non-true value (1, "yes", {}) must NOT read as delivered');
  assert.doesNotMatch(inbox, /status\s*[:=]\s*['"]delivered['"]/, 'no other path assigns the delivered status');
  assert.doesNotMatch(inbox, /['"]Delivered['"]/, 'the word is never hard-coded in the component: it only comes from statusLabel');
});

test('no unverified status string can carry a live-delivery word', () => {
  for (const s of [NOTES_COPY.sentUnconfirmed, NOTES_COPY.notSent, statusLabel('inbound')]) {
    assert.doesNotMatch(s, /\b(Delivered|Read|Expired)\b/);
  }
});
