// src/components/notes/notes-delivered-display.test.ts
//
// TG-1 anchor, part B (Hypatia #706, Flint #705): "Delivered" renders IFF note.delivered === true; every unverified 2xx path
// renders the floor "Sent to the relay". Part A (receipt-seam.test.ts) proves note.delivered is only ever set after a
// verified receipt; this proves the glass shows "Delivered" for nothing else. notes-status.test.ts already covers the pure
// functions; this adds the one link it cannot see: how the inbox turns a stored note into a status.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NOTES_COPY } from './notes-copy';
import { outboundStatus, statusLabel, statusIsHonest, peerSendsReceipts, showAwaitingHint, type NoteBubbleStatus } from './notes-status';

const here = dirname(fileURLToPath(import.meta.url));
const stripComments = (s: string) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');

test('the label is "Delivered" for the delivered status and for NOTHING else (every status, both deposit outcomes)', () => {
  const rows: Array<[boolean, boolean, NoteBubbleStatus, string]> = [
    [true, false, 'sent-unconfirmed', NOTES_COPY.sentToRelay],       // deposited 2xx, no verified receipt: on the relay
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
  for (const s of [NOTES_COPY.sentToRelay, NOTES_COPY.notSent, statusLabel('inbound')]) {
    assert.doesNotMatch(s, /\b(Delivered|Read|Expired)\b/);
  }
});

// ── "Awaiting delivery confirmation" must not be a promise the system cannot keep (Hypatia #745) ────────────────────
// Only the browser sends receipts: our agents never do, and a classical contact cannot (receipt-seam.test.ts A6). Every note
// carries a receipt_nonce, so without a per-PEER gate every message to an agent would say "Awaiting delivery confirmation" forever.

test('peerSendsReceipts: true only when an OUTBOUND note already carries a VERIFIED receipt (strict, derived from stored notes)', () => {
  assert.equal(peerSendsReceipts([]), false);
  assert.equal(peerSendsReceipts([{ direction: 'outbound' }, { direction: 'outbound', delivered: false }]), false, 'sent, never confirmed');
  assert.equal(peerSendsReceipts([{ direction: 'inbound', delivered: true }]), false, 'only OUTBOUND notes can be receipt-confirmed');
  assert.equal(peerSendsReceipts([{ direction: 'outbound', delivered: 1 }, { direction: 'outbound', delivered: 'true' }]), false, 'a truthy non-true value does not count');
  assert.equal(peerSendsReceipts([{ direction: 'outbound' }, { direction: 'outbound', delivered: true }]), true);
});

test('showAwaitingHint: the promise is made only for a deposited, nonce-stamped note to a peer who has proven it sends receipts', () => {
  const base = { outbound: true, status: 'sent-unconfirmed' as NoteBubbleStatus, hasReceiptNonce: true, peerSendsReceipts: true }; // 2xx floor; hint only if this peer already receipted
  assert.equal(showAwaitingHint(base), true);
  // an AGENT or classical contact (no receipt ever seen): the bare floor, no promise
  assert.equal(showAwaitingHint({ ...base, peerSendsReceipts: false }), false);
  // every other condition still has to hold
  assert.equal(showAwaitingHint({ ...base, hasReceiptNonce: false }), false, 'a note sent before the flow shipped can never get a receipt');
  assert.equal(showAwaitingHint({ ...base, outbound: false }), false);
  for (const status of ['delivered', 'not-sent', 'inbound'] as NoteBubbleStatus[]) assert.equal(showAwaitingHint({ ...base, status }), false, status);
});

test('the inbox gates the hint through showAwaitingHint with the per-peer fact, and never inlines its own condition', () => {
  const inbox = stripComments(readFileSync(join(here, 'NotesInbox.tsx'), 'utf8'));
  assert.match(inbox, /const peerReceipts = peerSendsReceipts\(notes\);/);
  assert.match(inbox, /showAwaitingHint\(\{[^}]*peerSendsReceipts:\s*peerReceipts[^}]*\}\)/);   // [^}] already spans newlines
  assert.doesNotMatch(inbox, /awaitingDelivery\s*=\s*outbound\s*&&/, 'the old inline per-note-only condition is gone');
});
