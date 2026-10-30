// src/lib/sync/receipt-emit-flint.test.ts
// S62 slice 3 (Flint): a receipt is best-effort, so it must never sit on the path of the note it answers. Today the seam AWAITS the receipt
// POST (up to the 8 s timeout) before accept returns, i.e. before consume can ack that note. A slow relay then stretches the poll past its
// timeout, the stored notes are not acked, they redeliver, and each redelivery sends another receipt (each one a deposit against the same
// per-IP budget as the user's own sends). NEG-first: both tests fail on 14e42ed.
// Run: npx tsx --test src/lib/sync/receipt-emit-flint.test.ts
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { buildNoteSeam, type NoteSeamDeps } from './live-book-poll';
import { createReceiptOutbox } from './receipt-outbox';
import { lockSession } from '@/lib/identity/client-store';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import type { NoteWireV0, NoteRecord } from '@/lib/messaging/types';

// Flint #2100: the receipt outbox is module state (R3-2), and N6 and N7 both use note n1 for the same owner. Each case starts after a REAL session
// lock (the production clear-on-lock path, not a test-only reset), which also pins R3-2's "cleared on lock".
beforeEach(() => lockSession());

const OWNER = { fingerprint: 'ab'.repeat(32), publicKeyArmored: 'x', privateKeyArmored: 'y', passphrase: 'z' };
const WIRE: NoteWireV0 = { type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1', from_fingerprint: 'cd'.repeat(32), sent_at: '2026-10-30T12:00:00.000Z', body: 'hi', participant_kind: 'human', receipt_key: 'ab'.repeat(32) };
const REC = { note_id: 'n1', thread_id: 't1', from_fingerprint: WIRE.from_fingerprint } as NoteRecord;
const seam = (sendReceipt: (w: NoteWireV0) => Promise<void>) =>
  buildNoteSeam(OWNER, { openOwner: () => OWNER.fingerprint, accept: (async () => REC) as never } as NoteSeamDeps, undefined, sendReceipt);

test('N6 a receipt POST that never returns does not hold the note: accept resolves without waiting for it', async () => {
  let started = false;
  const s = seam(() => { started = true; return new Promise<void>(() => {}); }); // a relay that never answers
  const r = await Promise.race([s.accept(WIRE), new Promise((res) => setTimeout(() => res('TIMED-OUT'), 300))]);
  assert.notEqual(r, 'TIMED-OUT', 'accept must not wait on the receipt (it gates the ack of the note it answers)');
  assert.ok(r && typeof r === 'object' && 'note_id' in r);
  assert.ok(started, 'control: the receipt was still started');
});

test('N7 a note redelivered on the NEXT poll sends ONE receipt, not one per delivery (deps and the seam are rebuilt every tick)', async () => {
  let sent = 0;
  const hook = async () => { sent++; };
  await seam(hook).accept(WIRE); // tick 1: stored, receipt sent, ack lost
  await seam(hook).accept(WIRE); // tick 2: a fresh seam, the same note redelivered
  await new Promise((r) => setTimeout(r, 20)); // let a deferred send run
  assert.equal(sent, 1);
  await seam(hook).accept({ ...WIRE, note_id: 'n2' });
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(sent, 2, 'control: a different note still gets its receipt');
});

// ── R3-3 at the SEAM (Flint's gate, Apollo's wiring): a backlog of 12 accepted notes starts <= 4 receipt POSTs in the first 60 s, the rest later ──
test('N8 R3-3: 12 notes accepted at once => <= 4 receipt sends in the first 60 s; the rest start on later ticks (fake clock, injected outbox)', async () => {
  let t = 5_000_000;
  const outbox = createReceiptOutbox({ now: () => t });
  let sent = 0;
  const hook = async () => { sent++; };
  const mk = () => buildNoteSeam(OWNER, { openOwner: () => OWNER.fingerprint, accept: (async () => REC) as never, receipts: outbox } as NoteSeamDeps, undefined, hook);
  for (let i = 0; i < 12; i++) await mk().accept({ ...WIRE, note_id: `n${i}` });
  assert.equal(sent, 4, 'at most 4 in the first window');
  t += 60_000; outbox.pump();
  assert.equal(sent, 8);
  t += 60_000; outbox.pump();
  assert.equal(sent, 12, 'every note is still answered, later');
});

test('N9 R3-2 "cleared on lock", through the REAL path: a session lock drops queued receipts and forgets which notes were answered', async () => {
  let sent = 0;
  const hook = async () => { sent++; };
  const s = () => buildNoteSeam(OWNER, { openOwner: () => OWNER.fingerprint, accept: (async () => REC) as never } as NoteSeamDeps, undefined, hook);
  await s().accept(WIRE); // answered
  await s().accept(WIRE); // deduped
  assert.equal(sent, 1);
  lockSession(); // the user locks, or the identity switches: the next session starts clean
  await s().accept(WIRE);
  assert.equal(sent, 2, 'after a lock the same note is answered again (the dedupe set was cleared by the real hook)');
});

test('N10 R3-2 keying: the dedupe is per OWNER and note. Two identities on the same tab that receive a note with the SAME id each send their own receipt (a constant key would let one suppress the other)', async () => {
  let sent = 0;
  const hook = async () => { sent++; };
  const accept = (async () => REC) as never;
  const ownerA = { ...OWNER };
  const ownerB = { ...OWNER, fingerprint: 'ef'.repeat(32) };
  const seamFor = (o: typeof OWNER) => buildNoteSeam(o, { openOwner: () => o.fingerprint, accept } as NoteSeamDeps, undefined, hook);
  await seamFor(ownerA).accept(WIRE);
  await seamFor(ownerB).accept(WIRE);
  assert.equal(sent, 2);
  await seamFor(ownerA).accept(WIRE); // and each is still deduped against itself
  assert.equal(sent, 2);
});
