// src/lib/sync/note-seam-receipt-order.test.ts
// S62 contract v6 done_when 2 + 4 at the SEAM that decides when a receipt may leave: only AFTER the durable store, never for a dropped note.
// Run: npx tsx --test src/lib/sync/note-seam-receipt-order.test.ts
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { buildNoteSeam, type NoteSeamDeps } from './live-book-poll';
import { lockSession } from '@/lib/identity/client-store';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import type { NoteWireV0, NoteRecord } from '@/lib/messaging/types';

// The receipt outbox is module state (one receipt per owner+note, S62 R3-2): every case starts from a clean one.
beforeEach(() => lockSession()); // the REAL clear-on-lock path (Flint #2100)

const OWNER = { fingerprint: 'ab'.repeat(32), publicKeyArmored: 'x', privateKeyArmored: 'y', passphrase: 'z' };
const WIRE: NoteWireV0 = { type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1', from_fingerprint: 'cd'.repeat(32), sent_at: '2026-10-30T12:00:00.000Z', body: 'hi', participant_kind: 'human', receipt_key: 'ab'.repeat(32) };
const REC = { note_id: 'n1', thread_id: 't1', from_fingerprint: WIRE.from_fingerprint } as NoteRecord;

function seam(accept: NoteSeamDeps['accept'], log: string[], sendReceipt: (w: NoteWireV0) => Promise<void>, over: Partial<NoteSeamDeps> = {}) {
  const deps: NoteSeamDeps = { openOwner: () => OWNER.fingerprint, accept, isAdmittedNow: async () => true, ...over };
  return buildNoteSeam(OWNER, deps, undefined, sendReceipt);
}
// #714 R1: a receipt is queued only for the delivery that CREATED the note row; the real acceptInboundNote reports that through args.onCreated.
const createdBy = (rec: NoteRecord, pre?: () => Promise<void>) => (async (a: { onCreated?: () => void }) => { await pre?.(); a.onCreated?.(); return rec; }) as never;
const settle = () => new Promise((r) => setTimeout(r, 20)); // the send re-checks the contact at send time, so it starts a few ticks after accept returns

test('N1 a stored note: the receipt is sent exactly once, and only AFTER accept (the durable store) has returned', async () => {
  const log: string[] = [];
  const s = seam(createdBy(REC, async () => { await new Promise((r) => setTimeout(r, 20)); log.push('stored'); }), log, async () => { log.push('receipt'); });
  const r = await s.accept(WIRE);
  assert.ok(r && 'note_id' in r);
  await settle();
  assert.deepEqual(log, ['stored', 'receipt']);
});

test('N2 done_when 2: a store that FAILS (accept throws) sends no receipt and leaves the note retryable (the throw propagates)', async () => {
  const log: string[] = [];
  const s = seam((async () => { throw new Error('IndexedDB write failed'); }) as never, log, async () => { log.push('receipt'); });
  await assert.rejects(() => s.accept(WIRE), /IndexedDB/);
  assert.deepEqual(log, []);
});

test('N3 done_when 4: a dropped note (unsigned / forged / stranger / not-in-book) sends NO receipt, for every drop reason', async () => {
  for (const reason of ['unverified', 'not-in-book', 'ratchet-unopenable'] as const) {
    const log: string[] = [];
    const s = seam((async (a: { onDrop?: (r: typeof reason) => void }) => { a.onDrop?.(reason); return null; }) as never, log, async () => { log.push('receipt'); });
    await s.accept(WIRE);
    assert.deepEqual(log, [], reason);
  }
});

test('N4 a receipt hook that THROWS or REJECTS never fails the note: it is still returned as accepted', async () => {
  for (const hook of [async () => { throw new Error('relay down'); }, () => Promise.reject(new Error('x'))]) {
    const origErr = console.error; console.error = () => {};
    try {
      const s = seam(createdBy(REC), [], hook as never);
      const r = await s.accept(WIRE);
      assert.ok(r && 'note_id' in r && r.note_id === 'n1');
      await settle();
    } finally { console.error = origErr; }
  }
});

// ── #714 R1: created-only emission, and the block re-check at SEND ──
test('R1-a a REDELIVERY (accept returns the stored note without reporting a creation) sends NO receipt', async () => {
  const log: string[] = [];
  const s = seam((async () => REC) as never, log, async () => { log.push('receipt'); });
  const r = await s.accept(WIRE);
  assert.ok(r && 'note_id' in r, 'the redelivered note is still acked (returned as accepted)');
  await settle();
  assert.deepEqual(log, []);
});
test('R1-b the same blob delivered twice: the first (creating) delivery sends ONE receipt, the second sends none', async () => {
  const log: string[] = [];
  let first = true;
  const s = seam((async (a: { onCreated?: () => void }) => { if (first) { first = false; a.onCreated?.(); } return REC; }) as never, log, async () => { log.push('receipt'); });
  await s.accept(WIRE);
  await s.accept(WIRE);
  await settle();
  assert.deepEqual(log, ['receipt']);
});
test('R1-c G2: a contact BLOCKED after accept but before the queued send starts gets NO receipt (the contact is re-read when the send RUNS)', async () => {
  // The outbox may hold a receipt behind its rate window; model that with a queue the test drains by hand.
  for (const [blockInWindow, want] of [[true, []], [false, ['receipt']]] as const) {
    const log: string[] = [];
    let admitted = true;
    const queued: Array<() => Promise<unknown>> = [];
    const receipts = { enqueue: (_o: string, _n: string, send: () => Promise<unknown>) => void queued.push(send) } as never;
    const s = seam(createdBy(REC), log, async () => { log.push('receipt'); }, { isAdmittedNow: async () => admitted, receipts });
    await s.accept(WIRE);
    assert.equal(queued.length, 1, 'one receipt is queued for the creating delivery');
    assert.deepEqual(log, [], 'and nothing has left yet');
    if (blockInWindow) admitted = false; // the user blocks them in the window between the accept and the send
    await queued[0]();
    assert.deepEqual(log, want, blockInWindow ? 'blocked in the window: nothing leaves' : 'control: still admitted, the receipt leaves');
  }
});
test('R1-d G2 control: still admitted at send time => the receipt goes; and a re-check that THROWS sends nothing and never fails the note', async () => {
  const log: string[] = [];
  const ok = seam(createdBy(REC), log, async () => { log.push('receipt'); });
  await ok.accept(WIRE);
  await settle();
  assert.deepEqual(log, ['receipt']);
  lockSession();
  const log2: string[] = [];
  const origErr = console.error; console.error = () => {};
  try {
    const bad = seam(createdBy(REC), log2, async () => { log2.push('receipt'); }, { isAdmittedNow: async () => { throw new Error('contacts locked'); } });
    const r = await bad.accept(WIRE);
    assert.ok(r && 'note_id' in r);
    await settle();
  } finally { console.error = origErr; }
  assert.deepEqual(log2, []);
});

// ── v7 binding constraint: no outbound traffic triggered or addressed by an UNAUTHENTICATED claim (Flint #2059, Archie v7, Hypatia TG-1 v1_3) ──
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { signNoteWire } from '@/lib/messaging/note-auth';
import { acceptInboundNote } from '@/lib/messaging/transport';
import { emitDeliveredReceipt } from '@/lib/messaging/receipt-emit';
import { newReceiptKey, receiptKeyToHex } from '@/lib/crypto/receipt-mac';

async function mintId() {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass, kem: id.pq_kem_public_key, sig: id.pq_sig_public_key };
}

test('N5 v7 NEG: a forged note NAMING an admitted book contact (valid shape, failing signature) produces ZERO outbound deposits; the same note, genuine, produces exactly one', async () => {
  const [A, B] = [await mintId(), await mintId()]; // A = the contact in B's book; B = this device
  const unsigned: NoteWireV0 = { type: NOTE_WIRE_TYPE, note_id: 'n-forge', thread_id: 't1', from_fingerprint: A.fp, sent_at: '2026-10-30T12:00:00.000Z', body: 'genuine body', participant_kind: 'agent', receipt_key: receiptKeyToHex(newReceiptKey()) };
  const genuine = await signNoteWire(unsigned, A.pub, A.priv, A.kpass, A.kem, A.sig);
  const forged: NoteWireV0 = { ...genuine, body: 'attacker-chosen body' }; // content changed after A signed: the signature no longer verifies
  const posts: string[] = [];
  const fetchImpl = (async (url: string) => { posts.push(String(url)); return new Response('{"ok":true}', { status: 200 }); }) as unknown as typeof fetch;
  const io = { putNote: async () => {}, putThread: async () => {}, listThreads: async () => [], getNote: async () => null };
  const deps: NoteSeamDeps = {
    openOwner: () => OWNER.fingerprint,
    // the REAL acceptInboundNote (real signature check); only storage is stubbed, and A is ADMITTED, exactly the forger's target
    accept: ((args: Parameters<typeof acceptInboundNote>[0]) => acceptInboundNote({ ...args, isAdmitted: async (fp) => fp === A.fp, io })) as never,
    isAdmittedNow: async (fp) => fp === A.fp,
  };
  const seamB = buildNoteSeam({ ...OWNER, fingerprint: B.fp } as never, { ...deps, openOwner: () => B.fp }, undefined, async (w) => { await emitDeliveredReceipt(w, { fetchImpl }); });
  const r = await seamB.accept(forged);
  assert.ok(r === null || 'dropped' in r, 'the forged note is dropped');
  await new Promise((res) => setTimeout(res, 150)); // the receipt is no longer awaited by accept, so give any (wrongly) started deposit time to land
  assert.deepEqual(posts, [], 'ZERO outbound deposits for a forged claim, even though its named sender IS in the book');
  const ok = await seamB.accept(genuine);
  assert.ok(ok && 'note_id' in ok, 'the genuine note is accepted');
  for (let i = 0; i < 100 && posts.length < 1; i++) await new Promise((res) => setTimeout(res, 30)); // the deposit now happens AFTER accept returned (R3-1)
  await new Promise((res) => setTimeout(res, 150));
  assert.equal(posts.length, 1, 'and answered exactly once');
});
