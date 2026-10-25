// src/lib/sync/consume-mailbox-receipt.test.ts
// DELIVERY-RECEIPT ROUTING (svrnty-receipt-v0) — the mailbox's FIFTH inbound type. Proves consumeOne
// routes a receipt by its OWN type-checked verify (the receipt seam) BEFORE the contact-update
// fall-through — so the always-on living-book poll does NOT eat + ack-delete a delivery receipt (the
// silent-loss). Mirrors consume-mailbox-note.test.ts: the receipt seam is INJECTED (fake verify/accept)
// to prove the CONTROL FLOW; the receipt crypto round-trip is covered by delivery-receipt.test.ts, and
// the seal-layer discriminator by the real-crypto test at the bottom.
//
// ★ THE INVARIANT THIS GUARDS (Flint carry-forward): a receipt outcome fires ONLY when the seam's accept
// returns non-null — i.e. the sender-side buildReceiptSeam verified the recipient's signature against the
// stored outbound note. summary.delivered++ (→ note.delivered=true) is UNREACHABLE for a dropped receipt.
//
// Run: PATH=~/.nvm/versions/node/v22.22.1/bin:$PATH npx tsx --test consume-mailbox-receipt.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import {
  consumeInboundContactUpdates,
  type ConsumeDeps,
  type ReceiptResponseSeam,
  type ReceiptLiveEvent,
  type NoteResponseSeam,
} from './consume-mailbox';
import type { NoteWireV0 } from '@/lib/messaging/types';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import { RECEIPT_WIRE_TYPE, type ReceiptWireV0 } from '@/lib/crypto/delivery-receipt';
import { noteOpenpgpDecryptor, sealReceiptTo, receiptOpenpgpDecryptor } from '@/lib/messaging/seal';
import { sealNoteClassicalFixture } from '@/lib/messaging/seal-classical-fixture';

// The owner (Alice, the ORIGINAL SENDER polling for receipts) needs REAL keys — consumeInboundContactUpdates
// signs the poll/ack requests with them.
let OWNER: { fingerprint: string; publicKeyArmored: string; privateKeyArmored: string; passphrase: string };
before(async () => {
  const passphrase = 'pw-alice';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart — 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name: 'alice', email: 'alice@x.test' }],
    passphrase,
    format: 'armored',
  });
  const fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  OWNER = { fingerprint, publicKeyArmored: publicKey, privateKeyArmored: privateKey, passphrase };
});

function recordingFetch(envelopes: Array<{ envelope_id: string; blob: string }>, ackLog: string[][]): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/queue')) {
      return new Response(JSON.stringify(envelopes), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (String(url).includes('/ack')) {
      ackLog.push(JSON.parse(String(init?.body ?? '{}')).envelope_ids);
      return new Response(JSON.stringify({ deleted: 1 }), { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
}

function fakeReceiptWire(from = 'BOBFP'): ReceiptWireV0 {
  return { type: RECEIPT_WIRE_TYPE, note_id: 'n1', nonce: 'deadbeef', from_fingerprint: from, sig: 'aa'.repeat(80) };
}

function fakeNoteWire(from = 'BOBFP'): NoteWireV0 {
  return {
    type: NOTE_WIRE_TYPE,
    note_id: 'n1',
    thread_id: 't1',
    from_fingerprint: from,
    sent_at: '2026-10-09T00:00:00.000Z',
    body: 'hello over the wire',
    participant_kind: 'human',
  };
}

function baseDeps(overrides: Partial<ConsumeDeps>): ConsumeDeps {
  return {
    owner: OWNER,
    decrypt: async () => null,
    store: { lookup: async () => null, persist: async () => {} },
    relayBase: 'http://relay.test/api/relay',
    now: () => '2026-10-09T00:00:00.000Z',
    ...overrides,
  };
}

// ── A verified receipt is routed to the receipt seam and NEVER falls through to contact-update ──
test('routes a delivery receipt via the receipt seam (verify-first) — delivered + acked, no fall-through', async () => {
  let decryptCalls = 0;
  const confirmedNotes: string[] = [];
  const emitted: ReceiptLiveEvent[] = [];
  const ackLog: string[][] = [];

  const receipt: ReceiptResponseSeam = {
    verify: async (blob) => (blob === 'RECEIPT_BLOB' ? fakeReceiptWire() : null),
    accept: async (w) => { confirmedNotes.push(w.note_id); return { note_id: w.note_id, thread_id: 't1', from_fingerprint: w.from_fingerprint }; },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; }, // MUST NOT be reached for the receipt blob
    receipt,
    emitReceipt: (e) => emitted.push(e),
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'RECEIPT_BLOB' }], ackLog),
  }));

  assert.deepEqual(confirmedNotes, ['n1'], 'the receipt seam verified + marked the note delivered');
  assert.equal(decryptCalls, 0, 'the contact-update decryptor was NOT invoked — routed by receipt-verify, not decrypt');
  assert.equal(summary.delivered, 1, 'the receipt graduated one outbound note to Delivered');
  assert.equal(summary.applied, 0, 'a receipt is NOT a contact-book apply');
  assert.equal(summary.acked, 1, 'the consumed receipt envelope is acked (not re-polled)');
  assert.deepEqual(ackLog, [['e1']]);
  assert.equal(emitted.length, 1, 'the inbox repaints the delivered status');
  assert.deepEqual(emitted[0], { note_id: 'n1', thread_id: 't1', from_fingerprint: 'BOBFP' });
});

// ── A dropped receipt (accept → null: unknown note / forged / unverifiable recipient) → terminal, NO delivered ──
test('a dropped receipt (accept → null) is acked terminally — floor holds, NO false delivered, no repaint', async () => {
  const emitted: ReceiptLiveEvent[] = [];
  const ackLog: string[][] = [];
  const receipt: ReceiptResponseSeam = {
    verify: async () => fakeReceiptWire('FORGERFP'),
    accept: async () => null, // no matching note / verifyReceiptWire false — silent I-1 (floor 'Sent · unconfirmed.' holds)
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    receipt,
    emitReceipt: (e) => emitted.push(e),
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'RECEIPT_BLOB' }], ackLog),
  }));

  assert.equal(summary.delivered, 0, '★ a dropped/forged receipt NEVER marks a note delivered (the honesty invariant)');
  assert.equal(summary.dropped, 1, 'dropped (terminal)');
  assert.deepEqual(ackLog, [['e1']], 'still acked (clean up invalid mail silently — no oracle)');
  assert.equal(emitted.length, 0, 'no delivered-repaint for a dropped receipt');
});

// ── A store failure while marking a VERIFIED note delivered → RETRYABLE: left in the mailbox, NOT acked ──
test('a store failure marking a verified note delivered is retryable (left in the mailbox)', async () => {
  const ackLog: string[][] = [];
  const receipt: ReceiptResponseSeam = {
    verify: async () => fakeReceiptWire(),
    accept: async () => { throw new Error('IndexedDB putNote failed'); },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    receipt,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'RECEIPT_BLOB' }], ackLog),
  }));

  assert.equal(summary.delivered, 0);
  assert.equal(summary.acked, 0, 'a retryable receipt is NOT acked — it redelivers next poll (at-least-once; putNote idempotent)');
  assert.deepEqual(ackLog, []);
});

// ── A non-receipt blob (receipt-verify → null) FALLS THROUGH to the contact-update path ──
test('a blob the receipt-verify rejects falls through to the contact-update path', async () => {
  let decryptCalls = 0;
  const ackLog: string[][] = [];
  const receipt: ReceiptResponseSeam = {
    verify: async () => null, // not a receipt → must fall through
    accept: async () => { throw new Error('accept must never be called on a null verify'); },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; }, // reached via fall-through; null → terminal drop
    receipt,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'CONTACT_UPDATE_BLOB' }], ackLog),
  }));

  assert.equal(decryptCalls, 1, 'fell through to the contact-update decryptor — the receipt seam did not eat it');
  assert.equal(summary.delivered, 0);
  assert.equal(summary.dropped, 1);
  assert.deepEqual(ackLog, [['e1']]);
});

// ── A throwing receipt-verify on hostile input → treated as not-a-receipt → falls through (fail-safe) ──
test('a throwing receipt-verify is treated as null and falls through (fail-safe)', async () => {
  let decryptCalls = 0;
  const ackLog: string[][] = [];
  const receipt: ReceiptResponseSeam = {
    verify: async () => { throw new Error('malformed blob blew up receipt-verify'); },
    accept: async () => { throw new Error('accept must not be reached'); },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; },
    receipt,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'HOSTILE' }], ackLog),
  }));

  assert.equal(decryptCalls, 1, 'a throwing receipt-verify does not wedge — it falls through to contact-update');
  assert.equal(summary.dropped, 1);
});

// ── NO-CROSS-SWALLOW: note + receipt + contact-update in ONE poll, each routed to its own seam ──
test('no-cross-swallow: note→note, receipt→receipt, contact-update→contact — none eaten', async () => {
  const noteFroms: string[] = [];
  const receiptNotes: string[] = [];
  let contactDecryptCalls = 0;
  const ackLog: string[][] = [];

  const note: NoteResponseSeam = {
    verify: async (blob) => (blob === 'NOTE' ? fakeNoteWire('BOBFP') : null),
    accept: async (w) => { noteFroms.push(w.from_fingerprint); return { note_id: w.note_id, thread_id: w.thread_id, from_fingerprint: w.from_fingerprint }; },
  };
  const receipt: ReceiptResponseSeam = {
    verify: async (blob) => (blob === 'RECEIPT' ? fakeReceiptWire('BOBFP') : null),
    accept: async (w) => { receiptNotes.push(w.note_id); return { note_id: w.note_id, thread_id: 't1', from_fingerprint: w.from_fingerprint }; },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    note,
    receipt,
    decrypt: async () => { contactDecryptCalls++; return null; }, // ONLY the contact-update blob reaches here
    fetchImpl: recordingFetch([
      { envelope_id: 'n', blob: 'NOTE' },
      { envelope_id: 'r', blob: 'RECEIPT' },
      { envelope_id: 'c', blob: 'CONTACT' },
    ], ackLog),
  }));

  assert.deepEqual(noteFroms, ['BOBFP'], 'the note routed to the note seam only');
  assert.deepEqual(receiptNotes, ['n1'], 'the receipt routed to the receipt seam only');
  assert.equal(contactDecryptCalls, 1, 'ONLY the contact-update blob reached the contact decryptor — neither note nor receipt was swallowed by it');
  assert.equal(summary.notes, 1, 'the note persisted');
  assert.equal(summary.delivered, 1, 'the receipt graduated a note');
  assert.equal(summary.dropped, 1, 'the contact-update (null decrypt) dropped terminally');
  assert.equal(summary.acked, 3, 'all three consumed + acked — no cross-swallow, no loss');
});

// ── REAL-CRYPTO DISCRIMINATOR: the seal layer never cross-swallows a note vs a receipt ──
// A receipt is sealed with the SAME openpgp envelope as a note, so at the relay they are
// byte-indistinguishable; the ONLY discriminator is the inner `type`, checked by each decryptor.
test('real crypto: receipt/note decryptors round-trip their own type and reject the other (no cross-swallow)', async () => {
  const receipt = fakeReceiptWire(OWNER.fingerprint);
  const note = fakeNoteWire(OWNER.fingerprint);
  const receiptBlob = await sealReceiptTo(receipt, OWNER.publicKeyArmored);
  const noteBlob = await sealNoteClassicalFixture(note, OWNER.publicKeyArmored);

  const decReceipt = receiptOpenpgpDecryptor(OWNER.privateKeyArmored, OWNER.passphrase);
  const decNote = noteOpenpgpDecryptor(OWNER.privateKeyArmored, OWNER.passphrase);

  // Each decryptor opens its OWN type…
  const asReceipt = await decReceipt(receiptBlob);
  assert.ok(asReceipt, 'a real sealed receipt decrypts to a ReceiptWireV0 via the receipt decryptor');
  assert.equal(asReceipt?.type, RECEIPT_WIRE_TYPE);
  assert.equal(asReceipt?.note_id, 'n1');
  assert.equal(asReceipt?.nonce, 'deadbeef');

  const asNote = await decNote(noteBlob);
  assert.equal(asNote?.type, NOTE_WIRE_TYPE);

  // …and returns null for the OTHER type (the cross-swallow guard — the 5-way routing depends on it).
  assert.equal(await decReceipt(noteBlob), null, 'the receipt decryptor returns null for a note blob → falls through, never eaten as a receipt');
  assert.equal(await decNote(receiptBlob), null, 'the note decryptor returns null for a receipt blob → falls through, never eaten as a note');

  // sealReceiptTo refuses a non-receipt wire (domain guard, mirrors sealNoteTo).
  await assert.rejects(
    () => sealReceiptTo(note as unknown as ReceiptWireV0, OWNER.publicKeyArmored),
    /refusing non-receipt wire type/,
    'sealReceiptTo refuses a non-receipt wire type',
  );
});
