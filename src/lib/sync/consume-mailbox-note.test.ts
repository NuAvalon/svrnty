// src/lib/sync/consume-mailbox-note.test.ts
// OVER-WIRE NOTE ROUTING (svrnty-note-v0) — the mailbox's THIRD inbound type. Proves consumeOne routes
// a note by its OWN type-checked verify (the note seam) FIRST — so the always-on living-book poll does
// NOT eat + ack-delete over-wire notes (the silent-loss). Mirrors consume-mailbox-joiner.test.ts: the
// note seam is INJECTED (fake verify/accept) to prove the CONTROL FLOW; the real note crypto round-trip
// is covered by note-auth.test.ts + the real-crypto discriminator test at the bottom of this file.
//
// THE REGRESSION IT GUARDS: without the note seam, a note decrypts NON-NULL via the contact-update
// decryptor, then drops on its missing `envelope.fingerprint` → terminal → ack-DELETED (lost). The
// "silent-loss WITHOUT the seam" test below reproduces that exactly; every other test proves the fix.
//
// Run: PATH=~/.nvm/versions/node/v22.22.1/bin:$PATH npx tsx --test consume-mailbox-note.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { consumeInboundContactUpdates, type ConsumeDeps, type NoteResponseSeam, type NoteLiveEvent, type JoinerResponseSeam } from './consume-mailbox';
import type { NoteWireV0 } from '@/lib/messaging/types';
import type { PendingJoiner } from '@/lib/trust/joiner-response';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import { sealNoteTo, noteOpenpgpDecryptor } from '@/lib/messaging/seal';

// The owner (Alice) needs REAL keys — consumeInboundContactUpdates signs the poll/ack requests with them.
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

function pendingJoinerLite(fp = 'BOBFP'): PendingJoiner {
  return { fingerprint: fp, epoch: 0, publicKeyArmored: 'BOBPUB', displayName: 'Bob', inviteNonce: 'CODE1', ts: '2026-10-09T00:00:00Z' };
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

// ── A note is routed to the note seam and NEVER falls through to contact-update (the fix) ──
test('routes an over-wire note via the note seam (verify-first) — persisted + acked, no fall-through', async () => {
  let decryptCalls = 0;
  const acceptedFrom: string[] = [];
  const emittedNotes: NoteLiveEvent[] = [];
  const ackLog: string[][] = [];

  const note: NoteResponseSeam = {
    verify: async (blob) => (blob === 'NOTE_BLOB' ? fakeNoteWire() : null),
    accept: async (w) => { acceptedFrom.push(w.from_fingerprint); return { note_id: w.note_id, thread_id: w.thread_id, from_fingerprint: w.from_fingerprint }; },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; }, // MUST NOT be reached for the note blob
    note,
    emitNote: (e) => emittedNotes.push(e),
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'NOTE_BLOB' }], ackLog),
  }));

  assert.deepEqual(acceptedFrom, ['BOBFP'], 'the note seam accepted the note (routed to the note path)');
  assert.equal(decryptCalls, 0, 'the contact-update decryptor was NOT invoked — routed by note-verify, not decrypt');
  assert.equal(summary.notes, 1, 'the note is counted as persisted');
  assert.equal(summary.applied, 0, 'a note is NOT a contact-book apply');
  assert.equal(summary.acked, 1, 'the consumed note envelope is acked (not re-polled)');
  assert.deepEqual(ackLog, [['e1']]);
  assert.equal(emittedNotes.length, 1, 'the inbox repaints on a persisted note');
  assert.deepEqual(emittedNotes[0], { note_id: 'n1', thread_id: 't1', from_fingerprint: 'BOBFP' });
});

// ── REGRESSION: WITHOUT the note seam, a note-shaped decrypt is EATEN (the silent-loss this fix closes) ──
test('without the note seam, a note-shaped blob is silently dropped + acked (the loss the fix closes)', async () => {
  const ackLog: string[][] = [];
  // A real note decrypts NON-NULL via the contact-update decryptor but lacks `envelope.fingerprint`.
  // Simulate that exact shape; with no note seam it hits the :246 shape check → terminal → acked = LOST.
  const summary = await consumeInboundContactUpdates(baseDeps({
    // no `note` seam
    decrypt: async () => ({ type: NOTE_WIRE_TYPE, body: 'hi', from_fingerprint: 'BOBFP' } as unknown as never),
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'NOTE_BLOB' }], ackLog),
  }));

  assert.equal(summary.notes, 0, 'no note persisted — the note never reached an inbox');
  assert.equal(summary.dropped, 1, 'the note is classified terminal (dropped) by the contact-update path');
  assert.deepEqual(ackLog, [['e1']], 'and ACK-DELETED — gone forever (this is the silent-loss)');
});

// ── A stranger / forged / unsigned note (accept → null) → terminal silent ack, no inbox repaint ──
test('a dropped note (accept → null: unsigned/forged/stranger) is acked terminally without a repaint', async () => {
  const emittedNotes: NoteLiveEvent[] = [];
  const ackLog: string[][] = [];
  const note: NoteResponseSeam = {
    verify: async () => fakeNoteWire('STRANGERFP'),
    accept: async () => null, // verifyNoteSender/admit dropped it — silent I-1/I-2
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    note,
    emitNote: (e) => emittedNotes.push(e),
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'NOTE_BLOB' }], ackLog),
  }));

  assert.equal(summary.notes, 0, 'a dropped note is not persisted');
  assert.equal(summary.dropped, 1, 'dropped (terminal)');
  assert.deepEqual(ackLog, [['e1']], 'still acked (clean up invalid mail silently)');
  assert.equal(emittedNotes.length, 0, 'no inbox repaint for a dropped note (no oracle — silent custody)');
});

// ── A store failure while persisting a VERIFIED note → RETRYABLE: left in the mailbox, NOT acked ──
test('a store failure persisting a verified note is retryable (left in the mailbox)', async () => {
  const ackLog: string[][] = [];
  const note: NoteResponseSeam = {
    verify: async () => fakeNoteWire(),
    accept: async () => { throw new Error('IndexedDB putNote failed'); },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    note,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'NOTE_BLOB' }], ackLog),
  }));

  assert.equal(summary.notes, 0);
  assert.equal(summary.acked, 0, 'a retryable note is NOT acked — it redelivers next poll (at-least-once)');
  assert.deepEqual(ackLog, [], 'nothing acked');
});

// ── A non-note blob (note-verify → null) FALLS THROUGH to the contact-update path (no eating either way) ──
test('a blob the note-verify rejects falls through to the contact-update path', async () => {
  let decryptCalls = 0;
  const ackLog: string[][] = [];
  const note: NoteResponseSeam = {
    verify: async () => null, // not a note → must fall through
    accept: async () => { throw new Error('accept must never be called on a null verify'); },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; }, // reached via fall-through; null → terminal drop
    note,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'CONTACT_UPDATE_BLOB' }], ackLog),
  }));

  assert.equal(decryptCalls, 1, 'fell through to the contact-update decryptor — the note seam did not eat it');
  assert.equal(summary.notes, 0);
  assert.equal(summary.dropped, 1);
  assert.deepEqual(ackLog, [['e1']]);
});

// ── A throwing note-verify on hostile input → treated as not-a-note → falls through (fail-safe) ──
test('a throwing note-verify is treated as null and falls through (fail-safe)', async () => {
  let decryptCalls = 0;
  const ackLog: string[][] = [];
  const note: NoteResponseSeam = {
    verify: async () => { throw new Error('malformed blob blew up note-verify'); },
    accept: async () => { throw new Error('accept must not be reached'); },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; },
    note,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'HOSTILE' }], ackLog),
  }));

  assert.equal(decryptCalls, 1, 'a throwing note-verify does not wedge — it falls through to contact-update');
  assert.equal(summary.dropped, 1);
});

// ── (Flint criterion b) 3-WAY NO-CROSS-SWALLOW: joiner / note / contact-update in ONE poll, each ──
//    routed to its own path, none eating another. joiner-first, then note, then contact-update.
test('3-way no-cross-swallow: joiner→joiner, note→note, contact-update→contact — none eaten', async () => {
  const joinerFps: string[] = [];
  const noteFroms: string[] = [];
  let contactDecryptCalls = 0;
  const ackLog: string[][] = [];

  const joiner: JoinerResponseSeam = {
    verify: async (blob) => (blob === 'JOINER' ? pendingJoinerLite() : null),
    accept: async (p) => { joinerFps.push(p.fingerprint); return { ignited: true }; },
  };
  const note: NoteResponseSeam = {
    verify: async (blob) => (blob === 'NOTE' ? fakeNoteWire('BOBFP') : null),
    accept: async (w) => { noteFroms.push(w.from_fingerprint); return { note_id: w.note_id, thread_id: w.thread_id, from_fingerprint: w.from_fingerprint }; },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    joiner,
    note,
    decrypt: async () => { contactDecryptCalls++; return null; }, // ONLY the contact-update blob reaches here
    fetchImpl: recordingFetch([
      { envelope_id: 'j', blob: 'JOINER' },
      { envelope_id: 'n', blob: 'NOTE' },
      { envelope_id: 'c', blob: 'CONTACT' },
    ], ackLog),
  }));

  assert.deepEqual(joinerFps, ['BOBFP'], 'the joiner routed to the joiner seam only');
  assert.deepEqual(noteFroms, ['BOBFP'], 'the note routed to the note seam only');
  assert.equal(contactDecryptCalls, 1, 'ONLY the contact-update blob reached the contact decryptor — neither joiner nor note was swallowed by it');
  assert.equal(summary.applied, 1, 'the joiner surfaced as an apply');
  assert.equal(summary.notes, 1, 'the note persisted');
  assert.equal(summary.dropped, 1, 'the contact-update (null decrypt) dropped terminally');
  assert.equal(summary.acked, 3, 'all three consumed + acked — no cross-swallow, no loss');
});

// ── REAL-CRYPTO DISCRIMINATOR: noteOpenpgpDecryptor accepts a real sealed note, rejects a non-note ──
// This is the crux of the finding: a note sealed with the SAME openpgp envelope as contact-updates
// decrypts as a note ONLY via its type-checked decryptor; a non-note openpgp blob returns null (→ the
// contact-update fall-through). Proves the discriminator is sound without needing IndexedDB.
test('real crypto: noteOpenpgpDecryptor accepts a real sealed note and rejects a non-note openpgp blob', async () => {
  const note: NoteWireV0 = fakeNoteWire(OWNER.fingerprint);
  const noteBlob = await sealNoteTo(note, OWNER.publicKeyArmored); // same openpgp envelope as a contact-update
  const dec = noteOpenpgpDecryptor(OWNER.privateKeyArmored, OWNER.passphrase);

  const asNote = await dec(noteBlob);
  assert.ok(asNote, 'a real sealed note decrypts to a NoteWireV0 via the note decryptor');
  assert.equal(asNote?.type, NOTE_WIRE_TYPE);
  assert.equal(asNote?.body, 'hello over the wire');

  // A non-note payload sealed with the same openpgp envelope → note-decryptor returns null (type check).
  const { encrypt, createMessage, readKey } = await import('openpgp');
  const encryptionKeys = await readKey({ armoredKey: OWNER.publicKeyArmored });
  const nonNote = (await encrypt({ message: await createMessage({ text: JSON.stringify({ kind: 'contact.update', envelope: { fingerprint: 'X' } }) }), encryptionKeys })) as string;
  assert.equal(await dec(nonNote), null, 'a non-note openpgp blob returns null → falls through to contact-update, never eaten as a note');
});
