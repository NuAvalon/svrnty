// src/lib/sync/consume-mailbox-affirm.test.ts
// MUTUAL-TRUST AFFIRMATION ROUTING (svrnty-trust-affirm-v0) — the mailbox's FOURTH inbound type. Proves
// consumeOne routes an affirmation by its OWN type-checked verify FIRST, so the always-on living-book
// poll does NOT eat + ack-delete it (the silent-loss that left mutual-trust permanently "awaiting").
// Mirrors consume-mailbox-note.test.ts: the affirm seam is INJECTED (fake verify/accept) to prove the
// CONTROL FLOW; the real crypto round-trip + the accept gates are covered by trust-affirm-seal.test.ts
// and trust-affirm-consume.test.ts.
//
// Run: npx tsx --test src/lib/sync/consume-mailbox-affirm.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import {
  consumeInboundContactUpdates,
  type ConsumeDeps,
  type TrustAffirmResponseSeam,
  type TrustLiveEvent,
  type NoteResponseSeam,
  type JoinerResponseSeam,
  type AcceptedTrustAffirmEvent,
} from './consume-mailbox';
import type { TrustAffirmWireV0 } from '@/lib/trust/trust-affirm';
import { TRUST_AFFIRM_WIRE_TYPE } from '@/lib/trust/trust-affirm';
import type { NoteWireV0 } from '@/lib/messaging/types';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import type { PendingJoiner } from '@/lib/trust/joiner-response';

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

function fakeAffirm(from = 'BOBFP', trusts = true): TrustAffirmWireV0 {
  return {
    type: TRUST_AFFIRM_WIRE_TYPE,
    affirm_id: 'af1',
    from_fingerprint: from,
    to_fingerprint: 'ALICEFP',
    trusts,
    sent_at: '2026-10-09T00:00:00.000Z',
  };
}
function acceptedFrom(w: TrustAffirmWireV0): AcceptedTrustAffirmEvent {
  return { id: 'rec_' + w.from_fingerprint, from_fingerprint: w.from_fingerprint, trusts: w.trusts, reciprocal: w.trusts };
}
function fakeNoteWire(from = 'BOBFP'): NoteWireV0 {
  return { type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1', from_fingerprint: from, sent_at: '2026-10-09T00:00:00.000Z', body: 'hi', participant_kind: 'human' };
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

// ── An affirmation is routed to the affirm seam and NEVER falls through to contact-update (the fix) ──
test('routes an affirmation via the affirm seam (verify-first) — applied + acked, no fall-through', async () => {
  let decryptCalls = 0;
  const emitted: TrustLiveEvent[] = [];
  const ackLog: string[][] = [];

  const affirm: TrustAffirmResponseSeam = {
    verify: async (blob) => (blob === 'AFFIRM_BLOB' ? fakeAffirm() : null),
    accept: async (w) => acceptedFrom(w),
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; }, // MUST NOT be reached for the affirm blob
    affirm,
    emitTrust: (e) => emitted.push(e),
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'AFFIRM_BLOB' }], ackLog),
  }));

  assert.equal(decryptCalls, 0, 'the contact-update decryptor was NOT invoked — routed by affirm-verify');
  assert.equal(summary.affirmed, 1, 'the flip is counted as applied');
  assert.equal(summary.applied, 0, 'an affirmation is NOT a contact-book apply');
  assert.equal(summary.acked, 1, 'the consumed affirmation envelope is acked');
  assert.deepEqual(ackLog, [['e1']]);
  assert.equal(emitted.length, 1, 'the trust map repaints on a persisted flip');
  assert.deepEqual(emitted[0], { id: 'rec_BOBFP', from_fingerprint: 'BOBFP', trusts: true, reciprocal: true });
});

// ── REGRESSION: WITHOUT the affirm seam, an affirmation-shaped decrypt is EATEN (the silent-loss) ──
test('without the affirm seam, an affirmation-shaped blob is silently dropped + acked (the loss the fix closes)', async () => {
  const ackLog: string[][] = [];
  const summary = await consumeInboundContactUpdates(baseDeps({
    // no `affirm` seam
    decrypt: async () => ({ type: TRUST_AFFIRM_WIRE_TYPE, trusts: true, from_fingerprint: 'BOBFP' } as unknown as never),
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'AFFIRM_BLOB' }], ackLog),
  }));
  assert.equal(summary.affirmed, 0, 'no flip applied — the affirmation never landed');
  assert.equal(summary.dropped, 1, 'classified terminal by the contact-update path');
  assert.deepEqual(ackLog, [['e1']], 'and ACK-DELETED — gone forever (the silent-loss)');
});

// ── A dropped affirmation (accept → null: stranger/forged) → terminal silent ack, no repaint ──
test('a dropped affirmation (accept → null) is acked terminally without a repaint (FALSE-MUTUAL gate)', async () => {
  const emitted: TrustLiveEvent[] = [];
  const ackLog: string[][] = [];
  const affirm: TrustAffirmResponseSeam = {
    verify: async () => fakeAffirm('STRANGERFP'),
    accept: async () => null, // authn/bind/admit dropped it — silent I-1/I-2
  };
  const summary = await consumeInboundContactUpdates(baseDeps({
    affirm,
    emitTrust: (e) => emitted.push(e),
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'AFFIRM_BLOB' }], ackLog),
  }));
  assert.equal(summary.affirmed, 0);
  assert.equal(summary.dropped, 1, 'dropped (terminal)');
  assert.deepEqual(ackLog, [['e1']], 'still acked (clean up invalid mail silently)');
  assert.equal(emitted.length, 0, 'no repaint, no "trusts you" echo for a dropped affirmation');
});

// ── ACK-FOLLOWS-PERSIST: a store failure applying a verified flip → RETRYABLE, NOT acked ──
test('a store failure applying a verified flip is retryable (left in the mailbox, not acked)', async () => {
  const ackLog: string[][] = [];
  const affirm: TrustAffirmResponseSeam = {
    verify: async () => fakeAffirm(),
    accept: async () => { throw new Error('IndexedDB updateContact failed'); },
  };
  const summary = await consumeInboundContactUpdates(baseDeps({
    affirm,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'AFFIRM_BLOB' }], ackLog),
  }));
  assert.equal(summary.affirmed, 0);
  assert.equal(summary.acked, 0, 'a retryable flip is NOT acked — it redelivers next poll (at-least-once)');
  assert.deepEqual(ackLog, []);
});

// ── A non-affirmation (affirm-verify → null) FALLS THROUGH to the contact-update path ──
test('a blob the affirm-verify rejects falls through to the contact-update path', async () => {
  let decryptCalls = 0;
  const ackLog: string[][] = [];
  const affirm: TrustAffirmResponseSeam = {
    verify: async () => null, // not an affirmation → must fall through
    accept: async () => { throw new Error('accept must never be called on a null verify'); },
  };
  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; },
    affirm,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'CONTACT_UPDATE_BLOB' }], ackLog),
  }));
  assert.equal(decryptCalls, 1, 'fell through to the contact-update decryptor — the affirm seam did not eat it');
  assert.equal(summary.affirmed, 0);
  assert.equal(summary.dropped, 1);
  assert.deepEqual(ackLog, [['e1']]);
});

// ── A throwing affirm-verify on hostile input → treated as not-an-affirmation → falls through ──
test('a throwing affirm-verify is treated as null and falls through (fail-safe)', async () => {
  let decryptCalls = 0;
  const ackLog: string[][] = [];
  const affirm: TrustAffirmResponseSeam = {
    verify: async () => { throw new Error('malformed blob blew up affirm-verify'); },
    accept: async () => { throw new Error('accept must not be reached'); },
  };
  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; },
    affirm,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'HOSTILE' }], ackLog),
  }));
  assert.equal(decryptCalls, 1, 'a throwing affirm-verify does not wedge — it falls through');
  assert.equal(summary.dropped, 1);
});

// ── 4-WAY NO-CROSS-SWALLOW: joiner / note / affirm / contact-update in ONE poll, each to its own path ──
test('4-way no-cross-swallow: joiner→joiner, note→note, affirm→affirm, contact→contact — none eaten', async () => {
  const joinerFps: string[] = [];
  const noteFroms: string[] = [];
  const affirmFroms: string[] = [];
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
  const affirm: TrustAffirmResponseSeam = {
    verify: async (blob) => (blob === 'AFFIRM' ? fakeAffirm('BOBFP') : null),
    accept: async (w) => { affirmFroms.push(w.from_fingerprint); return acceptedFrom(w); },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    joiner, note, affirm,
    decrypt: async () => { contactDecryptCalls++; return null; }, // ONLY the contact-update blob reaches here
    fetchImpl: recordingFetch([
      { envelope_id: 'j', blob: 'JOINER' },
      { envelope_id: 'n', blob: 'NOTE' },
      { envelope_id: 'a', blob: 'AFFIRM' },
      { envelope_id: 'c', blob: 'CONTACT' },
    ], ackLog),
  }));

  assert.deepEqual(joinerFps, ['BOBFP'], 'the joiner routed to the joiner seam only');
  assert.deepEqual(noteFroms, ['BOBFP'], 'the note routed to the note seam only');
  assert.deepEqual(affirmFroms, ['BOBFP'], 'the affirmation routed to the affirm seam only');
  assert.equal(contactDecryptCalls, 1, 'ONLY the contact-update blob reached the contact decryptor — nothing cross-swallowed');
  assert.equal(summary.applied, 1, 'the joiner surfaced as an apply');
  assert.equal(summary.notes, 1, 'the note persisted');
  assert.equal(summary.affirmed, 1, 'the affirmation flipped mutual trust');
  assert.equal(summary.dropped, 1, 'the contact-update (null decrypt) dropped terminally');
  assert.equal(summary.acked, 4, 'all four consumed + acked — no cross-swallow, no loss');
});
