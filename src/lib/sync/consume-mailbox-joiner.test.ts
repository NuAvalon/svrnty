// src/lib/sync/consume-mailbox-joiner.test.ts
// R1 RETURN-CHANNEL ROUTING (Flint #125392, pinned by joiner-response.e2e.test.ts). Proves consumeOne
// routes each polled blob by WHICH VERIFY SUCCEEDS — trying the joiner-response verify FIRST — and never
// by decrypt-null. Uses an INJECTED joiner seam (the real crypto round-trip is covered by
// send-joiner-response.test.ts + joiner-response.test.ts + the e2e SEAM test); here we prove the control
// flow: joiner-verify wins → accept + apply (no fall-through to contact-update); joiner-verify null →
// fall through to the contact-update path; and the accept outcome → ack/retry mapping.
// Run: PATH=/home/alpha/.nvm/versions/node/v22.22.1/bin:$PATH npx tsx --test consume-mailbox-joiner.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { consumeInboundContactUpdates, type ConsumeDeps, type JoinerResponseSeam, type LiveApplyEvent } from './consume-mailbox';
import type { PendingJoiner } from '@/lib/trust/joiner-response';

// The owner (Alice) needs REAL keys — consumeInboundContactUpdates signs the poll/ack requests with them.
// The joiner seam is INJECTED (fake verify/accept) so the routing control-flow is what's under test.
let OWNER: { fingerprint: string; publicKeyArmored: string; privateKeyArmored: string; passphrase: string };
before(async () => {
  const passphrase = 'pw-alice';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart — 'ed25519' is valid at runtime (see core.ts).
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

function pendingJoiner(fp = 'BOBFP'): PendingJoiner {
  return { fingerprint: fp, epoch: 0, publicKeyArmored: 'BOBPUB', displayName: 'Bob', inviteNonce: 'CODE1', ts: '2026-09-02T00:00:00Z' };
}

function baseDeps(overrides: Partial<ConsumeDeps>): ConsumeDeps {
  return {
    owner: OWNER,
    decrypt: async () => null,
    store: { lookup: async () => null, persist: async () => {} },
    relayBase: 'http://relay.test/api/relay',
    now: () => '2026-09-02T00:00:00.000Z',
    ...overrides,
  };
}

// ── A joiner-response is routed to the joiner seam and NEVER falls through to contact-update ──
test('routes a joiner-response via the joiner seam (verify-first) — no fall-through to contact-update', async () => {
  const pj = pendingJoiner();
  let decryptCalls = 0;
  let acceptedWith: PendingJoiner | null = null;
  const emitted: LiveApplyEvent[] = [];
  const ackLog: string[][] = [];

  const joiner: JoinerResponseSeam = {
    verify: async (blob) => (blob === 'JOINER_BLOB' ? pj : null),
    accept: async (p) => { acceptedWith = p; return { ignited: true }; },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; }, // MUST NOT be reached for the joiner blob
    joiner,
    emit: (e) => emitted.push(e),
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'JOINER_BLOB' }], ackLog),
  }));

  assert.equal(acceptedWith?.fingerprint, 'BOBFP', 'the joiner seam accepted the verified joiner');
  assert.equal(decryptCalls, 0, 'the contact-update decryptor was NOT invoked — routed by verify, not decrypt');
  assert.equal(summary.applied, 1, 'a fresh joiner surfaces as an apply');
  assert.equal(summary.acked, 1, 'the consumed envelope is acked');
  assert.deepEqual(ackLog, [['e1']]);
  assert.equal(emitted.length, 1, 'the live book repaints on a fresh KNOWN joiner');
  assert.equal(emitted[0].fingerprint, 'BOBFP');
});

// ── A non-joiner blob (verify → null) FALLS THROUGH to the contact-update path (proves no eating) ──
test('a blob the joiner-verify rejects falls through to the contact-update path', async () => {
  let decryptCalls = 0;
  const ackLog: string[][] = [];
  const joiner: JoinerResponseSeam = {
    verify: async () => null, // not a joiner-response → must fall through
    accept: async () => { throw new Error('accept must never be called on a null verify'); },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; }, // reached via fall-through; null → terminal drop
    joiner,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'CONTACT_UPDATE_BLOB' }], ackLog),
  }));

  assert.equal(decryptCalls, 1, 'fell through to the contact-update decryptor');
  assert.equal(summary.applied, 0);
  assert.equal(summary.dropped, 1, 'undecryptable contact-update → terminal drop (existing behaviour)');
  assert.deepEqual(ackLog, [['e1']], 'a terminal drop is still acked');
});

// ── accept returns null (joiner already in the book) → terminal ack, no repaint ──
test('an already-known joiner (accept → null) is acked terminally without a repaint', async () => {
  const emitted: LiveApplyEvent[] = [];
  const ackLog: string[][] = [];
  const joiner: JoinerResponseSeam = {
    verify: async () => pendingJoiner(),
    accept: async () => null, // already in the book — no fresh add
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    joiner,
    emit: (e) => emitted.push(e),
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'JOINER_BLOB' }], ackLog),
  }));

  assert.equal(summary.applied, 0);
  assert.equal(summary.dropped, 1, 'already-known → terminal (dropped counter), still acked');
  assert.deepEqual(ackLog, [['e1']]);
  assert.equal(emitted.length, 0, 'no repaint for an already-known joiner');
});

// ── accept throws (store I/O failure) → RETRYABLE: left in the mailbox, NOT acked ──
test('a store failure while accepting a verified joiner is retryable (left in the mailbox)', async () => {
  const ackLog: string[][] = [];
  const joiner: JoinerResponseSeam = {
    verify: async () => pendingJoiner(),
    accept: async () => { throw new Error('IndexedDB write failed'); },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    joiner,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'JOINER_BLOB' }], ackLog),
  }));

  assert.equal(summary.applied, 0);
  assert.equal(summary.acked, 0, 'a retryable joiner is NOT acked — it redelivers next poll (at-least-once)');
  assert.deepEqual(ackLog, [], 'nothing acked');
});

// ── verify THROWS on hostile input → treated as not-a-joiner → falls through (fail-safe) ──
test('a throwing joiner-verify is treated as null and falls through (fail-safe)', async () => {
  let decryptCalls = 0;
  const ackLog: string[][] = [];
  const joiner: JoinerResponseSeam = {
    verify: async () => { throw new Error('malformed blob blew up verify'); },
    accept: async () => { throw new Error('accept must not be reached'); },
  };

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => { decryptCalls++; return null; },
    joiner,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'HOSTILE' }], ackLog),
  }));

  assert.equal(decryptCalls, 1, 'a throwing verify does not wedge — it falls through to contact-update');
  assert.equal(summary.dropped, 1);
});
