// src/lib/relay/mailbox-store.test.ts
// Unit tests for the return-channel mailbox store. Server-independent proof of the functional
// invariants (deposit / non-destructive poll / ack-delete / at-least-once / cap-429 / TTL GC) and
// the config-driven policy hooks. The HTTP-level I-4 anti-oracle properties (owner-auth-first,
// uniform non-owner shape) are exercised against a live server by Flint's e2e gate.
//
// Run: PATH=/home/alpha/.nvm/versions/node/v22.22.1/bin:$PATH npx tsx --test mailbox-store.test.ts

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { depositEnvelope, pollMailbox, ackDelete, getMailboxStore } from './mailbox-store';

const ENV_KEYS = ['RELAY_MAILBOX_CAP', 'RELAY_ENVELOPE_TTL_MS', 'RELAY_MAX_PAYLOAD_BYTES'] as const;

beforeEach(() => {
  getMailboxStore().clear();
  for (const k of ENV_KEYS) delete process.env[k];
});

const NOW = 1_000_000;

test('deposit → owner poll returns the envelope with an assigned id', () => {
  const r = depositEnvelope('mbx-a', 'BLOB1', NOW);
  assert.deepEqual(r, { ok: true });
  const list = pollMailbox('mbx-a', NOW);
  assert.equal(list.length, 1);
  assert.equal(list[0].blob, 'BLOB1');
  assert.ok(list[0].envelope_id.length > 0, 'relay assigns an envelope_id');
});

test('poll is NON-destructive — repeated polls return the same set (no ack between)', () => {
  depositEnvelope('mbx-b', 'X', NOW);
  depositEnvelope('mbx-b', 'Y', NOW);
  const a = pollMailbox('mbx-b', NOW).map((e) => e.envelope_id).sort();
  const b = pollMailbox('mbx-b', NOW).map((e) => e.envelope_id).sort();
  assert.deepEqual(a, b, 'two polls with no ack between yield the same envelope_ids');
  assert.equal(a.length, 2);
});

test('ack-delete removes exactly the acked ids; unacked remain (at-least-once)', () => {
  depositEnvelope('mbx-c', 'first', NOW);
  depositEnvelope('mbx-c', 'second', NOW);
  const [e0, e1] = pollMailbox('mbx-c', NOW);
  const deleted = ackDelete('mbx-c', [e0.envelope_id], NOW);
  assert.equal(deleted, 1);
  const rest = pollMailbox('mbx-c', NOW);
  assert.deepEqual(rest.map((e) => e.envelope_id), [e1.envelope_id], 'acked gone, unacked remains');
});

test('ack of an unknown id is a no-op (idempotent redelivery-safe)', () => {
  depositEnvelope('mbx-d', 'z', NOW);
  const deleted = ackDelete('mbx-d', ['does-not-exist'], NOW);
  assert.equal(deleted, 0);
  assert.equal(pollMailbox('mbx-d', NOW).length, 1);
});

test('a never-used mailbox polls as empty (indistinguishable from drained, to the owner)', () => {
  assert.deepEqual(pollMailbox('mbx-never', NOW), []);
});

test('per-mailbox cap → 429 at capacity (config-driven RELAY_MAILBOX_CAP)', () => {
  process.env.RELAY_MAILBOX_CAP = '3';
  assert.deepEqual(depositEnvelope('mbx-cap', 'a', NOW), { ok: true });
  assert.deepEqual(depositEnvelope('mbx-cap', 'b', NOW), { ok: true });
  assert.deepEqual(depositEnvelope('mbx-cap', 'c', NOW), { ok: true });
  assert.deepEqual(depositEnvelope('mbx-cap', 'd', NOW), { ok: false, status: 429 }, 'at-cap → 429');
  assert.equal(pollMailbox('mbx-cap', NOW).length, 3, 'the over-cap deposit did not land');
});

test('TTL backstop GC — expired envelopes are swept on access (config-driven RELAY_ENVELOPE_TTL_MS)', () => {
  process.env.RELAY_ENVELOPE_TTL_MS = '50';
  depositEnvelope('mbx-ttl', 'stale', NOW); // expires_at = NOW + 50
  assert.equal(pollMailbox('mbx-ttl', NOW + 10).length, 1, 'not yet expired');
  assert.equal(pollMailbox('mbx-ttl', NOW + 100).length, 0, 'expired envelope swept by backstop GC');
});

test('a fresh (never-existed) deposit and a warm (has-mail) deposit both succeed identically (I-4 deposit-side outcome)', () => {
  depositEnvelope('mbx-warm', 'existing', NOW);
  const toFresh = depositEnvelope('mbx-fresh', 'p', NOW);
  const toWarm = depositEnvelope('mbx-warm', 'q', NOW);
  assert.deepEqual(toFresh, toWarm, 'deposit outcome does not depend on the recipient mailbox state');
});

test('deposit rejects malformed input with request-shape errors (not mailbox-state errors)', () => {
  assert.deepEqual(depositEnvelope('', 'blob', NOW), { ok: false, status: 400 }, 'empty mailbox_id');
  assert.deepEqual(depositEnvelope('mbx', '', NOW), { ok: false, status: 400 }, 'empty blob');
  process.env.RELAY_MAX_PAYLOAD_BYTES = '4';
  assert.deepEqual(depositEnvelope('mbx', 'toolong', NOW), { ok: false, status: 413 }, 'oversized blob');
});
