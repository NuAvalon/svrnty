// src/lib/sync/consume-mailbox.test.ts
// The consume→apply pipeline, with REAL crypto (a genuine signed contact.update from "Bob") but
// injected transport + decrypt + store — so the whole verify→apply→persist→ack→emit path is proven,
// plus the custody behaviours: whitelist-on-fetch drop, silent rejection, terminal-vs-retryable ack.
//
// Run: npx tsx --test consume-mailbox.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { signWithEnvelope } from '@/lib/crypto/sign-envelope';
import { DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput, type ContactUpdateEnvelope } from '@/lib/format/envelope';
import type { SignedContactUpdate, KnownContactIdentity } from '@/lib/trust/contact-update';
import type { StoredContact } from '@/lib/contacts/apply-contact-update';
import { consumeInboundContactUpdates, type ConsumeDeps, type KnownContact, type LiveApplyEvent } from './consume-mailbox';

interface Identity { fingerprint: string; publicKey: string; privateKey: string; passphrase: string }

async function makeIdentity(name: string): Promise<Identity> {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart — 'ed25519' is valid at runtime (see core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase,
    format: 'armored',
  });
  const fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  return { fingerprint, publicKey, privateKey, passphrase };
}

async function signUpdate(env: ContactUpdateEnvelope, bob: Identity): Promise<SignedContactUpdate> {
  const signature = await signWithEnvelope(DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput(env), bob.privateKey, bob.passphrase);
  return { envelope: env, signature };
}

let alice: Identity;
let bob: Identity;

before(async () => {
  alice = await makeIdentity('alice');
  bob = await makeIdentity('bob');
});

// A recording fetch: GET /queue → the given envelopes; POST /ack → records the acked ids.
function recordingFetch(envelopes: Array<{ envelope_id: string; blob: string }>, ackLog: string[][]): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/queue')) {
      return new Response(JSON.stringify(envelopes), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (String(url).includes('/ack')) {
      const body = JSON.parse(String(init?.body ?? '{}'));
      ackLog.push(body.envelope_ids);
      return new Response(JSON.stringify({ deleted: body.envelope_ids.length }), { status: 200 });
    }
    return new Response('not found', { status: 404 });
  }) as unknown as typeof fetch;
}

function aliceStore(records: Map<string, KnownContact>) {
  const persisted: Array<{ id: string; next: StoredContact }> = [];
  const store = {
    lookup: async (fp: string) => records.get(fp) ?? null,
    persist: async (id: string, next: StoredContact) => { persisted.push({ id, next }); },
  };
  return { store, persisted };
}

function bobKnownToAlice(atVersion = 0): KnownContact {
  const known: KnownContactIdentity = {
    fingerprint: bob.fingerprint,
    epoch: 0,
    version: atVersion,
    classicalPublicKeyArmored: bob.publicKey,
  };
  const current: StoredContact = {
    id: 'contact-bob',
    fingerprint: bob.fingerprint,
    name: 'Bob (old name)',
    email: 'bob@old.test',
    public_key: bob.publicKey,
    trust_level: 'verified',
    added_at: '2026-01-01T00:00:00.000Z',
    version: atVersion,
  };
  return { known, current };
}

function baseDeps(overrides: Partial<ConsumeDeps>): ConsumeDeps {
  return {
    owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase },
    decrypt: async () => null,
    store: { lookup: async () => null, persist: async () => {} },
    relayBase: 'http://relay.test/api/relay',
    now: () => '2026-08-19T00:00:00.000Z',
    ...overrides,
  };
}

test('happy path — Bob’s signed name change is verified, applied, persisted, acked, and emitted', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'Bob (NEW name)' },
  };
  const signed = await signUpdate(env, bob);
  const ackLog: string[][] = [];
  const { store, persisted } = aliceStore(new Map([[bob.fingerprint, bobKnownToAlice(0)]]));
  const emitted: LiveApplyEvent[] = [];

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => signed,
    store,
    emit: (e) => emitted.push(e),
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ackLog),
  }));

  assert.equal(summary.applied, 1);
  assert.equal(summary.acked, 1);
  assert.equal(persisted.length, 1);
  assert.equal(persisted[0].next.name, 'Bob (NEW name)', 'the applied record carries the new name');
  assert.equal(persisted[0].next.version, 1, 'version advanced');
  assert.deepEqual(ackLog, [['e1']], 'the applied envelope was acked');
  assert.equal(emitted.length, 1);
  assert.equal(emitted[0].fingerprint, bob.fingerprint);
});

test('whitelist-on-fetch (I-2) — an update from a stranger not in the book is dropped + acked, never applied', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'x' },
  };
  const signed = await signUpdate(env, bob);
  const ackLog: string[][] = [];
  const { store, persisted } = aliceStore(new Map()); // Bob is NOT in Alice's book

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => signed,
    store,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ackLog),
  }));

  assert.equal(summary.applied, 0);
  assert.equal(summary.dropped, 1);
  assert.equal(persisted.length, 0, 'nothing written for a stranger');
  assert.deepEqual(ackLog, [['e1']], 'stranger mail is still cleaned up (silently)');
});

test('undecryptable blob → dropped + acked (not-for-us / corrupt), silently', async () => {
  const ackLog: string[][] = [];
  const { store, persisted } = aliceStore(new Map([[bob.fingerprint, bobKnownToAlice(0)]]));
  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => null, // undecryptable
    store,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'garbage' }], ackLog),
  }));
  assert.equal(summary.applied, 0);
  assert.equal(summary.dropped, 1);
  assert.equal(persisted.length, 0);
  assert.deepEqual(ackLog, [['e1']]);
});

test('bad signature → dropped + acked (silent), never applied', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'forged' },
  };
  const signed = await signUpdate(env, bob);
  signed.signature = { ...signed.signature, classical: signed.signature.classical.replace(/[A-M]/, 'Z') }; // corrupt
  const ackLog: string[][] = [];
  const { store, persisted } = aliceStore(new Map([[bob.fingerprint, bobKnownToAlice(0)]]));

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => signed, store,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ackLog),
  }));
  assert.equal(summary.applied, 0);
  assert.equal(summary.dropped, 1);
  assert.equal(persisted.length, 0);
  assert.deepEqual(ackLog, [['e1']], 'a permanently-invalid (bad-sig) envelope is terminal → acked');
});

test('epoch-ahead-needs-lineage → RETRYABLE: dropped this poll but NOT acked (survives for lineage catch-up)', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 5, version: 1, updated_at: '2026-08-19T00:00:00.000Z', // epoch ahead of Alice's 0
    changed_fields: ['display_name'], delta: { display_name: 'future Bob' },
  };
  const signed = await signUpdate(env, bob);
  const ackLog: string[][] = [];
  const { store, persisted } = aliceStore(new Map([[bob.fingerprint, bobKnownToAlice(0)]]));

  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => signed, store,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ackLog),
  }));
  assert.equal(summary.applied, 0);
  assert.equal(summary.dropped, 1);
  assert.equal(summary.acked, 0, 'a retryable envelope is NOT acked — it must survive for a later poll');
  assert.equal(persisted.length, 0);
  assert.deepEqual(ackLog, [], 'no ack call for a retryable-only batch');
});

test('a store I/O failure does not wedge the channel — left for retry (no throw escapes, not acked)', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'io-fail' },
  };
  const signed = await signUpdate(env, bob);
  const ackLog: string[][] = [];
  // A real, in-book, verified update whose persist throws (simulating an IndexedDB write failure).
  const throwingStore = {
    lookup: async (fp: string) => (fp === bob.fingerprint ? bobKnownToAlice(0) : null),
    persist: async () => { throw new Error('simulated IndexedDB write failure'); },
  };
  // The whole poll must COMPLETE (return, not throw) — one poisoned envelope cannot wedge the channel.
  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => signed,
    store: throwingStore,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ackLog),
  }));
  assert.equal(summary.applied, 0);
  assert.equal(summary.dropped, 1);
  assert.equal(summary.acked, 0, 'a store-failure envelope is left in the mailbox (retryable), not acked');
  assert.deepEqual(ackLog, [], 'no ack — the verified update was not silently dropped');
});

test('empty mailbox → no-op summary', async () => {
  const ackLog: string[][] = [];
  const summary = await consumeInboundContactUpdates(baseDeps({
    fetchImpl: recordingFetch([], ackLog),
  }));
  assert.deepEqual(summary, { polled: 0, applied: 0, ignited: 0, dropped: 0, acked: 0 });
  assert.deepEqual(ackLog, []);
});
