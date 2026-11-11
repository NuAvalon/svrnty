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
import { makeUnlockCycle } from '@/lib/crypto/unlock-cycle';
import { lockSession } from '@/lib/identity/client-store';
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

test('a guard that defers the contact leaves the update on the relay: nothing is written, nothing is acked, and the next poll applies it', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'Bob (NEW name)' },
  };
  const signed = await signUpdate(env, bob);
  const { store, persisted } = aliceStore(new Map([[bob.fingerprint, bobKnownToAlice(0)]]));
  let deferNow = true;
  const guarded = {
    ...store,
    guard: async <T,>(run: () => Promise<T>) => (deferNow ? { deferred: true as const } : { deferred: false as const, value: await run() }),
  };

  const ackLog: string[][] = [];
  const first = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => signed, store: guarded, fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ackLog),
  }));
  assert.equal(first.applied, 0);
  assert.equal(first.acked, 0, 'the deferred envelope is NOT acked: it stays on the relay');
  assert.equal(persisted.length, 0, 'nothing was written while the owner-protecting write held the contact');
  assert.deepEqual(ackLog, []);

  deferNow = false; // the owner-protecting write is done: the same envelope is delivered again
  const second = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => signed, store: guarded, fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ackLog),
  }));
  assert.equal(second.applied, 1);
  assert.equal(second.acked, 1);
  assert.equal(persisted.length, 1, 'the change was applied on the next poll, not lost');
  assert.equal(persisted[0].next.name, 'Bob (NEW name)');
  assert.deepEqual(ackLog, [['e1']]);
});

test('a store with no guard behaves exactly as before (the write always runs)', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'Bob (NEW name)' },
  };
  const signed = await signUpdate(env, bob);
  const { store, persisted } = aliceStore(new Map([[bob.fingerprint, bobKnownToAlice(0)]]));
  assert.equal('guard' in store, false);
  const summary = await consumeInboundContactUpdates(baseDeps({ decrypt: async () => signed, store, fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], []) }));
  assert.equal(summary.applied, 1);
  assert.equal(persisted.length, 1);
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
  assert.deepEqual(summary, { polled: 0, applied: 0, ignited: 0, notes: 0, delivered: 0, dropped: 0, held: 0, lost: {}, opened_hybrid: 0, opened_classical: 0, deadLettered: 0, unrecorded: 0, released: 0, acked: 0 });
  assert.deepEqual(ackLog, []);
});

test('refused poll (401 owner-auth) → rejected status surfaced, not an empty mailbox', async () => {
  const summary = await consumeInboundContactUpdates(baseDeps({
    fetchImpl: async () => new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 }),
  }));
  assert.equal(summary.rejected, 401);
  assert.equal(summary.polled, 0, 'a refused poll is not a polled mailbox');
});

test('N10: session locked MID-TICK → remaining blobs are NOT decrypted, NOT persisted, and NOTHING is acked (no ack-delete on a dead cycle)', async () => {
  const ackLog: string[][] = [];
  const { store, persisted } = aliceStore(new Map([[bob.fingerprint, bobKnownToAlice(0)]]));
  const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase);
  let decrypts = 0;
  const summary = await consumeInboundContactUpdates(baseDeps({
    owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, cycle },
    // First blob: the lock lands while it is being decrypted, so it fails. A dead cycle makes EVERYTHING look
    // undecryptable (→ terminal → ack-delete) unless the consume loop treats it as undecided.
    decrypt: async () => { decrypts += 1; lockSession(); throw new Error('unlock cycle ended'); },
    store,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'B1' }, { envelope_id: 'e2', blob: 'B2' }, { envelope_id: 'e3', blob: 'B3' }], ackLog),
  }));

  assert.equal(decrypts, 1, 'the loop stopped: blobs 2 and 3 were never decrypted under the ended cycle');
  assert.equal(persisted.length, 0, 'nothing persisted');
  assert.deepEqual(ackLog, [], 'NOTHING acked — no envelope is ack-deleted because a lock made it look undecryptable');
  assert.equal(summary.acked, 0);
});

test('N10: control — a live cycle behaves exactly as before (undecryptable blob is still terminal → acked)', async () => {
  const ackLog: string[][] = [];
  const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase);
  const summary = await consumeInboundContactUpdates(baseDeps({
    owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, cycle },
    decrypt: async () => null,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'B1' }], ackLog),
  }));
  assert.equal(summary.dropped, 1);
  assert.deepEqual(ackLog, [['e1']]);
  cycle.drop();
});

test('N10: lock lands AFTER decrypt resolved and BEFORE apply → nothing persisted, nothing acked, retryable', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'Bob (NEW name)' },
  };
  const signed = await signUpdate(env, bob);
  const ackLog: string[][] = [];
  const { store, persisted } = aliceStore(new Map([[bob.fingerprint, bobKnownToAlice(0)]]));
  const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase);
  const lookup = store.lookup.bind(store);
  // decrypt resolves fine (key() already handed out); the lock lands during lookup — i.e. between decrypt and persist.
  store.lookup = async (fp: string) => { lockSession(); return lookup(fp); };

  const summary = await consumeInboundContactUpdates(baseDeps({
    owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, cycle },
    decrypt: async () => signed,
    store,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ackLog),
  }));

  assert.equal(persisted.length, 0, 'NOTHING persisted after the lock');
  assert.deepEqual(ackLog, [], 'retryable: the envelope stays in the mailbox (no ack-delete)');
  assert.equal(summary.applied, 0);
});

test('N10: control — same flow with NO lock persists and acks (the guard only fires on a dead cycle)', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'Bob (NEW name)' },
  };
  const signed = await signUpdate(env, bob);
  const ackLog: string[][] = [];
  const { store, persisted } = aliceStore(new Map([[bob.fingerprint, bobKnownToAlice(0)]]));
  const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase);
  const summary = await consumeInboundContactUpdates(baseDeps({
    owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, cycle },
    decrypt: async () => signed,
    store,
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ackLog),
  }));
  assert.equal(persisted.length, 1);
  assert.deepEqual(ackLog, [['e1']]);
  assert.equal(summary.applied, 1);
  cycle.drop();
});

// N10 (Flint #178422 blocking 1): the cycle re-check sits before EVERY write in consumeOne, not only the contact persist.
// Each seam: verify() succeeds but the lock lands during it → accept() must never run; nothing acked (retryable).
for (const seam of ['joiner', 'note', 'receipt'] as const) {   // 'affirm' left with the affirm wire (#593); 'receipt' is the 4th write path
  test(`N10: lock lands after ${seam}.verify, before ${seam}.accept → accept never runs, nothing acked`, async () => {
    const ackLog: string[][] = [];
    const cycle = makeUnlockCycle(alice.privateKey, alice.passphrase);
    let accepted = 0;
    const s = {
      verify: async () => { lockSession(); return {} as never; },
      accept: async () => { accepted++; return null as never; },
    };
    const summary = await consumeInboundContactUpdates(baseDeps({
      owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase, cycle },
      [seam]: s,
      fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'B1' }], ackLog),
    } as Partial<ConsumeDeps>));
    assert.equal(accepted, 0, `${seam}.accept must not run on a dead cycle`);
    assert.deepEqual(ackLog, [], 'retryable: left in the mailbox');
    assert.equal(summary.acked, 0);
  });
}

test('#720 benign terminal: a contact-update that is stale (already applied) is acked with NO dead-letter record', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'Bob (NEW name)' },
  };
  const signed = await signUpdate(env, bob);
  const known = bobKnownToAlice(0);
  known.current = { ...known.current, version: 5 }; // the book already holds a newer version: the apply is rejected as stale
  const { store, persisted } = aliceStore(new Map([[bob.fingerprint, known]]));
  const ackLog: string[][] = [];
  const recorded: unknown[] = [];
  const summary = await consumeInboundContactUpdates(baseDeps({
    decrypt: async () => signed,
    store,
    deadLetter: { record: async (row) => { recorded.push(row); return row; }, clear: async () => {} },
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ackLog),
  }));
  assert.equal(persisted.length, 0, 'nothing applied');
  assert.deepEqual(ackLog, [['e1']], 'acked');
  assert.deepEqual(recorded, [], 'a stale update is consumed content, not a loss: no record');
  assert.equal(summary.deadLettered, 0);
});

// ---------- lenses v1.7 review-3, gap E1: refused lens payloads through consumeInboundContactUpdates ----------

import { isMessageReason, type DeadLetterRow } from './dead-letter';
import { lensTerminalClass } from './consume-mailbox';

test('R4-T1b: a refused lens result drops the fingerprint AT DISPATCH — not at the row gate', () => {
  // The "a refusal stores the fingerprint again" mutant survived because makeDeadLetterRow's
  // AUTHENTICATED_REASONS gate drops the fp anyway. This pins the dispatch itself: hand it a
  // refused result WITH a fingerprint and none may come out the other side.
  for (const refused of ['method-cap', 'shared-slot'] as const) {
    const cls = lensTerminalClass({ refused, fingerprint: 'f'.repeat(64) });
    assert.equal('fp' in cls, false, `${refused}: the dispatch carries no fp — a stored-fp mutant goes red here`);
    assert.equal('reason' in cls && cls.reason, refused === 'method-cap' ? 'lens-method-cap' : 'lens-shared-slot');
  }
});

test('R4-T1b end-to-end: a refused lens payload through consume records NO fingerprint even when the seam names one', async () => {
  const recorded: DeadLetterRow[] = [];
  const lens = {
    verify: async () => new Uint8Array([1, 2, 3]),
    accept: async () => ({ refused: 'method-cap' as const, fingerprint: bob.fingerprint }),
  };
  const ackLog: string[][] = [];
  await consumeInboundContactUpdates(baseDeps({
    lens,
    deadLetter: { record: async (row) => { recorded.push(row); return row; }, clear: async () => {} },
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ackLog),
  }));
  assert.equal(recorded.length, 1);
  assert.equal(recorded[0].reason, 'lens-method-cap');
  assert.equal('fp' in recorded[0], false, 'no fingerprint reaches the record — and not via the row gate alone');
});

test('R2b (v1.10): a HELD lens payload is NOT acknowledged — the relay keeps it and it applies on the next poll', async () => {
  const recorded: DeadLetterRow[] = [];
  let calls = 0;
  const lens = {
    verify: async () => new Uint8Array([1, 2, 3]),
    // First poll: the book is unreadable → held. Second poll (healed): the same envelope applies.
    accept: async () => (calls++ === 0 ? { held: true as const } : { applied: true as const, id: 'ev', fingerprint: 'f'.repeat(64), ignited: false }),
  };
  const ackLog: string[][] = [];
  const deps = (ack: string[][]) => baseDeps({
    lens,
    deadLetter: { record: async (row) => { recorded.push(row); return row; }, clear: async () => {} },
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }], ack),
  });
  const first = await consumeInboundContactUpdates(deps(ackLog));
  assert.deepEqual(ackLog, [], 'a receiver-side hold is NOT acked — an ack would lose the payload (must go red)');
  assert.equal(recorded.length, 0, 'a held payload is not a loss — no dead-letter row');
  assert.equal(first.deadLettered, 0);
  const second = await consumeInboundContactUpdates(deps(ackLog));
  assert.deepEqual(ackLog, [['e1']], 'the same envelope re-runs next poll and acks once it applies');
  assert.equal(second.applied, 1, 'exactly one apply across the polls');
  assert.equal(recorded.length, 0, 'still no dead-letter row — it applied');
});

test('R3-E1: each refused lens payload is recorded under its OWN reason — NO fingerprint, never a message', async () => {
  const recorded: DeadLetterRow[] = [];
  let call = 0;
  const lens = {
    verify: async () => new Uint8Array([1, 2, 3]),
    accept: async () =>
      call++ === 0
        ? { refused: 'method-cap' as const, fingerprint: bob.fingerprint }
        : { refused: 'shared-slot' as const, fingerprint: bob.fingerprint },
  };
  const ackLog: string[][] = [];
  const summary = await consumeInboundContactUpdates(baseDeps({
    lens,
    deadLetter: { record: async (row) => { recorded.push(row); return row; }, clear: async () => {} },
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB1' }, { envelope_id: 'e2', blob: 'BLOB2' }], ackLog),
  }));
  assert.equal(recorded.length, 2);
  assert.equal(recorded[0].reason, 'lens-method-cap', 'method-cap keeps its own reason — never collapsed or swapped');
  assert.equal(recorded[1].reason, 'lens-shared-slot', 'shared-slot keeps its own reason');
  for (const row of recorded) {
    assert.equal(row.fp, undefined, 'classical-only pair-MAC — no sender fingerprint is stored (A ruling)');
    assert.equal(isMessageReason(row.reason), false, `${row.reason} is a non-message: it can never feed a message count`);
  }
  assert.deepEqual(ackLog, [['e1', 'e2']], 'both terminal rows were acked after recording');
  assert.equal(summary.deadLettered, 2);
});
