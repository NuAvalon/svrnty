// src/lib/sync/consume-mailbox-apply-ack.test.ts
// svrnty-addressbook-ack-001 anchors (a)–(d): the apply-ack wire end-to-end at the consume seam —
// recipient-emit on apply (exactly one signed ack {ack_of,to_fp}), dup/rejected → no ack, the
// author-side seam graduating method_delivery 'awaiting-ack' → 'acked' on a verified wire, and the
// TTL-honest 'undelivered' decay. Injected transport/store — same harness shape as
// consume-mailbox.test.ts.
//
// Run: npx tsx --test src/lib/sync/consume-mailbox-apply-ack.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { signWithEnvelope } from '@/lib/crypto/sign-envelope';
import { DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput, type ContactUpdateEnvelope } from '@/lib/format/envelope';
import type { SignedContactUpdate, KnownContactIdentity } from '@/lib/trust/contact-update';
import type { StoredContact } from '@/lib/contacts/apply-contact-update';
import {
  consumeInboundContactUpdates,
  type ConsumeDeps,
  type KnownContact,
  type ApplyAckTarget,
  type ApplyAckLiveEvent,
} from './consume-mailbox';
import {
  DOMAIN_APPLY_ACK,
  APPLY_ACK_WIRE_TYPE,
  buildApplyAckWire,
  tryParseApplyAckWire,
  verifyApplyAckWire,
  applyAckSigningInput,
  type ApplyAckWireV0,
} from '@/lib/crypto/apply-ack';
import {
  markAwaitingAck,
  markAcked,
  pendingAckSig,
  methodDeliveryPhase,
  METHOD_DELIVERY_TTL_MS,
} from '@/lib/trust/method-delivery';
import { buildApplyAckSeam } from './live-book-poll';
import { livingEdgeStatus } from '@/lib/trust/living-edge-status';

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

let alice: Identity; // the update AUTHOR (owns the edge that graduates)
let bob: Identity;   // the update APPLIER (emits the ack)

before(async () => {
  alice = await makeIdentity('alice');
  bob = await makeIdentity('bob');
});

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
    name: 'Bob',
    email: 'bob@x.test',
    public_key: bob.publicKey,
    trust_level: 'verified',
    added_at: '2026-01-01T00:00:00.000Z',
    version: atVersion,
  };
  return { known, current };
}

function aliceDeps(overrides: Partial<ConsumeDeps>): ConsumeDeps {
  return {
    owner: { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase },
    decrypt: async () => null,
    store: { lookup: async () => null, persist: async () => {} },
    relayBase: 'http://relay.test/api/relay',
    now: () => '2026-08-19T00:00:00.000Z',
    ...overrides,
  };
}

async function signUpdate(env: ContactUpdateEnvelope, who: Identity): Promise<SignedContactUpdate> {
  const signature = await signWithEnvelope(DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput(env), who.privateKey, who.passphrase);
  return { envelope: env, signature };
}

// ── Anchor (a): a foreign contact-update that APPLIES emits exactly one signed apply-ack ─────────
test('anchor (a): applied update → exactly one apply-ack {ack_of: update sig, to_fp: author}', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'Bob (NEW)' },
  };
  const signed = await signUpdate(env, bob);
  const ackLog: string[][] = [];
  const sent: ApplyAckTarget[] = [];
  const records = new Map([[bob.fingerprint, bobKnownToAlice(0)]]);

  const summary = await consumeInboundContactUpdates(aliceDeps({
    decrypt: async () => signed,
    store: { lookup: async (fp) => records.get(fp) ?? null, persist: async () => {} },
    sendApplyAck: async (t) => { sent.push(t); },
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB' }], ackLog),
  }));

  assert.equal(summary.applied, 1);
  assert.equal(sent.length, 1, 'exactly one apply-ack emitted per applied update');
  assert.equal(sent[0].to_fp, bob.fingerprint, 'ack addressed to the update author');
  assert.equal(sent[0].ack_of, signed.signature.classical, 'ack_of binds the update signature hex');
  assert.equal(sent[0].author_public_key, bob.publicKey, 'seal target is the held card key');
});

// ── Anchor (b): duplicate / stale deliveries never re-emit; an apply-ack can never trigger an ack ─
test('anchor (b): a stale re-delivery applies nothing → no second ack (idempotent)', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'Bob (NEW)' },
  };
  const signed = await signUpdate(env, bob);
  const ackLog: string[][] = [];
  const sent: ApplyAckTarget[] = [];
  // Bob's record is already at version 1 — this delivery is the at-least-once redelivery.
  const records = new Map([[bob.fingerprint, bobKnownToAlice(1)]]);

  const summary = await consumeInboundContactUpdates(aliceDeps({
    decrypt: async () => signed,
    store: { lookup: async (fp) => records.get(fp) ?? null, persist: async () => {} },
    sendApplyAck: async (t) => { sent.push(t); },
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB' }], ackLog),
  }));

  assert.equal(summary.applied, 0, 'stale-version applies nothing');
  assert.equal(sent.length, 0, 'no ack for a no-apply redelivery — exactly-one holds across dups');
  assert.deepEqual(ackLog, [['e1']], 'the stale envelope is still terminal-acked (consumed)');
});

test('anchor (b): an inbound apply-ack is routed to bookkeeping — never itself acked (ack-of-ack impossible)', async () => {
  const wire = await buildApplyAckWire('deadbeef'.repeat(8), alice.fingerprint, bob.fingerprint, bob.privateKey, bob.passphrase);
  const seen: ApplyAckWireV0[] = [];
  const sent: ApplyAckTarget[] = [];
  const ackLog: string[][] = [];

  const summary = await consumeInboundContactUpdates(aliceDeps({
    applyAck: {
      verify: async () => wire,
      accept: async (w) => { seen.push(w); return null; }, // no awaiting mark → drop
    },
    sendApplyAck: async (t) => { sent.push(t); },
    fetchImpl: recordingFetch([{ envelope_id: 'e9', blob: 'ACKBLOB' }], ackLog),
  }));

  assert.equal(seen.length, 1, 'the ack wire reached its own seam');
  assert.equal(sent.length, 0, 'no ack-of-ack — the emit path has no surface on the ack kind');
  assert.equal(summary.dropped, 1, 'unmatched ack is a benign terminal (apply-ack-no-match)');
  assert.deepEqual(ackLog, [['e9']], 'consumed: acked off the relay');
});

// ── Anchor (c): tampered/rejected updates emit NO ack — the refusal stays loud ────────────────────
test('anchor (c): a forged-signature update is refused loud → NO apply-ack', async () => {
  const env: ContactUpdateEnvelope = {
    fingerprint: bob.fingerprint, epoch: 0, version: 1, updated_at: '2026-08-19T00:00:00.000Z',
    changed_fields: ['display_name'], delta: { display_name: 'intruder' },
  };
  const signed = await signUpdate(env, bob);
  // Tamper: the delta no longer matches the signature (signed over the original fields).
  const forged: SignedContactUpdate = { envelope: { ...env, delta: { display_name: 'tampered' } }, signature: signed.signature };
  const sent: ApplyAckTarget[] = [];
  const records = new Map([[bob.fingerprint, bobKnownToAlice(0)]]);

  const summary = await consumeInboundContactUpdates(aliceDeps({
    decrypt: async () => forged,
    store: { lookup: async (fp) => records.get(fp) ?? null, persist: async () => {} },
    sendApplyAck: async (t) => { sent.push(t); },
    fetchImpl: recordingFetch([{ envelope_id: 'e1', blob: 'BLOB' }], [[]]),
  }));

  assert.equal(summary.applied, 0, 'tampered update never applies');
  assert.equal(sent.length, 0, 'NO ack for a rejected update — refuse stays loud');
  assert.equal(summary.dropped, 1);
});

// ── Anchor (d): the author-side seam graduates 'awaiting-ack' → 'acked' on a VERIFIED wire only ───
test('anchor (d): verified apply-ack marks the edge acked — exactly once, only on verify-true', async () => {
  const owedSig = 'ab'.repeat(64); // the update_sig alice recorded when the deposit landed
  const awaiting: StoredContact = {
    id: 'contact-bob',
    fingerprint: bob.fingerprint,
    name: 'Bob',
    email: 'bob@x.test',
    public_key: bob.publicKey,
    trust_level: 'verified',
    added_at: '2026-01-01T00:00:00.000Z',
    pq_kem_public_key: Buffer.alloc(32).toString('base64'),
    pq_sig_public_key: Buffer.alloc(32).toString('base64'),
    metadata: markAwaitingAck({ id: 'contact-bob' } as StoredContact, owedSig, '2026-08-19T00:00:00.000Z'),
  };
  // bob (the applier) signs "I applied your update owedSig" addressed to alice.
  const wire = await buildApplyAckWire(owedSig, alice.fingerprint, bob.fingerprint, bob.privateKey, bob.passphrase);

  const writes: Array<{ id: string; metadata: Record<string, unknown> }> = [];
  const seam = buildApplyAckSeam(
    { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase },
    undefined, // classical leg only in this unit
    {
      getContactByFingerprint: async (_owner: string, fp: string) =>
        (fp === bob.fingerprint ? (awaiting as never) : null),
      updateContact: async (id: string, updates: { metadata?: Record<string, unknown> }) => {
        writes.push({ id, metadata: updates.metadata ?? {} });
      },
    },
  );

  const graduated = await seam.accept(wire);
  assert.ok(graduated, 'a verified ack graduates the edge');
  assert.equal(graduated!.from_fingerprint, bob.fingerprint);
  assert.equal(writes.length, 1, 'exactly one write — the ONE line that marks acked');
  assert.equal(writes[0].metadata.method_delivery, 'acked');
  assert.equal(writes[0].metadata.method_delivery_sig, undefined, 'the owed sig is dropped once graduated');
});

test('anchor (d): forged / stray / wrong-ack_of wires never mark the edge (floor holds)', async () => {
  const owedSig = 'cd'.repeat(64);
  const awaiting: StoredContact = {
    id: 'contact-bob', fingerprint: bob.fingerprint, name: 'Bob', email: 'b@x', public_key: bob.publicKey,
    trust_level: 'verified', added_at: '2026-01-01T00:00:00.000Z',
    pq_kem_public_key: Buffer.alloc(32).toString('base64'), pq_sig_public_key: Buffer.alloc(32).toString('base64'),
    metadata: markAwaitingAck({ id: 'contact-bob' } as StoredContact, owedSig, '2026-08-19T00:00:00.000Z'),
  };
  const writes: unknown[] = [];
  const deps = {
    getContactByFingerprint: async () => awaiting as never,
    updateContact: async () => { writes.push(1); },
  };
  const seam = buildApplyAckSeam(
    { fingerprint: alice.fingerprint, publicKeyArmored: alice.publicKey, privateKeyArmored: alice.privateKey, passphrase: alice.passphrase },
    undefined, deps,
  );

  // wrong ack_of — a real signature over a DIFFERENT update's sig
  const wrongAckOf = await buildApplyAckWire('ff'.repeat(64), alice.fingerprint, bob.fingerprint, bob.privateKey, bob.passphrase);
  assert.equal(await seam.accept(wrongAckOf), null, 'ack for an unowed sig drops');
  // wrong to_fp — addressed to someone else entirely
  const wrongTo = await buildApplyAckWire(owedSig, bob.fingerprint, bob.fingerprint, bob.privateKey, bob.passphrase);
  assert.equal(await seam.accept(wrongTo), null, 'ack not addressed to this owner drops');
  // wrong from_fingerprint — a third party's claim
  const wire = await buildApplyAckWire(owedSig, alice.fingerprint, bob.fingerprint, bob.privateKey, bob.passphrase);
  const mismatched = { ...wire, from_fingerprint: alice.fingerprint };
  assert.equal(await seam.accept(mismatched), null, 'applier≠edge-peer drops');
  assert.equal(writes.length, 0, 'not one of them wrote');
});

test('anchor (d): living-edge-status — awaiting-ack within TTL stays, past TTL reads undelivered, acked is terminal', () => {
  const edge = (metadata: Record<string, unknown>) =>
    ({ peer_fingerprint: bob.fingerprint, peer_public_key: bob.publicKey, trusted: true, decay_days: 0, metadata }) as never;

  const fresh = edge({ method_delivery: 'awaiting-ack', method_delivery_at: new Date().toISOString() });
  assert.equal(livingEdgeStatus(fresh).methodDelivery, 'awaiting-ack');

  const stale = edge({ method_delivery: 'awaiting-ack', method_delivery_at: new Date(Date.now() - METHOD_DELIVERY_TTL_MS - 60_000).toISOString() });
  const st = livingEdgeStatus(stale);
  assert.equal(st.methodDelivery, 'undelivered', 'aged-out awaiting-ack reads undelivered — honest timeout');
  assert.equal(st.detailLine, 'Method update did not get an ack');

  const done = edge({ method_delivery: 'acked' });
  assert.equal(livingEdgeStatus(done).methodDelivery, 'acked');
  assert.equal(livingEdgeStatus(done).detailLine, 'Method update acknowledged');
});

// ── Grammar units: method-delivery transitions + wire parse/verify bindings ───────────────────────
test('method-delivery grammar: mark → pending → acked; TTL-decayed read', () => {
  const c = { id: 'c1', metadata: {} } as StoredContact;
  const marked = markAwaitingAck(c, 'aa'.repeat(64), '2026-08-19T00:00:00.000Z');
  const c2 = { ...c, metadata: marked };
  assert.equal(pendingAckSig(c2), 'aa'.repeat(64));
  assert.equal(methodDeliveryPhase(c2, Date.parse('2026-08-19T00:00:00.000Z') + 1000), 'awaiting-ack');
  assert.equal(methodDeliveryPhase(c2, Date.parse('2026-08-19T00:00:00.000Z') + METHOD_DELIVERY_TTL_MS + 1), 'undelivered');
  const acked = markAcked(c2);
  assert.equal(pendingAckSig({ ...c2, metadata: acked }), null, 'graduated edge owes nothing');
  assert.equal(methodDeliveryPhase({ ...c2, metadata: acked }, Date.now()), 'acked');
});

test('apply-ack wire grammar: tryParse gates the shape; verify binds (ack_of, to_fp, from_fp)', async () => {
  const owed = 'ee'.repeat(64);
  const wire = await buildApplyAckWire(owed, alice.fingerprint, bob.fingerprint, bob.privateKey, bob.passphrase);
  assert.equal(wire.type, APPLY_ACK_WIRE_TYPE);
  assert.ok(tryParseApplyAckWire(wire));
  assert.equal(tryParseApplyAckWire({ type: 'svrnty-note-v0' }), null, 'a note is not an ack');
  assert.equal(tryParseApplyAckWire({ ...wire, type: 'svrnty-receipt-v0' }), null, 'a receipt is not an ack');
  // verify the classical half end-to-end (pq pub omitted → classical path).
  assert.equal(
    await verifyApplyAckWire(wire, { ackOf: owed, toFp: alice.fingerprint, fromFingerprint: bob.fingerprint }, bob.publicKey),
    true,
    'the real signed ack verifies against the applier card key',
  );
  assert.equal(
    await verifyApplyAckWire(wire, { ackOf: 'ff'.repeat(64), toFp: alice.fingerprint, fromFingerprint: bob.fingerprint }, bob.publicKey),
    false,
    'a different ack_of never verifies',
  );
  // domain separation: the update's own signature must NOT verify as an ack (different domain).
  const updateSig = await signWithEnvelope(DOMAIN_CONTACT_UPDATE, applyAckSigningInput(owed, alice.fingerprint), bob.privateKey, bob.passphrase);
  const crossDomain: ApplyAckWireV0 = { ...wire, signature: updateSig };
  assert.equal(
    await verifyApplyAckWire(crossDomain, { ackOf: owed, toFp: alice.fingerprint, fromFingerprint: bob.fingerprint }, bob.publicKey),
    false,
    'a contact-update-domain sig can never pass as an apply-ack (domain separation)',
  );
});
