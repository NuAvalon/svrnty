// src/lib/headless/headless-client.test.ts
// Run: npx tsx --test src/lib/headless/headless-client.test.ts
//
// END-TO-END headless RECEIVE/POLL/SEND (L2b) against an in-memory mock relay — no browser, no IndexedDB.
// Two real canonical identities (mintHeadlessAgent): A sends a trust-affirmation + a note to B; B polls its
// smart mailbox headlessly → decrypts → verifies → applies into a HeadlessStore (reciprocal flips; note
// persisted). Plus the FALSE-MUTUAL gate: a stranger's affirmation flips nothing.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import {
  type HeadlessOwner,
  pollHeadlessOnce,
  sendTrustAffirmToPeer,
  sendNoteFromHeadless,
} from './headless-client';

const RELAY = 'http://relay.test/api/relay';

type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id: any = a.introduction.card.identity;
  return {
    fp: id.fingerprint, pub: id.public_key,
    priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, sig: id.pq_sig_public_key,
  };
}
function owner(id: Id): HeadlessOwner {
  return {
    fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass,
    kemPublicKey: id.kem, sigPublicKey: id.sig,
  };
}
function asContact(id: Id, over: Partial<HeadlessContact> = {}): HeadlessContact {
  return {
    id: 'c_' + id.fp.slice(0, 8), fingerprint: id.fp, public_key: id.pub,
    pq_sig_public_key: id.sig, pq_kem_public_key: id.kem, ...over,
  };
}

/** In-memory smart mailbox: POST /envelope deposits, GET /queue returns, POST /ack deletes. */
function mockRelay() {
  const boxes = new Map<string, Array<{ envelope_id: string; blob: string }>>();
  let seq = 0;
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const u = String(url);
    if (u.includes('/envelope')) {
      const { mailbox_id, blob } = JSON.parse(String(init?.body ?? '{}'));
      if (!boxes.has(mailbox_id)) boxes.set(mailbox_id, []);
      boxes.get(mailbox_id)!.push({ envelope_id: `e${++seq}`, blob });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    if (u.includes('/queue')) {
      const mid = new URL(u).searchParams.get('mailbox_id') ?? '';
      return new Response(JSON.stringify(boxes.get(mid) ?? []), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (u.includes('/ack')) {
      const { mailbox_id, envelope_ids } = JSON.parse(String(init?.body ?? '{}'));
      const q = boxes.get(mailbox_id) ?? [];
      boxes.set(mailbox_id, q.filter((e) => !envelope_ids.includes(e.envelope_id)));
      return new Response(JSON.stringify({ deleted: (envelope_ids as string[]).length }), { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, boxes };
}

test('headless RECEIVE: A affirms trust → B polls → reciprocal flips (B already trusts A) → MUTUAL', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl } = mockRelay();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A, { trusted: true, trust_level: 'trusted' })); // A in B's book, B trusts A

  // A deposits "I trust B" to B's mailbox (headless send).
  const dep = await sendTrustAffirmToPeer({
    senderFingerprint: A.fp, senderPublicKeyArmored: A.pub, senderPrivateKeyArmored: A.priv, passphrase: A.kpass,
    senderPqKemPublicKey: A.kem, senderPqSigPublicKey: A.sig,
    peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, trusts: true,
    relayBase: RELAY, fetchImpl,
  });
  assert.equal(dep.deposited, true);

  // B polls headlessly.
  const summary = await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(summary.affirmed, 1, 'the affirmation was consumed');
  assert.equal(summary.acked, 1, 'and acked');

  const a = bStore.getContactByFingerprint(A.fp)!;
  assert.equal(a.mutual?.they_trust_me, true, 'they_trust_me flipped');
  assert.equal(a.mutual?.reciprocal, true, 'reciprocal → MUTUAL (both sides trust)');
});

test('headless RECEIVE: in-book affirm but I do NOT trust them → they_trust_me set, reciprocal FALSE (inbound)', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl } = mockRelay();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A, { trusted: false, trust_level: 'known' })); // in book, NOT trusted

  await sendTrustAffirmToPeer({
    senderFingerprint: A.fp, senderPublicKeyArmored: A.pub, senderPrivateKeyArmored: A.priv, passphrase: A.kpass,
    senderPqKemPublicKey: A.kem, senderPqSigPublicKey: A.sig,
    peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, trusts: true, relayBase: RELAY, fetchImpl,
  });
  await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });

  const a = bStore.getContactByFingerprint(A.fp)!;
  assert.equal(a.mutual?.they_trust_me, true);
  assert.equal(a.mutual?.reciprocal, false, 'no wire-driven promotion — mutual needs MY own prior trust');
});

test('headless RECEIVE: a STRANGER affirmation flips nothing (FALSE-MUTUAL gate, in-book admit)', async () => {
  const [B, C] = [await mint(), await mint()]; // C is NOT in B's book
  const { fetchImpl } = mockRelay();
  const bStore = new HeadlessStore(); // empty book

  await sendTrustAffirmToPeer({
    senderFingerprint: C.fp, senderPublicKeyArmored: C.pub, senderPrivateKeyArmored: C.priv, passphrase: C.kpass,
    senderPqKemPublicKey: C.kem, senderPqSigPublicKey: C.sig,
    peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, trusts: true, relayBase: RELAY, fetchImpl,
  });
  const summary = await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });

  assert.equal(summary.affirmed, 0, 'a verified stranger affirmation is NOT applied');
  assert.equal(summary.dropped, 1, 'dropped terminally');
  assert.equal(summary.acked, 1, 'and acked (cleaned up silently)');
  assert.equal(bStore.getContactByFingerprint(C.fp), null, 'C never entered the book — no "trusts you" echo');
});

test('headless RECEIVE + SEND: A sends a note → B polls → note persisted in the headless store', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl } = mockRelay();
  const aStore = new HeadlessStore();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A, { trust_level: 'known' })); // A in B's book (admit)

  const sent = await sendNoteFromHeadless({
    owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub,
    body: 'hello from a headless agent', store: aStore, relayBase: RELAY, fetchImpl,
  });
  assert.equal(sent.deposited, true);
  assert.equal(aStore.listNotes().length, 1, 'outbound copy persisted on the sender');
  assert.equal(aStore.listNotes()[0].direction, 'outbound');

  const summary = await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(summary.notes, 1, 'the note was received + persisted');
  const inbound = bStore.listNotes();
  assert.equal(inbound.length, 1);
  assert.equal(inbound[0].direction, 'inbound');
  assert.equal(inbound[0].body, 'hello from a headless agent');
  assert.equal(inbound[0].from_fingerprint, A.fp);
  assert.equal(bStore.listThreads().length, 1, 'a thread was created');
});

test('headless RECEIVE: a BLOCKED in-book sender note is NOT persisted — block must block on the agent note-path (P1#2 survivor-safety)', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl } = mockRelay();
  const aStore = new HeadlessStore();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A, { trust_level: 'known', blocked: true })); // A in B's book but BLOCKED

  const sent = await sendNoteFromHeadless({
    owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub,
    body: 'note from a blocked sender', store: aStore, relayBase: RELAY, fetchImpl,
  });
  assert.equal(sent.deposited, true); // the sender CAN deposit; the RECEIVER's admission must drop it

  const summary = await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(summary.notes, 0, 'a blocked sender note is NOT persisted');
  assert.equal(bStore.listNotes().length, 0, 'nothing in the inbox from a blocked sender');
  assert.equal(bStore.listThreads().length, 0, 'no thread created for a blocked sender');
});

test('headless RECEIVE anti-rollback (#3 monotonic): a replayed STALE "trust" cannot revive a newer "break" (no false-Mutual)', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl } = mockRelay();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A, { trusted: true, trust_level: 'trusted' })); // B trusts A → an affirm can reach mutual

  const OLD = '2026-10-10T10:00:00.000Z';
  const NEW = '2026-10-10T11:00:00.000Z';
  const base = {
    senderFingerprint: A.fp, senderPublicKeyArmored: A.pub, senderPrivateKeyArmored: A.priv, passphrase: A.kpass,
    senderPqKemPublicKey: A.kem, senderPqSigPublicKey: A.sig,
    peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, relayBase: RELAY, fetchImpl,
  };

  // 1) A affirms trust (OLD) → B applies → they_trust_me TRUE.
  await sendTrustAffirmToPeer({ ...base, trusts: true, affirmId: 'af_trust_old', sentAt: OLD });
  await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(bStore.getContactByFingerprint(A.fp)!.mutual?.they_trust_me, true, 'trust applied');

  // 2) A BREAKS trust (NEW > OLD) → B applies → they_trust_me FALSE (the survivor revokes).
  await sendTrustAffirmToPeer({ ...base, trusts: false, affirmId: 'af_break_new', sentAt: NEW });
  await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(bStore.getContactByFingerprint(A.fp)!.mutual?.they_trust_me, false, 'break applied — trust revoked');

  // 3) REPLAY the stale OLD "trust" (sent_at=OLD < last-applied NEW, back-dated or captured-and-replayed).
  //    MUST be dropped — a superseded affirmation can never resurrect revoked trust.
  await sendTrustAffirmToPeer({ ...base, trusts: true, affirmId: 'af_trust_old_replay', sentAt: OLD });
  const summary = await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });

  assert.equal(summary.affirmed, 0, 'the stale replayed trust is NOT applied');
  assert.equal(summary.dropped, 1, 'it is dropped terminally (superseded by the newer break)');
  assert.equal(summary.acked, 1, 'and acked away — not left to replay forever');
  const a = bStore.getContactByFingerprint(A.fp)!;
  assert.equal(a.mutual?.they_trust_me, false, 'ANTI-ROLLBACK: a replayed stale affirmation cannot resurrect broken trust');
  assert.equal(a.mutual?.last_affirm_at, NEW, 'the per-sender monotonic cursor stayed at the newest applied affirm');
});

test('headless anti-rollback NaN-hardening (#3): a GARBAGE-timestamp affirm is dropped — no false-Mutual revival, no cursor poison', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl } = mockRelay();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A, { trusted: true, trust_level: 'trusted' }));
  const base = {
    senderFingerprint: A.fp, senderPublicKeyArmored: A.pub, senderPrivateKeyArmored: A.priv, passphrase: A.kpass,
    senderPqKemPublicKey: A.kem, senderPqSigPublicKey: A.sig,
    peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, relayBase: RELAY, fetchImpl,
  };
  const OLD = '2026-10-10T10:00:00.000Z';
  const NEW = '2026-10-10T11:00:00.000Z';

  // A trusts (OLD) then BREAKS (NEW) → they_trust_me false, cursor = NEW.
  await sendTrustAffirmToPeer({ ...base, trusts: true, affirmId: 't1', sentAt: OLD });
  await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  await sendTrustAffirmToPeer({ ...base, trusts: false, affirmId: 'b1', sentAt: NEW });
  await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(bStore.getContactByFingerprint(A.fp)!.mutual?.they_trust_me, false, 'break applied — trust revoked');

  // HOSTILE: the (in-book) sender signs a "trust" with a GARBAGE sent_at. Unguarded, Date.parse→NaN would
  // make `NaN < NEW` false → the malformed affirm would APPLY (revive trust) and poison the cursor.
  await sendTrustAffirmToPeer({ ...base, trusts: true, affirmId: 'garbage', sentAt: 'not-a-timestamp' });
  const s = await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(s.affirmed, 0, 'the garbage-timestamp affirm is NOT applied');
  assert.equal(s.dropped, 1, 'it is dropped terminally (malformed sent_at fails the finite guard)');
  const a = bStore.getContactByFingerprint(A.fp)!;
  assert.equal(a.mutual?.they_trust_me, false, 'NO false-Mutual revival — trust stays revoked');
  assert.equal(a.mutual?.last_affirm_at, NEW, 'the cursor is NOT poisoned — it stays at the last VALID affirm');

  // Proof the cursor survived intact: a replayed legit OLD trust is still correctly dropped (< NEW).
  await sendTrustAffirmToPeer({ ...base, trusts: true, affirmId: 't1replay', sentAt: OLD });
  await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });
  assert.equal(bStore.getContactByFingerprint(A.fp)!.mutual?.they_trust_me, false, 'ordering still enforced — garbage never defeated it');
});

test('headless RECEIVE: a BLOCKED in-book sender\'s AFFIRM is dropped — no flip (survivor-safety, affirm seam symmetry)', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl } = mockRelay();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A, { trusted: true, trust_level: 'trusted', blocked: true })); // in book but BLOCKED

  await sendTrustAffirmToPeer({
    senderFingerprint: A.fp, senderPublicKeyArmored: A.pub, senderPrivateKeyArmored: A.priv, passphrase: A.kpass,
    senderPqKemPublicKey: A.kem, senderPqSigPublicKey: A.sig,
    peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, trusts: true, relayBase: RELAY, fetchImpl,
  });
  const s = await pollHeadlessOnce(owner(B), bStore, { relayBase: RELAY, fetchImpl });

  assert.equal(s.affirmed, 0, 'a BLOCKED sender\'s affirmation is NOT applied (admitContact: in-book AND not-blocked)');
  assert.equal(s.dropped, 1, 'dropped terminally — a blocked person cannot re-establish trust via the affirm seam');
  assert.notEqual(bStore.getContactByFingerprint(A.fp)!.mutual?.they_trust_me, true, 'blocked sender cannot flip they_trust_me');
});

test('headless SEND: deposits to the peer fp-derived mailbox (relay-independent addressing)', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl, boxes } = mockRelay();
  await sendTrustAffirmToPeer({
    senderFingerprint: A.fp, senderPublicKeyArmored: A.pub, senderPrivateKeyArmored: A.priv, passphrase: A.kpass,
    senderPqKemPublicKey: A.kem, senderPqSigPublicKey: A.sig,
    peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, trusts: true, relayBase: RELAY, fetchImpl,
  });
  assert.ok(boxes.has(deriveMailboxId(B.fp)), 'deposited to B\'s fp-derived mailbox id');
  assert.equal(boxes.get(deriveMailboxId(B.fp))!.length, 1);
});
