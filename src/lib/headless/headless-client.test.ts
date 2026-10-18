// src/lib/headless/headless-client.test.ts
// Run: npx tsx --test src/lib/headless/headless-client.test.ts
//
// END-TO-END headless RECEIVE/POLL/SEND (L2b) against an in-memory mock relay — no browser, no IndexedDB.
// Two real canonical identities (mintHeadlessAgent): A sends a note to B; B polls its smart mailbox
// headlessly → decrypts → verifies → persists into a HeadlessStore. Plus the survivor-safety admit gate:
// a BLOCKED in-book sender's note is dropped on the receiver's admission.
//
// #593: the trust-affirmation RECEIVE/SEND tests were REMOVED with the affirm-wire (a device-held
// they_trust_me is false security; mutual is now PSI-discovered, #588). The chokepoint's retained behavior
// + the affirm-removal proof live in apply-trust-transition.test.ts.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import {
  type HeadlessOwner,
  pollHeadlessOnce,
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
