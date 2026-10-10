// src/lib/headless/headless-send-hybrid.test.ts
// Run: npx tsx --test src/lib/headless/headless-send-hybrid.test.ts
//
// L7 headless SEND seal-swap (Apollo). Proves sendNoteFromHeadless in ISOLATION — no receive side, so it
// is GREEN now, independent of the headless-RECEIVE compose + Athena's custody ① (owner ML-KEM secret).
// Two properties, mirroring messaging/transport.sendNoteToPeer's fail-closed contract so FE + headless
// sends behave identically:
//   • pq_kem PRESENT  ⇒ the deposited blob is a RAW-JSON MailboxEnvelopePackage (PQ-hybrid, HNDL),
//                        NOT armored OpenPGP; deposited:true; local outbound copy kept.
//   • pq_kem ABSENT   ⇒ fail-closed SKIP: nothing deposited (never a classical downgrade), deposited:false;
//                        the local outbound copy is STILL kept (as "not sent").
// The discriminating RECEIVE no-silent-loss gate (hybrid blob to a headless consume must OPEN or
// LEAVE-FOR-RETRY, never silent-ack-drop) is the roundtrip gate test — RED until the receive compose +
// ① land; GREEN = the isPQEncapLive flip. That one lives with the roundtrip suite, not here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { asMailboxEnvelopePackage } from '@/lib/sync/hybrid-dual-read';
import { HeadlessStore } from './headless-store';
import { type HeadlessOwner, sendNoteFromHeadless } from './headless-client';

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

/** In-memory smart mailbox: POST /envelope deposits; nothing else needed for a send-only proof. */
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
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, boxes };
}

test('headless SEND (hybrid): peer HAS pq_kem → deposits a RAW-JSON MailboxEnvelopePackage, not armored PGP', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl, boxes } = mockRelay();
  const aStore = new HeadlessStore({ allowPlaintext: true });

  const sent = await sendNoteFromHeadless({
    owner: owner(A),
    peerFingerprint: B.fp,
    peerPublicKeyArmored: B.pub,
    peerPqKemPublicKey: B.kem, // present ⇒ PQ-hybrid seal
    body: 'hybrid hello',
    store: aStore,
    relayBase: RELAY,
    fetchImpl,
  });

  assert.equal(sent.deposited, true, 'deposited when the recipient has a verified pq_kem');
  const box = boxes.get(deriveMailboxId(B.fp)) ?? [];
  assert.equal(box.length, 1, 'exactly one blob landed in B\'s fp-derived mailbox');

  const blob = box[0].blob;
  // The hybrid blob is the RAW-JSON MailboxEnvelopePackage (Flint seam-fix): the consume dual-read
  // discriminator JSON.parses it. An armored OpenPGP blob would NOT parse to this shape (= the silent-loss
  // bug Flint caught). Asserting the discriminator here is the send-side half of no-cross-format-loss.
  assert.ok(!blob.startsWith('-----BEGIN'), 'NOT armored PGP — raw JSON on the wire');
  const pkg = asMailboxEnvelopePackage(blob);
  assert.ok(pkg, 'deposited blob IS a MailboxEnvelopePackage (passes the consume discriminator)');
  assert.equal(pkg!.v, 1);
  assert.ok(pkg!.epk && pkg!.kem_ct && pkg!.nonce && pkg!.ct, 'has the X25519 epk + ML-KEM ct + GCM nonce/ct');

  // Local outbound copy is kept either way.
  const notes = aStore.listNotes();
  assert.equal(notes.length, 1, 'outbound copy persisted on the sender');
  assert.equal(notes[0].direction, 'outbound');
  assert.equal(notes[0].body, 'hybrid hello');
});

test('headless SEND (fail-closed): peer has NO pq_kem → NOT deposited (never downgrade), local copy kept as not-sent', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl, boxes } = mockRelay();
  const aStore = new HeadlessStore({ allowPlaintext: true });

  const sent = await sendNoteFromHeadless({
    owner: owner(A),
    peerFingerprint: B.fp,
    peerPublicKeyArmored: B.pub,
    // peerPqKemPublicKey intentionally OMITTED ⇒ fail-closed skip
    body: 'should not be deposited classical',
    store: aStore,
    relayBase: RELAY,
    fetchImpl,
  });

  assert.equal(sent.deposited, false, 'fail-closed: not deposited without a verified pq_kem');
  assert.equal((boxes.get(deriveMailboxId(B.fp)) ?? []).length, 0, 'NOTHING landed in the mailbox — no classical downgrade');

  // The user does not lose their message: the local outbound copy is still written (shown as "not sent").
  const notes = aStore.listNotes();
  assert.equal(notes.length, 1, 'local outbound copy kept even when the send is skipped');
  assert.equal(notes[0].direction, 'outbound');
});
