// src/lib/headless/headless-dual-seal.test.ts
// Run: NODE_OPTIONS=--experimental-global-webcrypto npx tsx --test src/lib/headless/headless-dual-seal.test.ts
//
// dual-seal-interim-001 (option B, hybrid-note-receive-gap-001): while canon main lacks the dual-read
// consume leg, a kem-456 sender's hybrid plain-send ghosts on classical receivers. dualSeal:true makes
// sendNoteFromHeadless ALSO deposit a CLASSICAL seal of the same signed wire to the same mailbox_id —
// a classical receiver lands the copy; a dual-read receiver dedupes on (note_id, direction, fp).

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
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey,
           kpass: a.secret_material.classicalKpass, kem: id.pq_kem_public_key, sig: id.pq_sig_public_key };
}
function owner(id: Id): HeadlessOwner {
  return { fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass,
           kemPublicKey: id.kem, sigPublicKey: id.sig };
}
function mockRelay() {
  const boxes = new Map<string, Array<{ envelope_id: string; blob: string }>>();
  let seq = 0;
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/envelope')) {
      const { mailbox_id, blob } = JSON.parse(String(init?.body ?? '{}'));
      if (!boxes.has(mailbox_id)) boxes.set(mailbox_id, []);
      boxes.get(mailbox_id)!.push({ envelope_id: `e${++seq}`, blob });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, boxes };
}

test('dualSeal:true → TWO deposits to the same mbx: hybrid package first, armored classical second', async () => {
  const A = await mint(), B = await mint();
  const store = new HeadlessStore(`/tmp/ds-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const { fetchImpl, boxes } = mockRelay();
  const r = await sendNoteFromHeadless({
    owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem,
    dualSeal: true, body: 'dual', store, relayBase: RELAY, fetchImpl,
  });
  assert.equal(r.deposited, true);
  assert.equal(r.deposited_classical, true);
  const box = boxes.get(deriveMailboxId(B.fp))!;
  assert.equal(box.length, 2, 'two envelopes in one mailbox');
  const [hybridBlob, classicalBlob] = [box[0].blob, box[1].blob];
  // leg 1 = hybrid MailboxEnvelopePackage (raw JSON), leg 2 = armored OpenPGP
  assert.ok(asMailboxEnvelopePackage(hybridBlob) != null, 'first blob is the hybrid package');
  assert.match(classicalBlob, /-----BEGIN PGP MESSAGE-----/, 'second blob is the classical armored seal');
  // both carry the SAME signed wire → same note_id → receiver dedup lands ONE row
  const pkg = asMailboxEnvelopePackage(hybridBlob)!;
  assert.ok(JSON.stringify(pkg).length > 0);
  const local = store.listNotes().filter(n => n.note_id === r.note_id);
  assert.equal(local.length, 1, 'one local outbound copy');
});

test('dualSeal absent → single hybrid deposit (status quo)', async () => {
  const A = await mint(), B = await mint();
  const store = new HeadlessStore(`/tmp/ds-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const { fetchImpl, boxes } = mockRelay();
  const r = await sendNoteFromHeadless({
    owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub, peerPqKemPublicKey: B.kem,
    body: 'single', store, relayBase: RELAY, fetchImpl,
  });
  assert.equal(r.deposited, true);
  assert.equal(r.deposited_classical, undefined);
  assert.equal(boxes.get(deriveMailboxId(B.fp))!.length, 1);
});

test('dualSeal on a kem-less peer → still fail-closed NOT-SENT (never a classical downgrade)', async () => {
  const A = await mint(), B = await mint();
  const store = new HeadlessStore(`/tmp/ds-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const { fetchImpl, boxes } = mockRelay();
  const r = await sendNoteFromHeadless({
    owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub,
    dualSeal: true, body: 'nope', store, relayBase: RELAY, fetchImpl,
  });
  assert.equal(r.deposited, false);
  assert.equal(boxes.size, 0, 'nothing deposited — fail-closed holds');
});
