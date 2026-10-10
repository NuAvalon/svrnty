// src/lib/headless/headless-no-silent-loss.test.ts
// Run: npx tsx --test src/lib/headless/headless-no-silent-loss.test.ts
//
// THE isPQEncapLive FLIP-GATE TEST (Apollo writes, Flint co-verifies adversarially — spec #168282 ④).
// Discriminating no-silent-loss for the HEADLESS receive path. The gate case Flint set the bar on:
//
//   A hybrid blob delivered to a consume with NO owner ML-KEM secret (a headless agent pre-custody-①,
//   OR a kem-advertising FE whose secret-load failed) must NOT be silently acked+dropped. It must be
//   LEFT FOR RETRY (or loud-error) — never silently deleted. advertise-kem-pub ⟹ MUST open hybrid;
//   a missing-but-advertised secret is LOUD, never a silent classical degrade.
//
// IMPL-AGNOSTIC OBSERVABLE (grounded in consume-mailbox.consumeOne): a 'terminal' outcome is pushed to
// toAck → the relay ack-DELETES the blob (silent loss). A 'retryable' outcome is NOT acked → the blob
// REMAINS in the mailbox for a later poll. So "no-silent-loss" = the blob is STILL IN THE MAILBOX after
// the poll (and was not acked). This asserts the BEHAVIOUR that matters (not deleted), independent of
// whatever summary bookkeeping field the ③ invariant adds.
//
// STATE: RED until Flint's ③ loud-not-silent invariant lands in consumeOne (undecryptable blob that IS a
// MailboxEnvelopePackage + owner advertises a kem pub but can't derive hybrid secrets ⇒ 'retryable', not
// 'terminal'). GREEN = the isPQEncapLive flip gate is met on the headless receive path. Today it FAILS,
// and that failure is the proof the silent-loss bug is real (the classical-only headless openers ack-drop
// the hybrid blob). The happy-path companion (secret present ⇒ OPENS) lands with Athena ① + the
// buildHeadlessConsumeDeps dualReadOpener compose — added below when those are in.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, pollHeadlessOnce, sendNoteFromHeadless } from './headless-client';

const RELAY = 'http://relay.test/api/relay';

type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id: any = a.introduction.card.identity;
  return {
    fp: id.fingerprint, pub: id.public_key,
    priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key,
  };
}
// B advertises a kem pub (mint gives one) but carries NO kem SECRET on its OwnerIdentity — the exact
// pre-① headless state: senders WILL hybrid-seal to it, and it currently can't open the result.
function ownerKemAdvertisedNoSecret(id: Id): HeadlessOwner {
  return {
    fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass,
    kemPublicKey: id.kem, sigPublicKey: id.sig, // kem PUB advertised; NO kem secret
  };
}
// B carries its ML-KEM SECRET on OwnerIdentity (custody ① threaded it) — the post-① state: it can OPEN
// the hybrid blobs senders seal to its advertised kem pub.
function ownerWithSecret(id: Id): HeadlessOwner {
  return {
    fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass,
    kemPublicKey: id.kem, kemSecretKey: id.kemSec, sigPublicKey: id.sig,
  };
}
function asContact(id: Id, over: Partial<HeadlessContact> = {}): HeadlessContact {
  return { id: 'c_' + id.fp.slice(0, 8), fingerprint: id.fp, public_key: id.pub, pq_sig_public_key: id.sig, pq_kem_public_key: id.kem, ...over };
}

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

test('FLIP-GATE: hybrid note to a kem-advertising headless owner with NO secret → LEFT FOR RETRY, never silent-ack-drop', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl, boxes } = mockRelay();
  const bStore = new HeadlessStore({ allowPlaintext: true });
  const mailboxB = deriveMailboxId(B.fp);

  // A hybrid-seals a note to B (B advertises a kem pub, so the send goes PQ-hybrid — my send-swap).
  const sent = await sendNoteFromHeadless({
    owner: ownerKemAdvertisedNoSecret(A),
    peerFingerprint: B.fp,
    peerPublicKeyArmored: B.pub,
    peerPqKemPublicKey: B.kem,
    body: 'inbound hybrid to an agent that cannot yet open it',
    store: new HeadlessStore({ allowPlaintext: true }),
    relayBase: RELAY,
    fetchImpl,
  });
  assert.equal(sent.deposited, true, 'precondition: the hybrid blob was deposited to B');
  assert.equal((boxes.get(mailboxB) ?? []).length, 1, 'precondition: one hybrid blob waiting for B');

  // B polls headlessly — but its OwnerIdentity carries NO kem secret, so it cannot open the hybrid blob.
  const summary = await pollHeadlessOnce(ownerKemAdvertisedNoSecret(B), bStore, { relayBase: RELAY, fetchImpl });

  // THE GATE: the undecryptable-but-hybrid blob must be LEFT FOR RETRY, never silently acked+dropped.
  assert.equal(
    (boxes.get(mailboxB) ?? []).length,
    1,
    'NO-SILENT-LOSS: the hybrid blob is LEFT IN THE MAILBOX for retry — not acked+deleted',
  );
  assert.equal(summary.acked, 0, 'the hybrid blob was NOT acked (advertise-kem ⟹ must-open; missing secret is loud, not a silent drop)');
  assert.equal(summary.notes, 0, 'and it was not (and must not be) fabricated as delivered while unopened');
});

test('FLIP-GATE (happy path, post-①): hybrid note to a headless owner WITH its kem secret → OPENS + persists + acks (never retryable-forever)', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl, boxes } = mockRelay();
  const bStore = new HeadlessStore({ allowPlaintext: true });
  bStore.upsertContact(asContact(A)); // A in B's book so an opened note is admitted + persisted
  const mailboxB = deriveMailboxId(B.fp);

  const sent = await sendNoteFromHeadless({
    owner: ownerWithSecret(A),
    peerFingerprint: B.fp,
    peerPublicKeyArmored: B.pub,
    peerPqKemPublicKey: B.kem,
    body: 'hybrid hello an agent CAN open',
    store: new HeadlessStore({ allowPlaintext: true }),
    relayBase: RELAY,
    fetchImpl,
  });
  assert.equal(sent.deposited, true);
  assert.equal((boxes.get(mailboxB) ?? []).length, 1, 'precondition: one hybrid blob waiting');

  // B WITH its ML-KEM secret polls — the dualReadOpener OPENS the hybrid blob (hybridSecretMissing=false,
  // so Flint's ③ does NOT intercept it; it decrypts, verifies, admits, persists, and acks).
  const summary = await pollHeadlessOnce(ownerWithSecret(B), bStore, { relayBase: RELAY, fetchImpl });

  // OPENS + delivers, the flip-side of no-silent-loss: a secret-HAVING agent must NOT loop its mail
  // retryable-forever. The note is persisted, the blob is acked + removed — proof hybridSecretMissing is
  // keyed on derivability (false here), not on mere kem-pub presence.
  assert.equal(summary.notes, 1, 'the hybrid note was OPENED + persisted (dualReadOpener hybrid path)');
  assert.equal(summary.acked, 1, 'the blob was acked (consumed), NOT left retryable-forever');
  assert.equal((boxes.get(mailboxB) ?? []).length, 0, 'blob removed from the mailbox — processed, not stuck');
  const inbound = bStore.listNotes();
  assert.equal(inbound.length, 1);
  assert.equal(inbound[0].direction, 'inbound');
  assert.equal(inbound[0].body, 'hybrid hello an agent CAN open');
  assert.equal(inbound[0].from_fingerprint, A.fp);
});
