// src/lib/headless/headless-seal-intake.test.ts
// Run: npx tsx --test src/lib/headless/headless-seal-intake.test.ts
//
// dh-fleet-comms §route anchors for the seal-only sibling + the intake consume-blob.
// R-1: sealNoteFromHeadless returns THE wire blob — the same sealed bytes whichever route carries
//      them; never a local plaintext variant; kem-less recipient is still fail-closed (blob:null).
// R-4: consumeInboundBlob runs the SAME consumeOne decision the relay fold uses — a delivered blob
//      folds note→store exactly as if the relay had carried it; 'retryable' = undecided, relay parks
//      it; 'terminal' = decided-drop, still consumed.
// REGRESSION: sendNoteFromHeadless still deposits the same bytes seal-note would hand a router.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { asMailboxEnvelopePackage } from '@/lib/sync/hybrid-dual-read';
import { consumeInboundBlob } from '@/lib/sync/consume-mailbox';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { HeadlessStore, type HeadlessContact } from './headless-store';
import { type HeadlessOwner, buildHeadlessConsumeDeps, sealNoteFromHeadless, sendNoteFromHeadless } from './headless-client';

const RELAY = 'http://relay.test/api/relay';

type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return {
    fp: id.fingerprint, pub: id.public_key,
    priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key,
  };
}
function owner(id: Id): HeadlessOwner {
  return {
    fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass,
    kemPublicKey: id.kem, kemSecretKey: id.kemSec, sigPublicKey: id.sig,
  };
}
function ownerKemAdvertisedNoSecret(id: Id): HeadlessOwner {
  return {
    fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass,
    kemPublicKey: id.kem, sigPublicKey: id.sig, // kem PUB advertised; NO kem secret (pre-custody-①)
  };
}
function asContact(id: Id, over: Partial<HeadlessContact> = {}): HeadlessContact {
  return { id: 'c_' + id.fp.slice(0, 8), fingerprint: id.fp, public_key: id.pub, pq_sig_public_key: id.sig, pq_kem_public_key: id.kem, ...over };
}

/** fetchImpl that records calls — a seal-only path must NEVER touch the relay. */
function recordingFetch() {
  const calls: string[] = [];
  const fetchImpl = (async (url: string) => {
    calls.push(String(url));
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

test('R-1: seal-note produces the PQ-hybrid wire blob + local copy and NEVER fetches', async () => {
  const [A, B] = [await mint(), await mint()];
  const aStore = new HeadlessStore();

  const r = await sealNoteFromHeadless({
    owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub,
    peerPqKemPublicKey: B.kem, body: 'router-bound', store: aStore,
  });

  assert.ok(r.blob && r.blob.length > 0, 'sealed blob returned');
  assert.ok(asMailboxEnvelopePackage(r.blob!) != null, 'blob is a raw-JSON MailboxEnvelopePackage (PQ-hybrid, HNDL)');
  assert.match(r.blob!, /ML-KEM-1024/, 'the sealed form, never a plaintext local variant');
  assert.ok(!r.blob!.includes('-----BEGIN'), 'not an armored/derived alternate form');
  const out = aStore.listNotes().filter((n) => n.direction === 'outbound');
  assert.equal(out.length, 1, 'the local outbound copy is still kept');
  assert.equal(out[0].body, 'router-bound');
});

test('R-1 fail-closed: kem-less peer → blob:null + local copy kept (never a classical seal)', async () => {
  const [A, B] = [await mint(), await mint()];
  const aStore = new HeadlessStore();
  const r = await sealNoteFromHeadless({
    owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub,
    body: 'no kem', store: aStore,
  });
  assert.equal(r.blob, null, 'no blob without a verified pq_kem — never downgrade');
  assert.equal(aStore.listNotes().filter((n) => n.direction === 'outbound').length, 1, 'local copy kept as not-sent');
});

test('R-1 regression: send deposits the SAME kind of blob seal-note returns (route-invariant form)', async () => {
  const [A, B] = [await mint(), await mint()];
  const { fetchImpl, calls } = recordingFetch();
  const aStore = new HeadlessStore();
  const sent = await sendNoteFromHeadless({
    owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub,
    peerPqKemPublicKey: B.kem, body: 'still deposits', store: aStore,
    relayBase: RELAY, fetchImpl,
  });
  assert.equal(sent.deposited, true);
  assert.ok(calls.some((u) => u.includes('/envelope')), 'the deposit POST happened');
});

test('R-4: a locally-delivered blob folds through consumeInboundBlob → note persisted, same as relay', async () => {
  const [A, B] = [await mint(), await mint()];
  const aStore = new HeadlessStore();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A)); // B has A in-book — the same admit gate the relay path enforces

  const sealed = await sealNoteFromHeadless({
    owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub,
    peerPqKemPublicKey: B.kem, body: 'local-delivery hello', store: aStore,
  });
  assert.ok(sealed.blob);

  const deps = await buildHeadlessConsumeDeps(owner(B), bStore, { relayBase: RELAY });
  const out = await consumeInboundBlob(deps, sealed.blob!);
  assert.equal(out.kind, 'note', 'a verified note from an admitted sender persists (the note outcome)');
  const inb = bStore.listNotes().filter((n) => n.direction === 'inbound');
  assert.equal(inb.length, 1);
  assert.equal(inb[0].body, 'local-delivery hello');
  assert.equal(inb[0].from_fingerprint, A.fp);

  // R-4 dedupe parity: the same blob folded again is idempotent at note_id — still exactly one inbound note.
  const again = await consumeInboundBlob(deps, sealed.blob!);
  assert.equal(again.kind, 'note');
  assert.equal(bStore.listNotes().filter((n) => n.direction === 'inbound').length, 1, 'note_id dedupe — redelivery folds to the same row');
});

test('R-4 retryable: a hybrid blob the receiver cannot open yet is UNDECIDED, never terminal', async () => {
  const [A, B] = [await mint(), await mint()];
  const aStore = new HeadlessStore();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A));
  const sealed = await sealNoteFromHeadless({
    owner: owner(A), peerFingerprint: B.fp, peerPublicKeyArmored: B.pub,
    peerPqKemPublicKey: B.kem, body: 'waits for custody', store: aStore,
  });
  assert.ok(sealed.blob);
  // B advertises kem but holds no secret → the ③ loud-not-silent gate: RETRYABLE (the intake replies
  // ok:false, the sender's router falls back to the relay where the envelope parks for a later poll).
  const deps = await buildHeadlessConsumeDeps(ownerKemAdvertisedNoSecret(B), bStore, { relayBase: RELAY });
  const out = await consumeInboundBlob(deps, sealed.blob!);
  assert.equal(out.kind, 'retryable');
  assert.equal(bStore.listNotes().filter((n) => n.direction === 'inbound').length, 0, 'nothing silently persisted');
});

test('R-4 terminal: garbage is decided-drop, not retryable and never persisted', async () => {
  const B = await mint();
  const bStore = new HeadlessStore();
  const deps = await buildHeadlessConsumeDeps(owner(B), bStore, { relayBase: RELAY });
  const out = await consumeInboundBlob(deps, 'this is not a sealed envelope');
  assert.equal(out.kind, 'terminal');
  assert.equal(bStore.listNotes().length, 0);
});
