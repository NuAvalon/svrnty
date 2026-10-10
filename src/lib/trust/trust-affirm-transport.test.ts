// src/lib/trust/trust-affirm-transport.test.ts
// Run: npx tsx --test src/lib/trust/trust-affirm-transport.test.ts
//
// END-TO-END (crypto/transport) round-trip of the FULL mutual-trust wire, minus the two pieces that
// genuinely need a browser (the IndexedDB updateContact + the UI trust button): A deposits a signed
// affirmation (sendTrustAffirmToPeer) → the relay carries the opaque blob → B decrypts it with its own
// type-checked decryptor → acceptTrustAffirm authenticates + binds-to-B + admits + flips. Proves the
// deposit side produces exactly what the consume side admits, with real canonical identities.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { TRUST_AFFIRM_WIRE_TYPE } from './trust-affirm';
import { sendTrustAffirmToPeer } from './trust-affirm-transport';
import { trustAffirmOpenpgpDecryptor } from './trust-affirm-seal';
import { acceptTrustAffirm, type MutualApplyResult } from './trust-affirm-consume';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';

type Signer = { fp: string; pub: string; priv: string; kpass: string; kem: string; sig: string };
async function signerFromMint(): Promise<Signer> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id: any = a.introduction.card.identity;
  return {
    fp: id.fingerprint, pub: id.public_key,
    priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, sig: id.pq_sig_public_key,
  };
}

/** A fake relay that captures the single deposited {mailbox_id, blob}. */
function capturingFetch(cap: { mailbox_id?: string; blob?: string }): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/envelope')) {
      const body = JSON.parse(String(init?.body ?? '{}'));
      cap.mailbox_id = body.mailbox_id;
      cap.blob = body.blob;
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
}

function spyApply(iTrustThem: boolean) {
  const calls: Array<{ fp: string; trusts: boolean }> = [];
  const applyMutual = async (fp: string, trusts: boolean): Promise<MutualApplyResult> => {
    calls.push({ fp, trusts });
    return { id: 'rec_' + fp.slice(0, 6), reciprocal: iTrustThem && trusts };
  };
  return { calls, applyMutual };
}

test('deposit → relay → consume → FLIP: A trusts B, B already trusts A → mutual', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const cap: { mailbox_id?: string; blob?: string } = {};

  // A deposits "I trust B".
  const dep = await sendTrustAffirmToPeer({
    senderFingerprint: A.fp, senderPublicKeyArmored: A.pub, senderPrivateKeyArmored: A.priv, passphrase: A.kpass,
    senderPqKemPublicKey: A.kem, senderPqSigPublicKey: A.sig,
    peerFingerprint: B.fp, peerPublicKeyArmored: B.pub,
    trusts: true, affirmId: 'af_rt_1', sentAt: '2026-10-10T03:20:00.000Z',
    relayBase: 'http://relay.test/api/relay', fetchImpl: capturingFetch(cap),
  });
  assert.equal(dep.deposited, true, 'the affirmation deposited to the relay');
  assert.equal(cap.mailbox_id, deriveMailboxId(B.fp), 'deposited to B\'s mailbox (fp-derived, relay-independent)');
  assert.ok(cap.blob, 'the relay carries an opaque sealed blob (content-blind)');

  // B decrypts with its OWN type-checked decryptor + consumes (A is in B's book; B already trusts A).
  const wire = await trustAffirmOpenpgpDecryptor(B.priv, B.kpass)(cap.blob!);
  assert.ok(wire, 'B decrypts the affirmation');
  assert.equal(wire?.type, TRUST_AFFIRM_WIRE_TYPE);
  assert.equal(wire?.from_fingerprint, A.fp);
  assert.equal(wire?.to_fingerprint, B.fp);

  const apply = spyApply(/* B already trusts A */ true);
  const out = await acceptTrustAffirm({ wire: wire!, ownerFingerprint: B.fp, isAdmitted: async () => true, applyMutual: apply.applyMutual });
  assert.ok(out, 'B admitted + applied the flip');
  assert.equal(out?.reciprocal, true, 'both sides trust → the edge is MUTUAL (awaiting-mutual resolves)');
  assert.deepEqual(apply.calls, [{ fp: A.fp, trusts: true }]);
});

test('deposit → consume: a BREAK affirmation round-trips and clears reciprocal', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const cap: { mailbox_id?: string; blob?: string } = {};
  await sendTrustAffirmToPeer({
    senderFingerprint: A.fp, senderPublicKeyArmored: A.pub, senderPrivateKeyArmored: A.priv, passphrase: A.kpass,
    senderPqKemPublicKey: A.kem, senderPqSigPublicKey: A.sig,
    peerFingerprint: B.fp, peerPublicKeyArmored: B.pub,
    trusts: false, affirmId: 'af_rt_2', sentAt: '2026-10-10T03:20:00.000Z',
    relayBase: 'http://relay.test/api/relay', fetchImpl: capturingFetch(cap),
  });
  const wire = await trustAffirmOpenpgpDecryptor(B.priv, B.kpass)(cap.blob!);
  assert.equal(wire?.trusts, false, 'the break direction survives the round-trip (signed)');
  const apply = spyApply(true);
  const out = await acceptTrustAffirm({ wire: wire!, ownerFingerprint: B.fp, isAdmitted: async () => true, applyMutual: apply.applyMutual });
  assert.equal(out?.reciprocal, false, 'break clears reciprocal');
  assert.deepEqual(apply.calls, [{ fp: A.fp, trusts: false }]);
});

test('deposit → consume: a deposited affirmation from a STRANGER is dropped at B (no flip)', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const cap: { mailbox_id?: string; blob?: string } = {};
  await sendTrustAffirmToPeer({
    senderFingerprint: A.fp, senderPublicKeyArmored: A.pub, senderPrivateKeyArmored: A.priv, passphrase: A.kpass,
    senderPqKemPublicKey: A.kem, senderPqSigPublicKey: A.sig,
    peerFingerprint: B.fp, peerPublicKeyArmored: B.pub,
    trusts: true, affirmId: 'af_rt_3', sentAt: '2026-10-10T03:20:00.000Z',
    relayBase: 'http://relay.test/api/relay', fetchImpl: capturingFetch(cap),
  });
  const wire = await trustAffirmOpenpgpDecryptor(B.priv, B.kpass)(cap.blob!);
  const apply = spyApply(true);
  // A is NOT in B's book → the FALSE-MUTUAL gate drops it.
  const out = await acceptTrustAffirm({ wire: wire!, ownerFingerprint: B.fp, isAdmitted: async () => false, applyMutual: apply.applyMutual });
  assert.equal(out, null, 'a verified affirmation from a non-contact does not flip anything');
  assert.deepEqual(apply.calls, []);
});
