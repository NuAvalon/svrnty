// src/lib/trust/joiner-open-legs.test.ts
// #720 (Archie #2056): the JOINER seam's opener reports which leg opened, because joining is exactly where an old client still shows up.
// Real keys, real sealing. Run: npx tsx --test src/lib/trust/joiner-open-legs.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { deriveOwnerHybridSecrets } from '@/lib/crypto/living-book-receive';
import { uint8ToBase64 } from '@/lib/crypto/pq';
import { encryptJoinerResponseClassicalFixture, encryptContactUpdateClassicalFixture } from '@/lib/messaging/seal-classical-fixture';
import { buildJoinerResponse, encryptJoinerResponseTo, verifyJoinerResponse } from './joiner-response';
import { createOpenLegCounter } from '@/lib/sync/open-leg-counter';

type Id = { fp: string; pub: string; priv: string; pass: string; kem: string; kemSec: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id = a.introduction.card.identity as unknown as { fingerprint: string; public_key: string; pq_kem_public_key: string; pq_sig_public_key: string };
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, pass: a.secret_material.classicalKpass, kem: id.pq_kem_public_key, kemSec: uint8ToBase64(a.secret_material.mlkem1024Sec), sig: id.pq_sig_public_key };
}
const CODE = 'invite-code-1';

async function signedFrom(bob: Id, alice: Id) {
  return buildJoinerResponse(
    { joinerFp: bob.fp, joinerEpoch: 1, joinerPubKeyArmored: bob.pub, joinerName: 'Bob', giverFp: alice.fp, inviteNonce: CODE, ts: '2026-10-30T12:00:00Z', joinerPqKemPublicKey: bob.kem, joinerPqSigPublicKey: bob.sig },
    bob.priv, bob.pass,
  );
}

test('J1 a HYBRID joiner response opens on the hybrid leg (1/0); a CLASSICAL one on the classical leg (0/1); junk on neither; verification still succeeds either way', async () => {
  const [alice, bob] = [await mint(), await mint()];
  const hybrid = await deriveOwnerHybridSecrets(alice.priv, alice.pass, alice.kem, alice.kemSec);
  assert.ok(hybrid);
  const signed = await signedFrom(bob, alice);
  const hybridBlob = await encryptJoinerResponseTo(signed, alice.pub, alice.kem);
  const classicalBlob = await encryptJoinerResponseClassicalFixture(signed, alice.pub);
  const verify = async (blob: string, withSecret: boolean) => {
    const c = createOpenLegCounter();
    const pj = await verifyJoinerResponse(blob, { fingerprint: alice.fp, privateKeyArmored: alice.priv, passphrase: alice.pass, hybrid: withSecret ? hybrid! : undefined, onOpenLeg: (l) => c.bump(l) }, (n) => n === CODE, { requirePq: false });
    return { pj, legs: c.take() };
  };
  const h = await verify(hybridBlob, true);
  assert.ok(h.pj); assert.deepEqual(h.legs, { hybrid: 1, classical: 0 });
  const c = await verify(classicalBlob, true);
  assert.ok(c.pj, 'the old-style response is still accepted (compat) ...'); assert.deepEqual(c.legs, { hybrid: 0, classical: 1 }, '... and COUNTED as classical');
  const noSecret = await verify(classicalBlob, false);
  assert.deepEqual(noSecret.legs, { hybrid: 0, classical: 1 }, 'an owner with no ML-KEM secret opens classical only');
  const junk = await verify('not-a-blob', true);
  assert.equal(junk.pj, null); assert.deepEqual(junk.legs, { hybrid: 0, classical: 0 });
  const noCounter = await verifyJoinerResponse(classicalBlob, { fingerprint: alice.fp, privateKeyArmored: alice.priv, passphrase: alice.pass }, (n) => n === CODE, { requirePq: false });
  assert.ok(noCounter, 'no callback: behaviour unchanged');
});

test('J2 a callback that throws never changes what opens', async () => {
  const [alice, bob] = [await mint(), await mint()];
  const classicalBlob = await encryptJoinerResponseClassicalFixture(await signedFrom(bob, alice), alice.pub);
  const pj = await verifyJoinerResponse(classicalBlob, { fingerprint: alice.fp, privateKeyArmored: alice.priv, passphrase: alice.pass, onOpenLeg: () => { throw new Error('counter fault'); } }, (n) => n === CODE, { requirePq: false });
  assert.ok(pj);
});

test('J3 static: the live joiner seam wires the shared counter (buildConsumeDeps passes legs to buildJoinerSeam)', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../sync/live-book-poll.ts', import.meta.url), 'utf8');
  assert.match(src, /joiner: buildJoinerSeam\(owner, codes, hybrid, legs\)/);
  assert.match(src, /onOpenLeg: legs \? \(leg\) => legs\.bump\(leg\) : undefined/);
});

test('J4 a blob that DECRYPTS but is not a joiner response (a classical contact-update) is NOT counted by the joiner opener, so it cannot be double-counted with the contact-update opener', async () => {
  const [alice, bob] = [await mint(), await mint()];
  const blob = await encryptContactUpdateClassicalFixture({ envelope: { fingerprint: bob.fp } } as never, alice.pub);
  const c = createOpenLegCounter();
  const pj = await verifyJoinerResponse(blob, { fingerprint: alice.fp, privateKeyArmored: alice.priv, passphrase: alice.pass, onOpenLeg: (l) => c.bump(l) }, (n) => n === CODE, { requirePq: false });
  assert.equal(pj, null);
  assert.deepEqual(c.take(), { hybrid: 0, classical: 0 });
});
