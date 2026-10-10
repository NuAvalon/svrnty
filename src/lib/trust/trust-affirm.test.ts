// src/lib/trust/trust-affirm.test.ts
// Run: npx tsx --test src/lib/trust/trust-affirm.test.ts
//
// Proves the trust-affirmation AUTHN floor (mirrors note-auth.test): a valid signed affirmation
// verifies; every forgery/tamper/unsigned/wrong-domain/fp-mismatch is refused fail-closed. Real
// canonical identities via mintHeadlessAgent (the proven headless path).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { signWithEnvelope } from '@/lib/crypto/sign-envelope';
import {
  DOMAIN_TRUST_AFFIRM,
  TRUST_AFFIRM_WIRE_TYPE,
  trustAffirmSigningInput,
  signTrustAffirm,
  verifyTrustAffirmSender,
  type TrustAffirmWireV0,
} from './trust-affirm';

type Signer = {
  fp: string;
  pub: string;
  priv: string;
  kpass: string;
  kem: string;
  sig: string;
};

async function signerFromMint(): Promise<Signer> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id: any = a.introduction.card.identity;
  return {
    fp: id.fingerprint,
    pub: id.public_key,
    priv: a.secret_material.classicalPrivateKey,
    kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key,
    sig: id.pq_sig_public_key,
  };
}

function baseWire(fromFp: string, toFp: string, trusts: boolean): TrustAffirmWireV0 {
  return {
    type: TRUST_AFFIRM_WIRE_TYPE,
    affirm_id: 'af_test_0001',
    from_fingerprint: fromFp,
    to_fingerprint: toFp,
    trusts,
    sent_at: '2026-10-10T03:20:00.000Z',
  };
}

async function sign(a: Signer, wire: TrustAffirmWireV0): Promise<TrustAffirmWireV0> {
  return signTrustAffirm(wire, a.pub, a.priv, a.kpass, a.kem, a.sig);
}

test('valid signed affirmation (canonical sender) verifies', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const signed = await sign(A, baseWire(A.fp, B.fp, true));
  assert.equal(await verifyTrustAffirmSender(signed), true);
});

test('a break affirmation (trusts=false) verifies too', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const signed = await sign(A, baseWire(A.fp, B.fp, false));
  assert.equal(await verifyTrustAffirmSender(signed), true);
});

test('tampering `trusts` (true→false) breaks verification', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const signed = await sign(A, baseWire(A.fp, B.fp, true));
  const tampered = { ...signed, trusts: false };
  assert.equal(await verifyTrustAffirmSender(tampered), false);
});

test('tampering `to_fingerprint` breaks verification', async () => {
  const [A, B, C] = [await signerFromMint(), await signerFromMint(), await signerFromMint()];
  const signed = await sign(A, baseWire(A.fp, B.fp, true));
  const tampered = { ...signed, to_fingerprint: C.fp };
  assert.equal(await verifyTrustAffirmSender(tampered), false);
});

test('unsigned (no signature/public_key) is refused', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  assert.equal(await verifyTrustAffirmSender(baseWire(A.fp, B.fp, true)), false);
});

test('fp↔key mismatch (A fingerprint paired with B key) is refused', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  // Sign with B's key but claim A's fingerprint — fingerprintMatchesKey must reject before the sig.
  const wire = baseWire(A.fp, B.fp, true);
  const forged: TrustAffirmWireV0 = {
    ...wire,
    public_key: B.pub,
    pq_kem_public_key: B.kem,
    pq_sig_public_key: B.sig,
    signature: await signWithEnvelope(DOMAIN_TRUST_AFFIRM, trustAffirmSigningInput(wire), B.priv, B.kpass),
  };
  assert.equal(await verifyTrustAffirmSender(forged), false);
});

test('wrong-domain signature (signed under DOMAIN_NOTE-ish tag) is refused', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const wire = baseWire(A.fp, B.fp, true);
  const wrongDomainSig = await signWithEnvelope('svrnty:note:v0', trustAffirmSigningInput(wire), A.priv, A.kpass);
  const forged: TrustAffirmWireV0 = { ...wire, public_key: A.pub, pq_kem_public_key: A.kem, pq_sig_public_key: A.sig, signature: wrongDomainSig };
  assert.equal(await verifyTrustAffirmSender(forged), false);
});

test('wrong wire type is refused', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const signed = await sign(A, baseWire(A.fp, B.fp, true));
  assert.equal(await verifyTrustAffirmSender({ ...signed, type: 'svrnty-note-v0' as any }), false);
});
