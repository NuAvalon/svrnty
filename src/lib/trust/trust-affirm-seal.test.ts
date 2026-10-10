// src/lib/trust/trust-affirm-seal.test.ts
// Run: npx tsx --test src/lib/trust/trust-affirm-seal.test.ts
//
// Proves the trust-affirmation OpenPGP envelope (increment 2) round-trips AND is a clean
// consume-dispatch discriminator: a sealed affirmation decrypts ONLY via its own type-checked
// decryptor, and a note sealed with the SAME envelope returns null (→ falls through, never eaten as an
// affirmation) — and vice versa. This is the real-crypto half of the 4-way no-cross-swallow property.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { signTrustAffirm, TRUST_AFFIRM_WIRE_TYPE, type TrustAffirmWireV0 } from './trust-affirm';
import { sealTrustAffirmTo, trustAffirmOpenpgpDecryptor } from './trust-affirm-seal';
import { sealNoteTo, noteOpenpgpDecryptor } from '@/lib/messaging/seal';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import type { NoteWireV0 } from '@/lib/messaging/types';

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

async function signedAffirm(from: Signer, toFp: string, trusts = true): Promise<TrustAffirmWireV0> {
  const wire: TrustAffirmWireV0 = {
    type: TRUST_AFFIRM_WIRE_TYPE,
    affirm_id: 'af_seal_0001',
    from_fingerprint: from.fp,
    to_fingerprint: toFp,
    trusts,
    sent_at: '2026-10-10T03:20:00.000Z',
  };
  return signTrustAffirm(wire, from.pub, from.priv, from.kpass, from.kem, from.sig);
}

test('a sealed affirmation round-trips through its own decryptor (fields intact)', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const affirm = await signedAffirm(A, B.fp, true);
  const blob = await sealTrustAffirmTo(affirm, B.pub);
  const dec = trustAffirmOpenpgpDecryptor(B.priv, B.kpass);

  const out = await dec(blob);
  assert.ok(out, 'the sealed affirmation decrypts to a TrustAffirmWireV0');
  assert.equal(out?.type, TRUST_AFFIRM_WIRE_TYPE);
  assert.equal(out?.from_fingerprint, A.fp);
  assert.equal(out?.to_fingerprint, B.fp);
  assert.equal(out?.trusts, true);
  assert.ok(out?.signature, 'the sender signature survives the envelope (authn checked downstream)');
});

test('DISCRIMINATOR: the affirm decryptor returns null for a real sealed NOTE (falls through)', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const note: NoteWireV0 = {
    type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1',
    from_fingerprint: A.fp, sent_at: '2026-10-10T03:20:00.000Z', body: 'hi', participant_kind: 'human',
  };
  const noteBlob = await sealNoteTo(note, B.pub); // SAME openpgp envelope
  const affirmDec = trustAffirmOpenpgpDecryptor(B.priv, B.kpass);
  assert.equal(await affirmDec(noteBlob), null, 'a note is NOT eaten as an affirmation (type gate)');
});

test('DISCRIMINATOR: the note decryptor returns null for a real sealed AFFIRMATION (falls through)', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const affirm = await signedAffirm(A, B.fp, true);
  const affirmBlob = await sealTrustAffirmTo(affirm, B.pub); // SAME openpgp envelope
  const noteDec = noteOpenpgpDecryptor(B.priv, B.kpass);
  assert.equal(await noteDec(affirmBlob), null, 'an affirmation is NOT eaten as a note (type gate)');
});

test('the affirm decryptor returns null on garbage / wrong-key (fail-closed, no throw)', async () => {
  const B = await signerFromMint();
  const dec = trustAffirmOpenpgpDecryptor(B.priv, B.kpass);
  assert.equal(await dec('not-a-pgp-blob'), null);
});

test('sealTrustAffirmTo refuses a non-affirm wire type (fail-loud)', async () => {
  const B = await signerFromMint();
  const notAffirm = { type: 'svrnty-note-v0', from_fingerprint: 'x', to_fingerprint: B.fp, trusts: true } as unknown as TrustAffirmWireV0;
  await assert.rejects(() => sealTrustAffirmTo(notAffirm, B.pub), /refusing non-affirm/);
});
