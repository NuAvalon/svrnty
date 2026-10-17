// src/lib/trust/discoverable-consent-seal.test.ts
// Run: npx tsx --test src/lib/trust/discoverable-consent-seal.test.ts
//
// Proves the discoverable-consent OpenPGP envelope (trust-PSI increment #2, TRANSPORT half) round-trips
// AND is a clean consume-dispatch discriminator: a sealed consent decrypts ONLY via its own type-checked
// decryptor, and a note sealed with the SAME envelope returns null (→ falls through, never eaten as a
// consent) — and vice versa. The real-crypto half of the 6-way no-cross-swallow property. Carol's
// signature survives the envelope (re-verified downstream in applyDiscoverableConsent — not here).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { signDiscoverableConsent, CONSENT_SCOPE_GLOBAL, type DiscoverableConsent } from './discoverable-consent';
import {
  sealDiscoverableConsentTo,
  discoverableConsentOpenpgpDecryptor,
  DISCOVERABLE_CONSENT_WIRE_TYPE,
  type DiscoverableConsentWireV0,
} from './discoverable-consent-seal';
import { sealNoteTo, noteOpenpgpDecryptor } from '@/lib/messaging/seal';
import { NOTE_WIRE_TYPE } from '@/lib/messaging/domains';
import type { NoteWireV0 } from '@/lib/messaging/types';

type Signer = { fp: string; pub: string; priv: string; kpass: string };
async function signerFromMint(): Promise<Signer> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id: any = a.introduction.card.identity;
  return { fp: id.fingerprint, pub: id.public_key, priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass };
}

async function signedConsentWire(carol: Signer, discoverable = true, epoch = 1): Promise<DiscoverableConsentWireV0> {
  const consent: DiscoverableConsent = {
    subject_fp: carol.fp, epoch, discoverable, scope_tag: CONSENT_SCOPE_GLOBAL, scope_value: '',
  };
  const signed = await signDiscoverableConsent(consent, carol.priv, carol.kpass); // classical sig (PQ optional)
  return { type: DISCOVERABLE_CONSENT_WIRE_TYPE, ...signed };
}

test('a sealed discoverable-consent round-trips through its own decryptor (fields intact)', async () => {
  const [carol, truster] = [await signerFromMint(), await signerFromMint()];
  const wire = await signedConsentWire(carol, true, 7);
  const blob = await sealDiscoverableConsentTo(wire, truster.pub);
  const dec = discoverableConsentOpenpgpDecryptor(truster.priv, truster.kpass);

  const out = await dec(blob);
  assert.ok(out, 'the sealed consent decrypts to a DiscoverableConsentWireV0');
  assert.equal(out?.type, DISCOVERABLE_CONSENT_WIRE_TYPE);
  assert.equal(out?.subject_fp, carol.fp);
  assert.equal(out?.discoverable, true);
  assert.equal(out?.epoch, 7);
  assert.equal(out?.scope_tag, CONSENT_SCOPE_GLOBAL);
  assert.ok(out?.sig, 'Carol’s signature survives the envelope (re-verified in applyDiscoverableConsent)');
});

test('DISCRIMINATOR: the consent decryptor returns null for a real sealed NOTE (falls through)', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const note: NoteWireV0 = {
    type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1',
    from_fingerprint: A.fp, sent_at: '2026-10-10T03:20:00.000Z', body: 'hi', participant_kind: 'human',
  };
  const noteBlob = await sealNoteTo(note, B.pub); // SAME openpgp envelope
  const consentDec = discoverableConsentOpenpgpDecryptor(B.priv, B.kpass);
  assert.equal(await consentDec(noteBlob), null, 'a note is NOT eaten as a consent (type gate)');
});

test('DISCRIMINATOR: the note decryptor returns null for a real sealed CONSENT (falls through)', async () => {
  const [carol, B] = [await signerFromMint(), await signerFromMint()];
  const consentBlob = await sealDiscoverableConsentTo(await signedConsentWire(carol), B.pub); // SAME envelope
  const noteDec = noteOpenpgpDecryptor(B.priv, B.kpass);
  assert.equal(await noteDec(consentBlob), null, 'a consent is NOT eaten as a note (type gate)');
});

test('the consent decryptor returns null on garbage / wrong-key (fail-closed, no throw)', async () => {
  const B = await signerFromMint();
  const dec = discoverableConsentOpenpgpDecryptor(B.priv, B.kpass);
  assert.equal(await dec('not-a-pgp-blob'), null);
});

test('sealDiscoverableConsentTo refuses a non-consent wire type (fail-loud)', async () => {
  const B = await signerFromMint();
  const notConsent = { type: 'svrnty-note-v0', subject_fp: 'x' } as unknown as DiscoverableConsentWireV0;
  await assert.rejects(() => sealDiscoverableConsentTo(notConsent, B.pub), /refusing non-consent/);
});
