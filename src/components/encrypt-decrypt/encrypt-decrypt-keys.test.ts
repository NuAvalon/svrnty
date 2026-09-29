import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as openpgp from 'openpgp';
import { generateKEMKeypair, generateSigningKeypair, uint8ToBase64 } from '@/lib/crypto/pq';
import { extractRawEnc, extractRawSign } from '@/lib/identity/raw-sign';
import { deriveCanonicalFingerprintHex } from '@/lib/identity/fingerprint';
import {
  decryptFromContact,
  encryptToContact,
  type ContactKeys,
} from '@/lib/crypto/contact-message';
import { assembleOwnerMessageKeys, parseStoredPqBundle } from './encrypt-decrypt-keys';
import { decryptMessageFromContact, encryptMessageToContact } from './encrypt-decrypt-actions';
import { ENCDEC_COPY } from './encrypt-decrypt-copy';

async function mintOwner() {
  const { privateKey, publicKey } = (await openpgp.generateKey({
    type: 'ecc',
    curve: 'ed25519',
    userIDs: [{ name: 'id' }],
    format: 'object',
  } as never)) as { privateKey: unknown; publicKey: { armor: () => string } };
  const kem = generateKEMKeypair();
  const sig = generateSigningKeypair();
  const { seed: signSeed, signPub } = extractRawSign(privateKey);
  const { encSec, encPub } = await extractRawEnc(privateKey);
  const fingerprint = deriveCanonicalFingerprintHex(signPub, encPub, kem.publicKey, sig.publicKey);
  const pq = {
    signing: { publicKey: uint8ToBase64(sig.publicKey), secretKey: uint8ToBase64(sig.secretKey) },
    kem: { publicKey: uint8ToBase64(kem.publicKey), secretKey: uint8ToBase64(kem.secretKey) },
  };
  const parsed = parseStoredPqBundle(pq);
  assert.ok(parsed);
  const assembled = await assembleOwnerMessageKeys(privateKey, parsed);
  const card: ContactKeys = {
    public_key: publicKey.armor(),
    pq_kem_public_key: uint8ToBase64(kem.publicKey),
    pq_sig_public_key: uint8ToBase64(sig.publicKey),
    fingerprint,
  };
  return { assembled, card, fingerprint, signSeed, encSec };
}

describe('owner key assembly — fingerprint wiring gate', () => {
  it('myFingerprint is deriveCanonicalFingerprintHex over live keys, not a placeholder', async () => {
    const alice = await mintOwner();
    assert.equal(alice.assembled.fingerprint.length, 64);
    assert.equal(alice.assembled.me.myFingerprint, alice.fingerprint);
    assert.equal(alice.assembled.sender.senderFingerprint, alice.fingerprint);
    assert.notEqual(alice.assembled.me.myFingerprint, '0'.repeat(64));
  });

  it('round-trips through fleet encryptToContact / decryptFromContact with senderVerified', async () => {
    const alice = await mintOwner();
    const bob = await mintOwner();
    const msg = 'meet at the barzakh';
    const armored = await encryptToContact(msg, bob.card, alice.assembled.sender);
    const opened = await decryptFromContact(armored, bob.assembled.me, alice.card);
    assert.ok(opened);
    assert.equal(opened.message, msg);
    assert.equal(opened.senderVerified, true);
    assert.equal(opened.senderFingerprint, alice.fingerprint);
  });

  it('UI wrapper maps a poisoned card to the fixed anti-poison string (never the crypto throw)', async () => {
    const alice = await mintOwner();
    const bob = await mintOwner();
    const poisoned: ContactKeys = { ...bob.card, fingerprint: 'f'.repeat(64) };
    const out = await encryptMessageToContact('hi', poisoned, alice.assembled.sender);
    assert.equal(out.ok, false);
    if (!out.ok) assert.equal(out.error, ENCDEC_COPY.encryptPoisoned);
  });

  it('UI wrapper maps a decrypt miss to the fixed non-leaky failure string', async () => {
    const bob = await mintOwner();
    const out = await decryptMessageFromContact('not a block', bob.assembled.me);
    assert.equal(out.ok, false);
    if (!out.ok) assert.equal(out.error, ENCDEC_COPY.decryptFailed);
  });
});
