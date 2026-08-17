// Hybrid-envelope encryption — roundtrip + BOTH-required + tamper-evidence.
// Run: npx tsx --test src/lib/crypto/envelope-encrypt.test.ts
// Proves the format §3/§5 invariants: exactly-one payload ciphertext, no single-secret decrypt path.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair, base64ToUint8, uint8ToBase64 } from './pq';
import {
  hybridEncryptToRecipient,
  hybridDecrypt,
  HYBRID_SUITE_ID,
  type RecipientPublicKeys,
  type RecipientSecretKeys,
} from './envelope-encrypt';

function newRecipient(): { pub: RecipientPublicKeys; sec: RecipientSecretKeys } {
  const edSecret = crypto.getRandomValues(new Uint8Array(32)); // Ed25519 seed
  const edPublic = ed25519.getPublicKey(edSecret);
  const kem = generateKEMKeypair();
  return {
    pub: { classicalEd25519PublicKey: edPublic, kemPublicKey: kem.publicKey },
    sec: { classicalEd25519SecretKey: edSecret, kemSecretKey: kem.secretKey },
  };
}

const enc = new TextEncoder();
const dec = new TextDecoder();

test('roundtrip: hybrid encrypt → decrypt recovers the payload', async () => {
  const r = newRecipient();
  const env = await hybridEncryptToRecipient(enc.encode('the castle walls hold'), r.pub);
  assert.equal(env.suite_id, HYBRID_SUITE_ID);
  assert.ok(env.epk_classical.length > 0 && env.kem_ct_pq.length > 0 && env.aead_ct.length > 0);
  const out = await hybridDecrypt(env, r.sec);
  assert.equal(dec.decode(out), 'the castle walls hold');
});

test('both-required: correct classical + WRONG pq secret → decrypt FAILS (no classical-only path)', async () => {
  const r = newRecipient();
  const other = newRecipient();
  const env = await hybridEncryptToRecipient(enc.encode('x'), r.pub);
  await assert.rejects(
    hybridDecrypt(env, { classicalEd25519SecretKey: r.sec.classicalEd25519SecretKey, kemSecretKey: other.sec.kemSecretKey }),
  );
});

test('both-required: WRONG classical + correct pq secret → decrypt FAILS (no pq-only path)', async () => {
  const r = newRecipient();
  const other = newRecipient();
  const env = await hybridEncryptToRecipient(enc.encode('x'), r.pub);
  await assert.rejects(
    hybridDecrypt(env, { classicalEd25519SecretKey: other.sec.classicalEd25519SecretKey, kemSecretKey: r.sec.kemSecretKey }),
  );
});

test('tamper: flipping a byte of aead_ct → decrypt FAILS (GCM integrity)', async () => {
  const r = newRecipient();
  const env = await hybridEncryptToRecipient(enc.encode('tamper me'), r.pub);
  const ct = base64ToUint8(env.aead_ct);
  ct[0] ^= 0xff;
  await assert.rejects(hybridDecrypt({ ...env, aead_ct: uint8ToBase64(ct) }, r.sec));
});

test('privacy: envelope carries no plaintext copy — only aead_ct decrypts, and only with both keys', async () => {
  const r = newRecipient();
  const secret = 'no classical-only copy exists';
  const env = await hybridEncryptToRecipient(enc.encode(secret), r.pub);
  // The envelope's non-AEAD fields are KEM contributions, not payload — none should contain the plaintext.
  const blob = env.suite_id + env.epk_classical + env.kem_ct_pq + env.aead_iv;
  assert.ok(!blob.includes(uint8ToBase64(enc.encode(secret))));
  assert.equal(dec.decode(await hybridDecrypt(env, r.sec)), secret);
});
