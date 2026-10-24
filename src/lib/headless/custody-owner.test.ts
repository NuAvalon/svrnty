// src/lib/headless/custody-owner.test.ts
// Proves the custody→HeadlessOwner adapter against a REAL mint (no mocks): the field-map is correct
// (esp. ① kemSecretKey = private.mlkem1024_sec) AND the resulting owner can actually DERIVE the hybrid
// open-material (so a headless agent opens inbound PQ-hybrid mail). Run alone: `tsx --test <this file>`.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent, serializeMintArtifact } from '@/lib/identity/headless-mint';
import { deriveOwnerHybridSecrets } from '@/lib/crypto/living-book-receive';
import { custodyToHeadlessOwner } from './custody-owner';

test('maps every OwnerIdentity field from a real mint artifact (incl. ① kemSecretKey)', async () => {
  const ser = serializeMintArtifact(await mintHeadlessAgent()); // throwaway PQ mint → real keys
  const owner = custodyToHeadlessOwner(ser);
  assert.equal(owner.fingerprint, ser.public.durable_id);
  assert.equal(owner.publicKeyArmored, ser.public.card.identity.public_key);
  assert.equal(owner.privateKeyArmored, ser.private.classical_private_key);
  assert.equal(owner.passphrase, ser.private.classical_kpass);
  assert.equal(owner.kemPublicKey, ser.public.card.identity.pq_kem_public_key);
  assert.equal(owner.sigPublicKey, ser.public.card.identity.pq_sig_public_key);
  assert.equal(owner.kemSecretKey, ser.private.mlkem1024_sec); // ★ the ① contract (Apollo #168442)
  assert.ok(owner.kemSecretKey && owner.kemSecretKey.length > 0, 'kem secret is non-empty B64');
});

test('the built owner CAN derive hybrid open-material (opens hybrid — not classical-only)', async () => {
  const owner = custodyToHeadlessOwner(serializeMintArtifact(await mintHeadlessAgent()));
  const hybrid = await deriveOwnerHybridSecrets(
    owner.privateKeyArmored, owner.passphrase, owner.kemPublicKey, owner.kemSecretKey,
  );
  assert.ok(hybrid, 'deriveOwnerHybridSecrets returned defined — owner can open hybrid');
  assert.equal(hybrid.secrets.mlkem1024Sec.length, 3168, 'ML-KEM-1024 secret decodes to 3168 bytes');
  assert.equal(hybrid.secrets.x25519Sec.length, 32, 'x25519 secret is 32 bytes');
  assert.match(hybrid.myFp, /^[0-9a-f]{64}$/, 'myFp (seal-target senders use) is a 64-hex mailbox fp');
});

test('classical-only artifact → no kem secret → classical fallback (deriveOwnerHybridSecrets undefined)', async () => {
  const ser = serializeMintArtifact(await mintHeadlessAgent());
  (ser.public.card.identity as { pq_kem_public_key: string }).pq_kem_public_key = ''; // simulate classical id
  (ser.private as { mlkem1024_sec: string }).mlkem1024_sec = '';
  const owner = custodyToHeadlessOwner(ser);
  assert.equal(owner.kemSecretKey, undefined);
  const hybrid = await deriveOwnerHybridSecrets(
    owner.privateKeyArmored, owner.passphrase, owner.kemPublicKey, owner.kemSecretKey,
  );
  assert.equal(hybrid, undefined, 'classical identity → undefined → classical-only openers (no silent loss)');
});

test('fail-closed: missing classical key material throws (never a half-built signing owner)', () => {
  const bad = { public: { durable_id: 'x', card: { identity: { public_key: '' } } }, private: {} };
  assert.throws(() => custodyToHeadlessOwner(bad as never), /missing classical key material/);
});
