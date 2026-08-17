// src/lib/identity/identity-card-sign.test.ts
// (A) signed identity card — sign/verify round-trip + the pq_kem-swap tamper detection (spec §8).
// Real keys, generated once in before(). Run: npx tsx --test src/lib/identity/identity-card-sign.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { signIdentityCard, verifySignedIdentityCard, type SignedIdentityCard } from './identity-card-sign';
import type { IdentityCard } from '../format/envelope';

const passphrase = 'test-passphrase-0';
const otherPass = 'test-passphrase-1';

let privateKey: string, publicKey: string, fingerprint: string;
let malloryPriv: string, malloryPub: string, malloryFp: string;

before(async () => {
  ({ privateKey, publicKey } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Alice', email: 'alice@example.test' }], passphrase, format: 'armored',
  }));
  fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  ({ privateKey: malloryPriv, publicKey: malloryPub } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Mallory', email: 'm@example.test' }], passphrase: otherPass, format: 'armored',
  }));
  malloryFp = (await readKey({ armoredKey: malloryPub })).getFingerprint();
});

const b64 = (s: string) => Buffer.from(s).toString('base64');

/** Alice's identity card with a real fp↔key binding + placeholder pq keys (the signature covers them). */
function aliceCard(over: Partial<IdentityCard['identity']> = {}): IdentityCard {
  return {
    version: '1.0',
    type: 'identity-exchange',
    created_at: '2026-08-17T00:00:00.000Z',
    identity: {
      fingerprint,
      display_name: 'Alice',
      public_key: publicKey,
      email: 'alice@example.test',
      pq_sig_public_key: b64('alice-ml-dsa-pubkey'),
      pq_kem_public_key: b64('alice-ml-kem-pubkey'),
      ...over,
    },
  };
}

test('round-trip: a card signed by its own key verifies', async () => {
  const signed = await signIdentityCard(aliceCard(), privateKey, passphrase);
  assert.equal(await verifySignedIdentityCard(signed), true);
});

test('§8.1 THE threat — swapping pq_kem_public_key breaks verification', async () => {
  const signed = await signIdentityCard(aliceCard(), privateKey, passphrase);
  const tampered: SignedIdentityCard = {
    ...signed,
    identity: { ...signed.identity, pq_kem_public_key: b64('attacker-ml-kem-pubkey') },
  };
  assert.equal(await verifySignedIdentityCard(tampered), false);
});

test('swapping pq_sig_public_key breaks verification', async () => {
  const signed = await signIdentityCard(aliceCard(), privateKey, passphrase);
  const tampered: SignedIdentityCard = {
    ...signed,
    identity: { ...signed.identity, pq_sig_public_key: b64('attacker-ml-dsa-pubkey') },
  };
  assert.equal(await verifySignedIdentityCard(tampered), false);
});

test('tampering a scalar (display_name) breaks verification', async () => {
  const signed = await signIdentityCard(aliceCard(), privateKey, passphrase);
  assert.equal(
    await verifySignedIdentityCard({ ...signed, identity: { ...signed.identity, display_name: 'Eve' } }),
    false,
  );
});

test('no signature field → false (branch-2 guard; the caller drops pq quietly)', async () => {
  const unsigned = aliceCard() as SignedIdentityCard; // no signature attached
  assert.equal(await verifySignedIdentityCard(unsigned), false);
});

test('fingerprint↔key mismatch → false (Invariant-1) even with a valid signature', async () => {
  const signed = await signIdentityCard(aliceCard({ fingerprint: malloryFp }), privateKey, passphrase);
  assert.equal(await verifySignedIdentityCard(signed), false);
});

test('attacker re-signs a swapped card with THEIR key but keeps the victim fingerprint → false', async () => {
  // Mallory swaps pq_kem, keeps Alice's fingerprint + public_key, signs with her OWN key.
  // fp↔key passes (Alice's pair), but the signature is against Alice's public_key while Mallory
  // signed → verifyWithEnvelope fails. The attacker cannot forge Alice's signature.
  const forged = await signIdentityCard(
    aliceCard({ pq_kem_public_key: b64('mallory-kem') }),
    malloryPriv, otherPass,
  );
  assert.equal(await verifySignedIdentityCard(forged), false);
});

test('structural: signature attaches TOP-LEVEL, not nested inside identity (§8.5)', async () => {
  const signed = await signIdentityCard(aliceCard(), privateKey, passphrase);
  assert.equal(typeof signed.signature, 'string');
  assert.equal((signed.identity as Record<string, unknown>).signature, undefined);
});
