// S14 (Flint, lane:svrnty): the 'no-pq-kem' send branch is unreachable for a VERIFIED card, because the canonical
// fingerprint hashes sign‖enc‖kem‖sig (Res#1, canonical-only): a card with the kem leg stripped cannot pass the
// fingerprint↔key binding, so it is refused BEFORE any send. Pins that, with a positive control.
// Run: npx tsx --test src/lib/identity/card-kem-leg-binding.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { fingerprintMatchesKey } from './fingerprint';
import { verifySignedIdentityCard } from './identity-card-sign';

async function mintCard() {
  const a = await mintHeadlessAgent({ throwaway: true });
  return JSON.parse(JSON.stringify(a.introduction.card)) as { identity: Record<string, string>; signature: string };
}

test('control: a freshly minted card verifies and binds (kem+sig legs present)', async () => {
  const card = await mintCard();
  const id = card.identity;
  assert.equal(
    await fingerprintMatchesKey(id.fingerprint, id.public_key, { kem_public_key: id.pq_kem_public_key, sig_public_key: id.pq_sig_public_key }),
    true,
  );
  assert.equal(await verifySignedIdentityCard(card as never), true);
});

test('a card with the kem leg STRIPPED is refused at the fingerprint binding', async () => {
  const card = await mintCard();
  const id = card.identity;
  assert.equal(await fingerprintMatchesKey(id.fingerprint, id.public_key, { sig_public_key: id.pq_sig_public_key }), false);
  delete id.pq_kem_public_key;
  assert.equal(await verifySignedIdentityCard(card as never), false, 'the card no longer verifies: no send is ever built for it');
});

test('a card with a SHORT/placeholder kem leg is refused too (FIPS length required)', async () => {
  const card = await mintCard();
  card.identity.pq_kem_public_key = 'AAAA';
  assert.equal(await verifySignedIdentityCard(card as never), false);
  assert.equal(
    await fingerprintMatchesKey(card.identity.fingerprint, card.identity.public_key, { kem_public_key: 'AAAA', sig_public_key: card.identity.pq_sig_public_key }),
    false,
  );
});

test('a card with the sig leg stripped is refused as well (both PQ legs are bound)', async () => {
  const card = await mintCard();
  const id = card.identity;
  assert.equal(await fingerprintMatchesKey(id.fingerprint, id.public_key, { kem_public_key: id.pq_kem_public_key }), false);
});
