// src/lib/identity/identity-card-sign.test.ts
// (A) signed identity card — sign/verify round-trip + the pq_kem-swap tamper detection (spec §8).
// Real keys, generated once in before(). Run: npx tsx --test src/lib/identity/identity-card-sign.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import {
  signIdentityCard, verifySignedIdentityCard, type SignedIdentityCard,
  suiteFromKemLength, classifyImportedCard,
} from './identity-card-sign';
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

// ── §6 suite-length derivation (the ek length IS the suite discriminant) ─────────────
/** A base64 ML-KEM public key of exactly `n` decoded bytes (real length, placeholder bytes). */
const kemOfBytes = (n: number) => Buffer.from('k'.repeat(n)).toString('base64');

test('§6 suiteFromKemLength: 1568B → ML-KEM-1024 (Cat-5)', () => {
  assert.equal(suiteFromKemLength(kemOfBytes(1568)), 'ML-KEM-1024');
});
test('§6 suiteFromKemLength: 1184B → ML-KEM-768 (Cat-3)', () => {
  assert.equal(suiteFromKemLength(kemOfBytes(1184)), 'ML-KEM-768');
});
test('§6 downgrade-floor: 800B (ML-KEM-512) → undefined — below the svrnty floor, not accepted', () => {
  assert.equal(suiteFromKemLength(kemOfBytes(800)), undefined);
});
test('§6 suiteFromKemLength: empty / non-base64 → undefined (never a false accept)', () => {
  assert.equal(suiteFromKemLength(''), undefined);
  assert.equal(suiteFromKemLength('not valid base64 !!'), undefined);
});

// ── §4 classifyImportedCard — the fail-closed 4-branch import table ──────────────────
test('classify branch 1: fp↔key mismatch → reject, no classical import, no pq', async () => {
  const signed = await signIdentityCard(aliceCard({ fingerprint: malloryFp }), privateKey, passphrase);
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, 1);
  assert.equal(d.importClassical, false);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'reject');
});
test('classify branch 1: malformed card (no identity) → reject', async () => {
  const d = await classifyImportedCard({ version: '1.0', type: 'identity-exchange' });
  assert.equal(d.branch, 1);
  assert.equal(d.importClassical, false);
  assert.equal(d.pq, null);
});
test('classify branch 2: fp OK, no signature → classical-only, quiet, pq dropped', async () => {
  const d = await classifyImportedCard(aliceCard()); // aliceCard() carries no `signature`
  assert.equal(d.branch, 2);
  assert.equal(d.importClassical, true);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'quiet');
});
test('classify branch 3: signature present but INVALID (tampered) → classical-only, LOUD, pq dropped', async () => {
  const signed = await signIdentityCard(aliceCard({ pq_kem_public_key: kemOfBytes(1568) }), privateKey, passphrase);
  const tampered = { ...signed, identity: { ...signed.identity, display_name: 'Eve' } };
  const d = await classifyImportedCard(tampered);
  assert.equal(d.branch, 3);
  assert.equal(d.importClassical, true);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'loud');
});
test('classify branch 4a: valid sig, empty pq_kem → quiet, no pq (legit v1/no-PQ signer)', async () => {
  const signed = await signIdentityCard(
    aliceCard({ pq_kem_public_key: '', pq_sig_public_key: '' }), privateKey, passphrase,
  );
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, '4a');
  assert.equal(d.importClassical, true);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'quiet');
});
test('classify branch 4b: valid sig, supported suite length → STORE authenticated pq (both keys)', async () => {
  const kem = kemOfBytes(1568), sig = kemOfBytes(1184);
  const signed = await signIdentityCard(
    aliceCard({ pq_kem_public_key: kem, pq_sig_public_key: sig }), privateKey, passphrase,
  );
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, '4b');
  assert.equal(d.suite, 'ML-KEM-1024');
  assert.equal(d.importClassical, true);
  assert.equal(d.alarm, 'quiet');
  assert.deepEqual(d.pq, { pq_kem_public_key: kem, pq_sig_public_key: sig });
});
test('classify branch 4c: valid sig, UNSUPPORTED suite length → soft-info, no pq (sender bug, NOT tamper)', async () => {
  const signed = await signIdentityCard(aliceCard({ pq_kem_public_key: kemOfBytes(999) }), privateKey, passphrase);
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, '4c');
  assert.equal(d.alarm, 'soft-info'); // crucial: a valid signature means this is NOT tampering — never cry wolf
  assert.notEqual(d.alarm, 'loud');
  assert.equal(d.pq, null);
  assert.equal(d.importClassical, true);
});
