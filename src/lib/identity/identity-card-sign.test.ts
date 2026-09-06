// src/lib/identity/identity-card-sign.test.ts
// (A) signed identity card — sign/verify round-trip + the pq_kem-swap tamper detection (spec §8).
// Real keys, generated once in before(). Run: npx tsx --test src/lib/identity/identity-card-sign.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey, readPrivateKey, decryptKey } from 'openpgp';
import {
  signIdentityCard, verifySignedIdentityCard, type SignedIdentityCard,
  suiteFromKemLength, classifyImportedCard,
} from './identity-card-sign';
import type { IdentityCard } from '../format/envelope';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from './fingerprint';

// A §5 CANONICAL identity + card: openpgp (sign+enc) + REAL ML-KEM-1024 (1568B) / ML-DSA-87 (2592B)
// pubkeys → a 64-hex SHA256(sign‖enc‖kem‖sig) fp (NOT the 40-hex OpenPGP fp). Post-res1 the card-verify
// Invariant-1 (fingerprintMatchesKey) is canonical-only, so a card must carry its real FIPS-length pq
// that hashes to the claimed fp. Mirrors genesis + relay/mailbox-auth.test.ts makeCanonicalIdentity.
interface CanonId { fingerprint: string; publicKey: string; privateKey: string; passphrase: string; kemB64: string; sigB64: string; }
async function makeCanonicalId(name: string): Promise<CanonId> {
  const pass = 'pw-' + name;
  const { privateKey: priv, publicKey: pub } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same keygen as core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }], passphrase: pass, format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: priv });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey,
  });
  return { fingerprint, publicKey: pub, privateKey: priv, passphrase: pass, kemB64: uint8ToBase64(pq.kem.publicKey), sigB64: uint8ToBase64(pq.signing.publicKey) };
}
function canonCard(id: CanonId, over: Partial<IdentityCard['identity']> = {}): IdentityCard {
  return {
    version: '1.0', type: 'identity-exchange', created_at: '2026-08-17T00:00:00.000Z',
    identity: {
      fingerprint: id.fingerprint, display_name: 'Alice', public_key: id.publicKey, email: 'alice@example.test',
      pq_sig_public_key: id.sigB64, pq_kem_public_key: id.kemB64, ...over,
    },
  };
}

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

test('round-trip (CANONICAL): a card signed by its own key verifies', async () => {
  const id = await makeCanonicalId('rt');
  const signed = await signIdentityCard(canonCard(id), id.privateKey, id.passphrase);
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
test('classify branch 2 (CANONICAL): fp OK, no signature → classical-only, quiet, pq dropped', async () => {
  const id = await makeCanonicalId('br2');
  const d = await classifyImportedCard(canonCard(id)); // canonCard carries no `signature`
  assert.equal(d.branch, 2);
  assert.equal(d.importClassical, true);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'quiet');
});
test('classify branch 3 (CANONICAL): signature present but INVALID (tampered) → classical-only, LOUD, pq dropped', async () => {
  const id = await makeCanonicalId('br3');
  const signed = await signIdentityCard(canonCard(id), id.privateKey, id.passphrase);
  // fp↔key still passes (canonical fp intact); tampering display_name breaks only the signature → branch 3.
  const tampered = { ...signed, identity: { ...signed.identity, display_name: 'Eve' } };
  const d = await classifyImportedCard(tampered);
  assert.equal(d.branch, 3);
  assert.equal(d.importClassical, true);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'loud');
});
test('CANONICAL-ONLY GATE (res1): a card with EMPTY pq → branch 1 (reject) — no v1/no-PQ signers in greenfield (was branch 4a pre-res1)', async () => {
  // Pre-res1, an empty-pq card from a "legit v1/no-PQ signer" imported classical-quiet (branch 4a) via the
  // 40-hex OpenPGP path. Post-res1 classifyImportedCard's fp-gate (fingerprintMatchesKey) is canonical-only:
  // empty pq → the canonical fp cannot be recomputed → fp↔key FALSE → branch 1 (reject). Greenfield has no
  // v1/no-PQ signers (Archie #130477 canonical-only), so 4a collapses to branch 1. [Flint: the 4a source
  // branch is now dead code — prune at your gate-semantics discretion.]
  const id = await makeCanonicalId('br4a');
  const signed = await signIdentityCard(canonCard(id, { pq_kem_public_key: '', pq_sig_public_key: '' }), id.privateKey, id.passphrase);
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, 1);
  assert.equal(d.importClassical, false);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'reject');
});
test('classify branch 4b (CANONICAL): valid sig, supported suite → STORE authenticated pq (both keys)', async () => {
  const id = await makeCanonicalId('br4b'); // real ML-KEM-1024 (1568B) + ML-DSA-87 (2592B) pq
  const signed = await signIdentityCard(canonCard(id), id.privateKey, id.passphrase);
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, '4b');
  assert.equal(d.suite, 'ML-KEM-1024');
  assert.equal(d.importClassical, true);
  assert.equal(d.alarm, 'quiet');
  assert.deepEqual(d.pq, { pq_kem_public_key: id.kemB64, pq_sig_public_key: id.sigB64 });
});
test('CANONICAL-ONLY GATE (res1): a card with a WRONG-LENGTH suite → branch 1 (reject) — the fp-gate needs FIPS-length canonical pq (was branch 4c pre-res1)', async () => {
  // Pre-res1, an unsupported-suite (wrong-length kem) card imported classical soft-info (branch 4c) via the
  // 40-hex path. Post-res1 the fp-gate is canonical-only: a non-FIPS-length kem → the canonical fp cannot be
  // recomputed → fp↔key FALSE → branch 1 (reject). Greenfield canonical-only (Archie #130477); 4c collapses
  // to branch 1. [Flint: the 4c source branch is now dead code — prune at your gate-semantics discretion.]
  const id = await makeCanonicalId('br4c');
  const signed = await signIdentityCard(canonCard(id, { pq_kem_public_key: kemOfBytes(999) }), id.privateKey, id.passphrase);
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, 1);
  assert.equal(d.importClassical, false);
  assert.equal(d.pq, null);
  assert.equal(d.alarm, 'reject');
});
