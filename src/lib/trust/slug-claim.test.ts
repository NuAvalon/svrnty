// src/lib/trust/slug-claim.test.ts
// F6 signed-slug-claim reference verifier + the §5 canonical-id fix. Proves BOTH halves hold:
//   (a) the signature verifies against public_key, AND (b) fingerprint === H(public_key) — for a
// classical (40-hex OpenPGP) claim AND for a 64-hex CANONICAL id once the PQ pubkeys are threaded so
// fingerprintMatchesKey recomputes SHA256(sign‖enc‖kem‖sig). Also pins the property the LIVE Python
// satellite depends on: the §5 PQ pubkeys are EXCLUDED from the signed bytes (byte-exact input unchanged).
// Run: npx tsx --test src/lib/trust/slug-claim.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from '../identity/fingerprint';
import { signSlugClaim, verifySignedSlugClaim } from './slug-claim';
import type { SlugClaim } from '../format/envelope';
import { slugClaimSigningInput } from '../format/envelope';

const NOW = '2026-09-06T00:00:00.000Z';

interface Identity {
  fingerprint: string;
  publicKey: string;
  privateKey: string;
  passphrase: string;
}

// A classical (40-hex OpenPGP) identity — fingerprintMatchesKey binds via the getFingerprint() path.
async function makeIdentity(name: string): Promise<Identity> {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'curve25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase,
    format: 'armored',
  });
  const fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  return { fingerprint, publicKey, privateKey, passphrase };
}

interface CanonicalIdentity extends Identity {
  kemPublicKeyB64: string;
  sigPublicKeyB64: string;
}

// A §5 CANONICAL identity: openpgp (sign+enc) + ML-KEM/ML-DSA pubkeys → a 64-hex SHA256(sign‖enc‖kem‖sig)
// fingerprint (NOT the 40-hex OpenPGP fp). Mirrors relay/mailbox-auth.test.ts makeCanonicalIdentity.
async function makeCanonicalIdentity(name: string): Promise<CanonicalIdentity> {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime — the exact keygen used
    // in src/lib/identity/core.ts (which carries the same pre-existing tsc wart).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey,
  });
  return {
    fingerprint, publicKey, privateKey, passphrase,
    kemPublicKeyB64: uint8ToBase64(pq.kem.publicKey),
    sigPublicKeyB64: uint8ToBase64(pq.signing.publicKey),
  };
}

let alice: Identity;   // classical
let mallory: Identity; // classical attacker

before(async () => {
  alice = await makeIdentity('alice');
  mallory = await makeIdentity('mallory');
});

// ── Classical (40-hex) baseline — the F6 fix, unchanged by §5 ────────────────────────────────────

test('CANONICAL-ONLY GATE (res1): a classical 40-hex slug claim does NOT verify — the OpenPGP fall-through is removed (the canonical happy-path is the "CANONICAL" test below)', async () => {
  // alice is a classical (40-hex OpenPGP) identity. Post-res1 fingerprintMatchesKey is canonical-only:
  // a 40-hex claimed fp with no PQ legs → false. Inverts the pre-res1 "classical binds" assertion
  // (mirrors canonical-fingerprint.test.ts). The verifying happy-path is now canonical (below).
  const claim: SlugClaim = { slug: 'alice', fingerprint: alice.fingerprint, public_key: alice.publicKey, timestamp: NOW };
  const signed = await signSlugClaim(claim, alice.privateKey, alice.passphrase);
  assert.equal(await verifySignedSlugClaim(signed), false);
});

test('classical: a fingerprint that does not hash to the public key is refused (Invariant-1)', async () => {
  const claim: SlugClaim = { slug: 'alice', fingerprint: mallory.fingerprint, public_key: alice.publicKey, timestamp: NOW };
  const signed = await signSlugClaim(claim, alice.privateKey, alice.passphrase);
  assert.equal(await verifySignedSlugClaim(signed), false);
});

test('classical: tampering the slug after signing is refused (the signature binds the slug)', async () => {
  const claim: SlugClaim = { slug: 'alice', fingerprint: alice.fingerprint, public_key: alice.publicKey, timestamp: NOW };
  const signed = await signSlugClaim(claim, alice.privateKey, alice.passphrase);
  assert.equal(await verifySignedSlugClaim({ ...signed, slug: 'bob' }), false);
});

test('classical: an attacker cannot claim a slug for a key they do not hold (sign with wrong key)', async () => {
  const claim: SlugClaim = { slug: 'alice', fingerprint: alice.fingerprint, public_key: alice.publicKey, timestamp: NOW };
  // fp == H(public_key) holds (both Alice's), but Mallory signs → the sig fails against Alice's key.
  const forged = await signSlugClaim(claim, mallory.privateKey, mallory.passphrase);
  assert.equal(await verifySignedSlugClaim(forged), false);
});

// ── §5 CANONICAL-ID slug-claim: thread PQ pubkeys → the 64-hex canonical fp recomputes + matches ──

test('CANONICAL: a 64-hex canonical slug claim verifies WHEN the PQ pubkeys are threaded (the §5 fix)', async () => {
  const cid = await makeCanonicalIdentity('canon');
  assert.match(cid.fingerprint, /^[0-9a-f]{64}$/); // 64-hex canonical, NOT a 40-hex OpenPGP fp
  const claim: SlugClaim = { slug: 'canon', fingerprint: cid.fingerprint, public_key: cid.publicKey, timestamp: NOW };
  const signed = await signSlugClaim(claim, cid.privateKey, cid.passphrase, undefined, cid.kemPublicKeyB64, cid.sigPublicKeyB64);
  assert.equal(await verifySignedSlugClaim(signed), true);
});

test('CANONICAL WITHOUT threaded PQ pubkeys → fail-closed (the pre-fix bug; proves the threading is load-bearing)', async () => {
  const cid = await makeCanonicalIdentity('canon2');
  // Sign classical-only (omit the PQ pubkeys). fingerprintMatchesKey then can't recompute the 64-hex
  // canonical fp → falls to the 40-hex OpenPGP path → 64 !== 40 → refused.
  const claim: SlugClaim = { slug: 'canon2', fingerprint: cid.fingerprint, public_key: cid.publicKey, timestamp: NOW };
  const signed = await signSlugClaim(claim, cid.privateKey, cid.passphrase);
  assert.equal(await verifySignedSlugClaim(signed), false);
});

test('CANONICAL with a WRONG-LENGTH kem → rejected at the boundary (§5 defense-in-depth, fail-loud)', async () => {
  const cid = await makeCanonicalIdentity('canon3');
  const claim: SlugClaim = { slug: 'canon3', fingerprint: cid.fingerprint, public_key: cid.publicKey, timestamp: NOW };
  const signed = await signSlugClaim(claim, cid.privateKey, cid.passphrase, undefined, cid.kemPublicKeyB64, cid.sigPublicKeyB64);
  // Truncate the kem to 40 base64 chars (~30 bytes, not 1568) → verifySignedSlugClaim's length-guard rejects.
  assert.equal(await verifySignedSlugClaim({ ...signed, pq_kem_public_key: signed.pq_kem_public_key!.slice(0, 40) }), false);
});

test('CANONICAL tamper: swapping in another identity\'s kem → the canonical fp recompute differs → refused', async () => {
  const cid = await makeCanonicalIdentity('canon4');
  const other = await makeCanonicalIdentity('other');
  const claim: SlugClaim = { slug: 'canon4', fingerprint: cid.fingerprint, public_key: cid.publicKey, timestamp: NOW };
  const signed = await signSlugClaim(claim, cid.privateKey, cid.passphrase, undefined, cid.kemPublicKeyB64, cid.sigPublicKeyB64);
  // Swap the kem to a DIFFERENT (still FIPS-length) canonical kem → SHA256(sign‖enc‖kem‖sig) recomputes to
  // a different 64-hex ≠ claimed fp → fp-match fails (the PQ pubkeys are self-protected by the fp-match).
  assert.equal(await verifySignedSlugClaim({ ...signed, pq_kem_public_key: other.kemPublicKeyB64 }), false);
});

test('CANONICAL tamper: tampering the slug after signing is refused (the signature binds the slug)', async () => {
  const cid = await makeCanonicalIdentity('canon5');
  const claim: SlugClaim = { slug: 'canon5', fingerprint: cid.fingerprint, public_key: cid.publicKey, timestamp: NOW };
  const signed = await signSlugClaim(claim, cid.privateKey, cid.passphrase, undefined, cid.kemPublicKeyB64, cid.sigPublicKeyB64);
  // fp-match still passes (fingerprint↔keys intact), but the slug changed → the signature no longer matches.
  assert.equal(await verifySignedSlugClaim({ ...signed, slug: 'stolen' }), false);
});

test('SATELLITE-SAFE: the §5 PQ pubkeys are EXCLUDED from slugClaimSigningInput — a canonical claim verifies, and the signed bytes are independent of the attached pq (the LIVE Python satellite verifies the sig without pq)', async () => {
  // Post-res1 the identity is canonical, but the satellite-safe property is unchanged + load-bearing:
  // pq_kem/pq_sig are NOT in the signed byte-vector (slugClaimSigningInput). The LIVE Python satellite
  // verifies the claim signature WITHOUT the pq pubkeys; they're carried only so the client recomputes
  // the 64-hex canonical fp. Sign a canonical claim, then prove directly that slugClaimSigningInput does
  // not depend on the pq pubkeys' presence or value.
  const cid = await makeCanonicalIdentity('sat');
  const claim: SlugClaim = { slug: 'sat', fingerprint: cid.fingerprint, public_key: cid.publicKey, timestamp: NOW };
  const signed = await signSlugClaim(claim, cid.privateKey, cid.passphrase, undefined, cid.kemPublicKeyB64, cid.sigPublicKeyB64);
  assert.equal(await verifySignedSlugClaim(signed), true);
  const base = slugClaimSigningInput(signed);
  assert.equal(
    slugClaimSigningInput({ ...signed, pq_kem_public_key: undefined, pq_sig_public_key: undefined }),
    base, 'pq pubkeys must be EXCLUDED from slugClaimSigningInput (satellite verifies without them)',
  );
  assert.equal(
    slugClaimSigningInput({ ...signed, pq_kem_public_key: 'ZZZZ', pq_sig_public_key: 'ZZZZ' }),
    base, 'slugClaimSigningInput must not depend on the pq pubkey values',
  );
});
