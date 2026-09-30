// Canonical four-key fingerprint + scalar-extract + bind/PSI-auth preimages.
// Run: npx tsx --test src/lib/identity/canonical-fingerprint.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey, readKey } from 'openpgp';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { generatePQKeypairBundle } from '@/lib/crypto/pq';
import {
  extractRawSign,
  rawSign,
  strip0x40,
  bindPreimage,
  psiAuthPreimage,
  signBind,
  signPsiAuth,
  signPsiAuthWrapped,
} from './raw-sign';
import {
  deriveCanonicalFingerprintHex,
  mintCanonicalFingerprint,
  canonicalPubsFromArmoredPublicKey,
  fingerprintMatchesKey,
  canonicalClaimMatches,
  buildSatelliteRegisterFields,
  SIGN_PUB_LEN,
  ENC_PUB_LEN,
  KEM_PUB_LEN,
  SIG_PUB_LEN,
} from './fingerprint';

const passphrase = 'canonical-fp-test-passphrase';

let privateKey: string;
let publicKey: string;
let unlocked: any;
let pq: ReturnType<typeof generatePQKeypairBundle>;

before(async () => {
  const generated = await generateKey({
    type: 'ecc',
    curve: 'ed25519',
    userIDs: [{ name: 'Canon', email: 'canon@example.test' }],
    passphrase,
    format: 'armored',
  });
  privateKey = generated.privateKey;
  publicKey = generated.publicKey;
  const locked = await readPrivateKey({ armoredKey: privateKey });
  unlocked = locked.isDecrypted()
    ? locked
    : await decryptKey({ privateKey: locked, passphrase });
  pq = generatePQKeypairBundle();
});

test('scalar-extract: noble.getPublicKey(seed) equals 0x40-stripped Q', () => {
  const { seed, signPub } = extractRawSign(unlocked);
  assert.equal(seed.length, 32);
  assert.equal(signPub.length, SIGN_PUB_LEN);
  assert.equal(bytesToHex(ed25519.getPublicKey(seed)), bytesToHex(signPub));
  const q = unlocked.keyPacket.publicParams.Q as Uint8Array;
  assert.equal(q[0], 0x40);
  assert.equal(bytesToHex(strip0x40(q)), bytesToHex(signPub));
});

test('scalar-extract: noble.sign verifies against the committed pubkey', () => {
  const { seed, signPub } = extractRawSign(unlocked);
  const msg = new TextEncoder().encode('scalar-extract-round-trip');
  const sig = rawSign(msg, seed);
  assert.equal(sig.length, 64);
  assert.equal(ed25519.verify(sig, msg, signPub), true);
});

test('scalar-extract fail-closed on seed↔signPub mismatch', () => {
  const { seed } = extractRawSign(unlocked);
  const bogus = {
    keyPacket: {
      privateParams: { seed },
      publicParams: { Q: Uint8Array.from([0x40, ...new Uint8Array(32).fill(7)]) },
    },
  };
  assert.throws(() => extractRawSign(bogus), /scalar-extract invariant failed/);
});

test('canonical fp is 64 hex and matches SHA256(sign‖enc‖kem‖sig) byte order', async () => {
  const minted = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked,
    kemPublicKey: pq.kem.publicKey,
    sigPublicKey: pq.signing.publicKey,
  });
  assert.match(minted.fingerprint, /^[0-9a-f]{64}$/);
  const fromPublic = await canonicalPubsFromArmoredPublicKey(
    publicKey,
    Buffer.from(pq.kem.publicKey).toString('base64'),
    Buffer.from(pq.signing.publicKey).toString('base64'),
  );
  assert.equal(fromPublic.fingerprint, minted.fingerprint);
  const bundle = new Uint8Array(SIGN_PUB_LEN + ENC_PUB_LEN + KEM_PUB_LEN + SIG_PUB_LEN);
  bundle.set(minted.signPub, 0);
  bundle.set(minted.encPub, SIGN_PUB_LEN);
  bundle.set(pq.kem.publicKey, SIGN_PUB_LEN + ENC_PUB_LEN);
  bundle.set(pq.signing.publicKey, SIGN_PUB_LEN + ENC_PUB_LEN + KEM_PUB_LEN);
  assert.equal(bytesToHex(sha256(bundle)), minted.fingerprint);
});

test('fp commits to all four keys — omitting any one changes the fingerprint', async () => {
  const minted = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked,
    kemPublicKey: pq.kem.publicKey,
    sigPublicKey: pq.signing.publicKey,
  });
  const zero32 = new Uint8Array(32);
  const zeroKem = new Uint8Array(KEM_PUB_LEN);
  const zeroSig = new Uint8Array(SIG_PUB_LEN);
  assert.notEqual(
    deriveCanonicalFingerprintHex(zero32, minted.encPub, pq.kem.publicKey, pq.signing.publicKey),
    minted.fingerprint,
  );
  assert.notEqual(
    deriveCanonicalFingerprintHex(minted.signPub, zero32, pq.kem.publicKey, pq.signing.publicKey),
    minted.fingerprint,
  );
  assert.notEqual(
    deriveCanonicalFingerprintHex(minted.signPub, minted.encPub, zeroKem, pq.signing.publicKey),
    minted.fingerprint,
  );
  assert.notEqual(
    deriveCanonicalFingerprintHex(minted.signPub, minted.encPub, pq.kem.publicKey, zeroSig),
    minted.fingerprint,
  );
});

test('reject-wrong-length: any key not at FIPS length throws (no truncated hash)', () => {
  const sign = new Uint8Array(32);
  const enc = new Uint8Array(32);
  const kem = new Uint8Array(KEM_PUB_LEN);
  const sig = new Uint8Array(SIG_PUB_LEN);
  assert.throws(() => deriveCanonicalFingerprintHex(sign.slice(0, 31), enc, kem, sig));
  assert.throws(() => deriveCanonicalFingerprintHex(sign, enc.slice(0, 31), kem, sig));
  assert.throws(() => deriveCanonicalFingerprintHex(sign, enc, kem.slice(0, 800), sig));
  assert.throws(() => deriveCanonicalFingerprintHex(sign, enc, kem, sig.slice(0, 2000)));
});

test('fingerprintMatchesKey: four-key identity id matches; legacy OpenPGP 40-hex is REJECTED (canonical-only)', async () => {
  const minted = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked,
    kemPublicKey: pq.kem.publicKey,
    sigPublicKey: pq.signing.publicKey,
  });
  const kemB64 = Buffer.from(pq.kem.publicKey).toString('base64');
  const sigB64 = Buffer.from(pq.signing.publicKey).toString('base64');
  assert.equal(
    await fingerprintMatchesKey(minted.fingerprint, publicKey, {
      kem_public_key: kemB64,
      sig_public_key: sigB64,
    }),
    true,
  );
  assert.equal(
    await fingerprintMatchesKey(minted.fingerprint.slice(0, 16), publicKey, {
      kem_public_key: kemB64,
      sig_public_key: sigB64,
    }),
    true,
  );
  const openpgpFp = (await readKey({ armoredKey: publicKey })).getFingerprint();
  assert.equal(openpgpFp.length, 40);
  // Res#1 gate (BLOCKING): the legacy SHA-1 40-hex basis no longer binds, and a canonical
  // fp presented WITHOUT the pq overlay is canonical-only-false (fall-through removed).
  assert.equal(await fingerprintMatchesKey(openpgpFp, publicKey), false); // legacy SHA-1 basis REJECTED
  assert.equal(await fingerprintMatchesKey(minted.fingerprint, publicKey), false); // canonical fp w/o pq overlay → false
  assert.equal(await fingerprintMatchesKey('deadbeef'.repeat(5), publicKey), false);
});

test('canonicalClaimMatches requires a prefix of at least 16 hex chars', () => {
  const derived = 'a'.repeat(64);
  assert.equal(canonicalClaimMatches(derived, derived), true);
  assert.equal(canonicalClaimMatches(derived.slice(0, 16), derived), true);
  assert.equal(canonicalClaimMatches(derived.slice(0, 15), derived), false);
  assert.equal(canonicalClaimMatches('b'.repeat(16), derived), false);
});

test('bind + PSI-auth preimages are the exact UTF-8 strings; signatures verify', () => {
  const { seed, signPub } = extractRawSign(unlocked);
  const signHex = bytesToHex(signPub);
  const bindMsg = bindPreimage(signHex, 'nonce-1', 7);
  assert.equal(new TextDecoder().decode(bindMsg), `svrnty-bind:${signHex}:nonce-1:7`);
  const bindSig = signBind(seed, signHex, 'nonce-1', 7);
  assert.equal(ed25519.verify(bindSig, bindMsg, signPub), true);

  const fp = 'ab'.repeat(32);
  const psiMsg = psiAuthPreimage(fp, 1_700_000_000);
  assert.equal(new TextDecoder().decode(psiMsg), `svrnty-psi-auth:${fp}:1700000000`);
  const psiSig = signPsiAuth(seed, fp, 1_700_000_000);
  assert.equal(ed25519.verify(psiSig, psiMsg, signPub), true);

  const wrapped = new TextEncoder().encode(`${fp}:1700000000`);
  const fromWrapped = signPsiAuthWrapped(seed, wrapped);
  assert.equal(ed25519.verify(fromWrapped, psiMsg, signPub), true);
  const alreadyFull = psiAuthPreimage(fp, 1_700_000_000);
  assert.equal(ed25519.verify(signPsiAuthWrapped(seed, alreadyFull), alreadyFull, signPub), true);
});

test('buildSatelliteRegisterFields emits the satellite /register contract (base64 raw keys, correct names, SHA256(sign‖enc‖kem‖sig)==fingerprint)', async () => {
  const kemB64 = Buffer.from(pq.kem.publicKey).toString('base64');
  const sigB64 = Buffer.from(pq.signing.publicKey).toString('base64');
  const canonical = await canonicalPubsFromArmoredPublicKey(publicKey, kemB64, sigB64);

  const fields = await buildSatelliteRegisterFields({
    identity: { fingerprint: canonical.fingerprint, public_key: publicKey, name: 'Canon' },
    post_quantum: { kem_public_key: kemB64, sig_public_key: sigB64 },
  });
  assert.ok(fields, 'fields must be non-null for a full PQ identity');

  // public_key is base64 raw Ed25519, NOT OpenPGP-armored (the prior 400 "Invalid public_key encoding").
  assert.equal(fields!.public_key.includes('BEGIN PGP'), false);

  // Every key field base64-decodes to its exact FIPS length (I-6 injectivity, satellite-enforced).
  const pkB = Buffer.from(fields!.public_key, 'base64');
  const encB = Buffer.from(fields!.encryption_pk, 'base64');
  const kemBytes = Buffer.from(fields!.pq_kem_pk, 'base64');
  const sigBytes = Buffer.from(fields!.pq_sig_pk, 'base64');
  assert.equal(pkB.length, SIGN_PUB_LEN); // 32
  assert.equal(encB.length, ENC_PUB_LEN); // 32
  assert.equal(kemBytes.length, KEM_PUB_LEN); // 1568
  assert.equal(sigBytes.length, SIG_PUB_LEN); // 2592

  // THE satellite re-derivation (register_identity): SHA256(sign‖enc‖kem‖sig) must equal the
  // fingerprint. Green here ⇒ the satellite verifies the wire payload ⇒ register 200 by construction.
  const bundle = new Uint8Array(SIGN_PUB_LEN + ENC_PUB_LEN + KEM_PUB_LEN + SIG_PUB_LEN);
  bundle.set(pkB, 0);
  bundle.set(encB, SIGN_PUB_LEN);
  bundle.set(kemBytes, SIGN_PUB_LEN + ENC_PUB_LEN);
  bundle.set(sigBytes, SIGN_PUB_LEN + ENC_PUB_LEN + KEM_PUB_LEN);
  assert.equal(bytesToHex(sha256(bundle)), fields!.fingerprint);
  assert.equal(fields!.fingerprint, canonical.fingerprint);

  // crypto_version satisfies the satellite regex ^(classical|hybrid-v1)$.
  assert.equal(fields!.crypto_version, 'hybrid-v1');

  // The wrong-shape fields the client used to send are gone (armored public_key / hex sign_pub/…).
  assert.equal((fields as Record<string, unknown>).sign_pub, undefined);
  assert.equal((fields as Record<string, unknown>).enc_pub, undefined);
});
