// Canonical-enroll /verify field-builder contract — the encoding-trap guard.
// Run: npx tsx --test src/lib/identity/canonical-enroll.test.ts
//
// This is the client half of the genesis contract: the body we POST to /verify MUST let the
// registration authority re-derive the SAME canonical DID it enforces (option-B, Flint sign-off):
//   fingerprint == SHA256( rawEd25519 ‖ rawX25519 ‖ rawMLKEM1024 ‖ rawMLDSA87 )   [over DECODED bytes]
// The traps this locks out: armored public_key, hex PQ legs, wrong lengths, truncated fp, DID drift
// between the mint path and the enroll path.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from './fingerprint';
import { buildCanonicalVerifyFields } from './canonical-enroll';

// Mint a real 4-key identity WITHOUT IndexedDB storage — the exact object shape generateIdentity()
// produces (browser-identity.ts), minus persistence.
async function mintIdentityObject() {
  const passphrase = 'test-internal-passphrase';
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    curve: 'ed25519',
    userIDs: [{ name: 'Enroll Test', email: 'enroll-test@example.test' }],
    passphrase,
    format: 'armored',
  });
  const pqBundle = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked,
    kemPublicKey: pqBundle.kem.publicKey,
    sigPublicKey: pqBundle.signing.publicKey,
  });
  const identity = {
    identity: { name: 'Enroll Test', fingerprint, public_key: publicKey },
    post_quantum: {
      kem_public_key: uint8ToBase64(pqBundle.kem.publicKey),
      sig_public_key: uint8ToBase64(pqBundle.signing.publicKey),
    },
  };
  return { identity, mintFingerprint: fingerprint };
}

const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
function decodeLen(b64: string): number {
  return Buffer.from(b64, 'base64').length;
}

test('buildCanonicalVerifyFields: fingerprint == SHA256(decoded sign‖enc‖kem‖sig) — client/server DID agreement', async () => {
  const { identity } = await mintIdentityObject();
  const f = await buildCanonicalVerifyFields(identity);
  assert.ok(f, 'fields must be built');
  // The server re-derives over the DECODED raw bytes (Flint option-B parser) — reproduce it exactly.
  const h = createHash('sha256');
  h.update(Buffer.from(f!.public_key, 'base64')); // raw Ed25519
  h.update(Buffer.from(f!.x25519_pk, 'base64')); // raw X25519
  h.update(Buffer.from(f!.mlkem768_pk, 'base64')); // raw ML-KEM-1024
  h.update(Buffer.from(f!.mldsa65_pk, 'base64')); // raw ML-DSA-87
  assert.equal(h.digest('hex'), f!.fingerprint, 'DID must equal SHA256 of the four decoded raw keys');
});

test('buildCanonicalVerifyFields: exact per-alg DECODED lengths (I-6 injectivity) 32/32/1568/2592', async () => {
  const { identity } = await mintIdentityObject();
  const f = await buildCanonicalVerifyFields(identity);
  assert.ok(f);
  assert.equal(decodeLen(f!.public_key), 32, 'Ed25519 raw = 32B');
  assert.equal(decodeLen(f!.x25519_pk), 32, 'X25519 raw = 32B');
  assert.equal(decodeLen(f!.mlkem768_pk), 1568, 'ML-KEM-1024 raw = 1568B');
  assert.equal(decodeLen(f!.mldsa65_pk), 2592, 'ML-DSA-87 raw = 2592B');
});

test('buildCanonicalVerifyFields: all four keys are base64 and NOT armored (the KB#89341 trap)', async () => {
  const { identity } = await mintIdentityObject();
  const f = await buildCanonicalVerifyFields(identity);
  assert.ok(f);
  for (const k of ['public_key', 'x25519_pk', 'mlkem768_pk', 'mldsa65_pk'] as const) {
    assert.match(f![k], B64, `${k} must be base64`);
    assert.ok(!f![k].includes('BEGIN'), `${k} must NOT be an armored OpenPGP block`);
  }
  // The armored key is ~hundreds of chars and contains the PGP header; the raw b64 Ed25519 is ~44.
  assert.ok(f!.public_key.length < 64, 'public_key must be the RAW 32B Ed25519 (b64 ~44 chars), not armored');
});

test('buildCanonicalVerifyFields: full-64 hex DID + key_version 2', async () => {
  const { identity } = await mintIdentityObject();
  const f = await buildCanonicalVerifyFields(identity);
  assert.ok(f);
  assert.match(f!.fingerprint, /^[0-9a-f]{64}$/, 'fingerprint must be the full 64-char hex canonical DID');
  assert.equal(f!.key_version, 2);
});

test('buildCanonicalVerifyFields: enroll DID == mint DID (no drift between mint and enroll paths)', async () => {
  const { identity, mintFingerprint } = await mintIdentityObject();
  const f = await buildCanonicalVerifyFields(identity);
  assert.ok(f);
  assert.equal(f!.fingerprint, mintFingerprint, 'the DID we register must equal the DID we minted');
});

test('buildCanonicalVerifyFields: fail-closed (null) on missing key material', async () => {
  assert.equal(await buildCanonicalVerifyFields({ identity: { public_key: 'x' } }), null, 'missing PQ → null');
  assert.equal(await buildCanonicalVerifyFields({ post_quantum: { kem_public_key: 'a', sig_public_key: 'b' } }), null, 'missing armored → null');
  assert.equal(await buildCanonicalVerifyFields({}), null, 'empty → null');
});
