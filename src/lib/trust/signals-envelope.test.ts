// 0.1 sign-envelope end-to-end: trust-signal round-trip, tamper / attribution / NFC / downgrade,
// legacy back-compat, and the F6 signed slug-claim. Real keys, generated once in before().
// Run: npx tsx --test src/lib/trust/signals-envelope.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKey,
  readKey,
  readPrivateKey,
  decryptKey,
  createMessage,
  sign as pgpSign,
} from 'openpgp';
import { createSignal, verifySignal, vouchSignal } from './signals';
import { signSlugClaim, verifySignedSlugClaim } from './slug-claim';
import { generateSigningKeypair, type PQSigningKeypair } from '../crypto/pq';

const passphrase = 'test-passphrase-0';
const otherPass = 'test-passphrase-1';
const TO = 'RECIPIENT_FINGERPRINT';

// Generated once before any test (keygen is expensive) — a before() hook rather than top-level
// await, which the test runner's CJS output does not support.
let privateKey: string;
let publicKey: string;
let fingerprint: string;
let pq: PQSigningKeypair;
let otherPriv: string;
let otherPub: string;
let otherFingerprint: string;

before(async () => {
  ({ privateKey, publicKey } = await generateKey({
    type: 'curve25519',
    userIDs: [{ name: 'Alice', email: 'alice@example.test' }],
    passphrase,
    format: 'armored',
  }));
  fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  pq = generateSigningKeypair(); // ML-DSA-87 { publicKey, secretKey }

  ({ privateKey: otherPriv, publicKey: otherPub } = await generateKey({
    type: 'curve25519',
    userIDs: [{ name: 'Mallory', email: 'm@example.test' }],
    passphrase: otherPass,
    format: 'armored',
  }));
  otherFingerprint = (await readKey({ armoredKey: otherPub })).getFingerprint();
});

/** Sign arbitrary text with Alice's classical key — used to forge a legacy (pre-0.1) signature. */
async function pgpSignText(text: string): Promise<string> {
  const pk = await readPrivateKey({ armoredKey: privateKey });
  const dk = await decryptKey({ privateKey: pk, passphrase });
  return (await pgpSign({ message: await createMessage({ text }), signingKeys: dk })).toString();
}

test('trust signal: classical round-trip verifies', async () => {
  const s = await createSignal(vouchSignal('bob'), fingerprint, TO, privateKey, passphrase);
  assert.equal(await verifySignal(s, publicKey), true);
});

test('tampering the payload breaks verification', async () => {
  const s = await createSignal(vouchSignal('bob'), fingerprint, TO, privateKey, passphrase);
  assert.equal(await verifySignal({ ...s, payload: vouchSignal('carol') }, publicKey), false);
});

test('attribution binding: tampering `from` breaks verification', async () => {
  const s = await createSignal(vouchSignal('bob'), fingerprint, TO, privateKey, passphrase);
  assert.equal(await verifySignal({ ...s, from: otherFingerprint }, publicKey), false);
});

test('NFC robustness: composed vs decomposed unicode verify identically', async () => {
  const composed = 'café'; // é as one code point (NFC)
  const decomposed = 'café'; // e + combining acute (NFD)
  const s = await createSignal(vouchSignal(composed), fingerprint, TO, privateKey, passphrase);
  // A verifier that received the name in a different normal form must still accept it —
  // exactly the failure the old JSON.stringify signer had.
  assert.equal(await verifySignal({ ...s, payload: vouchSignal(decomposed) }, publicKey), true);
});

test('legacy back-compat: a pre-0.1 with-from JSON.stringify signature still verifies', async () => {
  const payload = vouchSignal('bob');
  const timestamp = new Date().toISOString();
  const legacyBytes = JSON.stringify({ payload, from: fingerprint, to: TO, timestamp });
  const signature = await pgpSignText(legacyBytes);
  const legacySignal = { payload, from: fingerprint, to: TO, timestamp, signature };
  assert.equal(await verifySignal(legacySignal, publicKey), true);
});

test('downgrade resistance: stripping the PQ half of a hybrid signal fails', async () => {
  const s = await createSignal(vouchSignal('bob'), fingerprint, TO, privateKey, passphrase, pq.secretKey);
  assert.ok(s.pq_signature, 'expected a hybrid signal');
  assert.equal(await verifySignal(s, publicKey, pq.publicKey), true);
  const stripped = { ...s };
  delete stripped.pq_signature;
  // The classical half signed the HYBRID-suite bytes; verified as classical it reconstructs
  // CLASSICAL-suite bytes → no match. Downgrade defeated.
  assert.equal(await verifySignal(stripped, publicKey, pq.publicKey), false);
});

// --- F6: signed slug claim ---

test('F6: a slug claim signed by the key holder verifies', async () => {
  const claim = { slug: 'alice', fingerprint, public_key: publicKey, timestamp: new Date().toISOString() };
  const signed = await signSlugClaim(claim, privateKey, passphrase);
  assert.equal(await verifySignedSlugClaim(signed), true);
});

test('F6: a fingerprint that does not hash to the public key is refused', async () => {
  const claim = { slug: 'alice', fingerprint: otherFingerprint, public_key: publicKey, timestamp: new Date().toISOString() };
  const signed = await signSlugClaim(claim, privateKey, passphrase);
  // Signature is valid, but fingerprint !== H(public_key) → refuse (the binding half of F6).
  assert.equal(await verifySignedSlugClaim(signed), false);
});

test('F6: tampering the slug after signing is refused', async () => {
  const claim = { slug: 'alice', fingerprint, public_key: publicKey, timestamp: new Date().toISOString() };
  const signed = await signSlugClaim(claim, privateKey, passphrase);
  assert.equal(await verifySignedSlugClaim({ ...signed, slug: 'bob' }), false);
});

test('F6: an attacker cannot claim a slug for a key they do not hold', async () => {
  // Mallory signs with HER key but presents Alice's fingerprint + public_key.
  const claim = { slug: 'alice', fingerprint, public_key: publicKey, timestamp: new Date().toISOString() };
  const forged = await signSlugClaim(claim, otherPriv, otherPass);
  // fingerprint == H(public_key) holds (both Alice's), but the signature was made by Mallory's
  // key, so it fails to verify against Alice's public_key. Refused.
  assert.equal(await verifySignedSlugClaim(forged), false);
});
