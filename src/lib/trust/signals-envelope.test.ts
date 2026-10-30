// 0.1 sign-envelope end-to-end: trust-signal round-trip, tamper / attribution / NFC / downgrade,
// legacy back-compat, and the F6 signed slug-claim. Real keys, generated once in before().
// Run: npx tsx --test src/lib/trust/signals-envelope.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKey,
  readPrivateKey,
  decryptKey,
  createMessage,
  sign as pgpSign,
} from 'openpgp';
import { createSignal, verifySignal, vouchSignal } from './signals';
import { formatSignalMessage, parseSignalMessage } from './transport';
import { signSlugClaim, verifySignedSlugClaim } from './slug-claim';
import { generatePQKeypairBundle, uint8ToBase64, type PQSigningKeypair } from '../crypto/pq';
import { mintCanonicalFingerprint } from '../identity/fingerprint';

const passphrase = 'test-passphrase-0';
const otherPass = 'test-passphrase-1';
const TO = 'RECIPIENT_FINGERPRINT';

// Generated once before any test (keygen is expensive) — a before() hook rather than top-level
// await, which the test runner's CJS output does not support.
// Both identities are §5 CANONICAL: openpgp (sign+enc) + ML-KEM/ML-DSA → a 64-hex SHA256(sign‖enc‖kem‖sig)
// fingerprint. Post-res1 fingerprintMatchesKey is canonical-only, so the F6 slug claims below must carry
// the PQ pubkeys (kemB64/sigB64) for the fingerprint ≡ H(keys) half to bind.
let privateKey: string;
let publicKey: string;
let fingerprint: string;
let pq: PQSigningKeypair; // Alice's ML-DSA-87 identity leg — also the PQ half of the hybrid signal test
let kemB64: string;
let sigB64: string;
let otherPriv: string;
let otherFingerprint: string;

async function makeCanonicalIdentity(name: string, email: string, passphrase: string) {
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same as src/lib/identity/core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email }],
    passphrase,
    format: 'armored',
  });
  const bundle = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked, kemPublicKey: bundle.kem.publicKey, sigPublicKey: bundle.signing.publicKey,
  });
  return {
    privateKey, publicKey, fingerprint, signing: bundle.signing,
    kemB64: uint8ToBase64(bundle.kem.publicKey),
    sigB64: uint8ToBase64(bundle.signing.publicKey),
  };
}

before(async () => {
  const alice = await makeCanonicalIdentity('Alice', 'alice@example.test', passphrase);
  ({ privateKey, publicKey, fingerprint, kemB64, sigB64 } = alice);
  pq = alice.signing; // ML-DSA-87 { publicKey, secretKey }

  ({ privateKey: otherPriv, fingerprint: otherFingerprint } =
    await makeCanonicalIdentity('Mallory', 'm@example.test', otherPass));
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

test('#718: legacy pre-0.1 signatures are REFUSED (L1 with-from and L2 from-unsigned); only the 0.1 envelope verifies', async () => {
  // The legacy verify loop sunset on ~2026-08-23 (7-day freshness window after 0.1). No code on any branch
  // emits these bytes; it was the only path into hybridVerify's classical-only branch besides verifyWithEnvelope.
  const payload = vouchSignal('bob');
  const timestamp = new Date().toISOString();
  const l1 = await pgpSignText(JSON.stringify({ payload, from: fingerprint, to: TO, timestamp }));
  assert.equal(await verifySignal({ payload, from: fingerprint, to: TO, timestamp, signature: l1 }, publicKey), false, 'L1');
  const l2 = await pgpSignText(JSON.stringify({ payload, to: TO, timestamp }));
  assert.equal(await verifySignal({ payload, from: fingerprint, to: TO, timestamp, signature: l2 }, publicKey), false, 'L2');
  // control: the same content through the 0.1 envelope verifies
  const s = await createSignal(payload, fingerprint, TO, privateKey, passphrase);
  assert.equal(await verifySignal(s, publicKey), true);
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
  const signed = await signSlugClaim(claim, privateKey, passphrase, undefined, kemB64, sigB64);
  assert.equal(await verifySignedSlugClaim(signed), true);
});

test('F6: a fingerprint that does not hash to the public key is refused', async () => {
  const claim = { slug: 'alice', fingerprint: otherFingerprint, public_key: publicKey, timestamp: new Date().toISOString() };
  const signed = await signSlugClaim(claim, privateKey, passphrase, undefined, kemB64, sigB64);
  // Signature is valid, but fingerprint !== H(public_key) → refuse (the binding half of F6).
  assert.equal(await verifySignedSlugClaim(signed), false);
});

test('F6: tampering the slug after signing is refused', async () => {
  const claim = { slug: 'alice', fingerprint, public_key: publicKey, timestamp: new Date().toISOString() };
  const signed = await signSlugClaim(claim, privateKey, passphrase, undefined, kemB64, sigB64);
  assert.equal(await verifySignedSlugClaim({ ...signed, slug: 'bob' }), false);
});

test('F6: an attacker cannot claim a slug for a key they do not hold', async () => {
  // Mallory signs with HER key but presents Alice's fingerprint + public_key (+ Alice's PQ pubkeys).
  const claim = { slug: 'alice', fingerprint, public_key: publicKey, timestamp: new Date().toISOString() };
  const forged = await signSlugClaim(claim, otherPriv, otherPass, undefined, kemB64, sigB64);
  // fingerprint == H(public_key) holds (both Alice's), but the signature was made by Mallory's
  // key, so it fails to verify against Alice's public_key. Refused.
  assert.equal(await verifySignedSlugClaim(forged), false);
});

test('#717: a malformed pq_signature ("" / null / 0 / false) refuses, never reads as classical', async () => {
  const s = await createSignal(vouchSignal('bob'), fingerprint, TO, privateKey, passphrase);
  assert.equal(await verifySignal(s, publicKey), true); // control
  for (const bad of ['', null, 0, false] as unknown[]) {
    assert.equal(await verifySignal({ ...s, pq_signature: bad } as typeof s, publicKey), false, `pq=${JSON.stringify(bad)}`);
  }
});

test('#718: the paste transport keeps pq_signature raw ("" stays "", absent stays absent), so verify can refuse it', async () => {
  const s = await createSignal(vouchSignal('bob'), fingerprint, TO, privateKey, passphrase);
  const back = parseSignalMessage(formatSignalMessage(s));
  assert.ok(back);
  assert.equal(back.pq_signature, undefined, 'absent stays absent');
  assert.equal(await verifySignal(back, publicKey), true); // control
  const forged = parseSignalMessage(formatSignalMessage({ ...s, pq_signature: '' }));
  assert.ok(forged);
  assert.equal(forged.pq_signature, '', '"" must survive the transport, not become absent');
  assert.equal(await verifySignal(forged, publicKey), false);
  const h = await createSignal(vouchSignal('bob'), fingerprint, TO, privateKey, passphrase, pq.secretKey);
  const hb = parseSignalMessage(formatSignalMessage(h));
  assert.equal(hb?.pq_signature, h.pq_signature, 'hybrid round-trips');
  assert.equal(await verifySignal(hb!, publicKey, pq.publicKey), true);
});
