// src/lib/identity/did-peer.test.ts
// Run: npx tsx --test src/lib/identity/did-peer.test.ts
//
// T1 (c)-collapse: durable_id-anchored DID + TWO-SIGNER DID-Document (genesis operational-self-sign /
// mutation cold-seed-authority-sign). Covers: durable_id anchor == canonical fingerprint, build shape,
// genesis self-certification + fail-closed, authority-mutation commitment chain, multi-device rotation with a
// STABLE id, monotonic seq, tamper, and the byte-exact co-verify vector (genesis + mutation) for Flint + a
// Python cross-impl. signed_bytes is the byte-exact seam; ed25519 legs are reproducible, ML-DSA is verify-only.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  deriveCanonicalFingerprintHex,
  deriveNextAuthorityKeypair,
  deriveNextAuthorityCommitment,
  authorityCommitmentFromReveal,
} from './fingerprint';
import { buildSignedBytes, SUITE_HYBRID } from '../crypto/sign-envelope';
import { DOMAIN_DID_DOC } from '../format/envelope';
import {
  addDevice,
  buildDidDocument,
  canonicalDidDocInput,
  deriveDid,
  didFromFingerprint,
  extractGenesisOperationalKeys,
  parseDid,
  resolveVerificationMethod,
  revokeDevice,
  setNextAuthorityCommitment,
  signDidDocGenesis,
  signDidDocMutation,
  verifyDidDocument,
  type DeviceKeys,
  type GenesisOperationalSigner,
} from './did-peer';

// ── deterministic fixtures ──
// Cold-seed governance authority (epoch 0) + its pre-rotation commitment (what the genesis doc pins).
const masterSecret = new Uint8Array(32).fill(0x07);
const auth0 = deriveNextAuthorityKeypair(masterSecret, 0);
const nac0 = deriveNextAuthorityCommitment(masterSecret, 0); // H(auth0 pubs) — genesis's nextAuthorityCommitment
const auth1 = deriveNextAuthorityKeypair(masterSecret, 1); // a ROTATED authority
const nac1 = deriveNextAuthorityCommitment(masterSecret, 1);

// Genesis operational key bundle → durable_id. signSeed is the raw ed25519 seed (extractRawSign shape).
const gSignSeed = new Uint8Array(32).fill(0x11);
const gSignPub = ed25519.getPublicKey(gSignSeed);
const gSig = ml_dsa87.keygen(new Uint8Array(32).fill(0x12)); // { secretKey, publicKey } — publicKey is 2592B
const gEncPub = new Uint8Array(32).fill(0x13);
const gKemPub = new Uint8Array(1568).fill(0x14);
const genesisDevice: DeviceKeys = { device: 'genesis', signPub: gSignPub, encPub: gEncPub, kemPub: gKemPub, sigPub: gSig.publicKey };
const operationalSigner: GenesisOperationalSigner = { signSeed: gSignSeed, sigSecret: gSig.secretKey };

const DURABLE = deriveCanonicalFingerprintHex(gSignPub, gEncPub, gKemPub, gSig.publicKey);
const DID = didFromFingerprint(DURABLE);

function dev(slug: string, fill: number): DeviceKeys {
  return {
    device: slug,
    signPub: new Uint8Array(32).fill(fill),
    encPub: new Uint8Array(32).fill(fill + 1),
    kemPub: new Uint8Array(1568).fill(fill + 2),
    sigPub: new Uint8Array(2592).fill(fill + 3),
  };
}
const laptop = dev('laptop', 0x20);

const genesisUnsigned = () => buildDidDocument({ did: DID, devices: [genesisDevice], nextAuthorityCommitment: nac0, seq: 0 });
const genesisSigned = () => signDidDocGenesis(genesisUnsigned(), operationalSigner);

test('fixtures: commitment reveal round-trips (H(auth0 pubs) == nac0)', () => {
  assert.equal(authorityCommitmentFromReveal(bytesToHex(auth0.edPublic), bytesToHex(auth0.dsaPublic)), nac0);
  assert.notEqual(nac0, nac1);
});

test('deriveDid: anchor == durable_id (canonical fingerprint), 64-hex, parseable, didFromFingerprint agrees', () => {
  assert.equal(deriveDid(gSignPub, gEncPub, gKemPub, gSig.publicKey), DID);
  assert.equal(DID, `did:svrnty:${DURABLE}`);
  assert.ok(DID.startsWith('did:svrnty:'));
  const { anchorHex } = parseDid(DID);
  assert.equal(anchorHex, DURABLE);
  assert.match(anchorHex, /^[0-9a-f]{64}$/);
});

test('buildDidDocument: shape — VMs, keyAgreement, authentication, seq, nextAuthorityCommitment', () => {
  const doc = genesisUnsigned();
  assert.equal(doc.id, DID);
  assert.equal(doc.verificationMethod.length, 2); // ed25519 + ML-DSA-87
  assert.equal(doc.keyAgreement.length, 2); // x25519 + ML-KEM
  assert.deepEqual(doc.authentication, [`${DID}#genesis-sign`, `${DID}#genesis-sig`]);
  assert.equal(doc.seq, 0);
  assert.equal(doc.nextAuthorityCommitment, nac0);
  assert.equal(resolveVerificationMethod(doc, `${DID}#genesis-sign`)?.publicKeyHex, bytesToHex(gSignPub));
  const keys = extractGenesisOperationalKeys(doc)!;
  assert.equal(deriveCanonicalFingerprintHex(keys.signPub, keys.encPub, keys.kemPub, keys.sigPub), DURABLE);
});

test('build fail-closed: bad slug, duplicate device, no devices, bad nextAuthorityCommitment', () => {
  assert.throws(() => buildDidDocument({ did: DID, devices: [dev('Phone!', 1)], nextAuthorityCommitment: nac0 }));
  assert.throws(() => buildDidDocument({ did: DID, devices: [genesisDevice, dev('genesis', 0x30)], nextAuthorityCommitment: nac0 }));
  assert.throws(() => buildDidDocument({ did: DID, devices: [], nextAuthorityCommitment: nac0 }));
  assert.throws(() => buildDidDocument({ did: DID, devices: [genesisDevice], nextAuthorityCommitment: 'nothex' }));
});

test('GENESIS self-sign → verify roundtrip (operational-key path)', () => {
  const doc = genesisSigned();
  assert.equal(doc.proof?.mode, 'genesis-operational');
  assert.equal(doc.proof?.authorityPubkeys, undefined); // genesis reveals nothing extra — pubs are the doc's own VMs
  const r = verifyDidDocument(doc);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.seq, 0);
  assert.equal(r.nextAuthorityCommitment, nac0); // edge threads this as the next expected commitment
});

test('GENESIS fail-closed: wrong seed, wrong seq, spliced id, tampered field', () => {
  // signSeed that does not match the doc's genesis sign pub → refuse to sign
  assert.throws(() => signDidDocGenesis(genesisUnsigned(), { signSeed: new Uint8Array(32).fill(0x99), sigSecret: gSig.secretKey }));
  // a seq>0 doc cannot be genesis-self-signed
  const seq1 = buildDidDocument({ did: DID, devices: [genesisDevice], nextAuthorityCommitment: nac0, seq: 1 });
  assert.throws(() => signDidDocGenesis(seq1, operationalSigner));
  // splice a different id onto a validly-signed genesis doc → operational keys no longer anchor to id
  const doc = genesisSigned();
  const otherDid = didFromFingerprint('a'.repeat(64));
  assert.equal(verifyDidDocument({ ...doc, id: otherDid }).ok, false);
  // tamper a signed field
  assert.equal(verifyDidDocument({ ...doc, seq: doc.seq + 5 }).ok, false);
  assert.equal(verifyDidDocument({ ...doc, nextAuthorityCommitment: nac1 }).ok, false);
});

test('MUTATION: authority-signed add-device verifies iff the revealed authority matches the committed commitment', () => {
  const withLaptop = signDidDocMutation(addDevice(genesisSigned(), laptop), auth0); // seq 1, authority-signed
  assert.equal(withLaptop.seq, 1);
  assert.equal(withLaptop.proof?.mode, 'authority-mutation');
  assert.equal(withLaptop.id, DID); // id unchanged
  assert.ok(resolveVerificationMethod(withLaptop, `${DID}#laptop-sign`));
  // valid with the genesis-committed nac0
  assert.equal(verifyDidDocument(withLaptop, { expectedAuthorityCommitment: nac0 }).ok, true);
  // MISSING commitment → cannot validate authority (fail-closed)
  assert.equal(verifyDidDocument(withLaptop).ok, false);
  assert.equal(verifyDidDocument(withLaptop).reason, 'authority-commitment-required');
  // WRONG commitment → authority not committed
  assert.equal(verifyDidDocument(withLaptop, { expectedAuthorityCommitment: nac1 }).ok, false);
  // a mutation signed by an UNCOMMITTED authority (auth1) is rejected under nac0
  const forged = signDidDocMutation(addDevice(genesisSigned(), laptop), auth1);
  assert.equal(verifyDidDocument(forged, { expectedAuthorityCommitment: nac0 }).ok, false);
});

test('MUTATION: genesis cannot masquerade as mutation and vice-versa (seq guards both paths)', () => {
  // signDidDocMutation refuses seq 0
  assert.throws(() => signDidDocMutation(genesisUnsigned(), auth0));
  // a seq-0 doc carrying an authority-mutation proof is rejected (genesis-must-be-seq-0 is enforced only for
  // genesis-mode; an authority proof at seq 0 fails the mutation-must-advance-seq guard)
  const bad = { ...genesisSigned(), proof: signDidDocMutation(addDevice(genesisSigned(), laptop), auth0).proof, seq: 0 };
  assert.equal(verifyDidDocument(bad, { expectedAuthorityCommitment: nac0 }).ok, false);
});

test('seq monotonic: a doc with seq ≤ last-seen is rejected at the edge', () => {
  const m = signDidDocMutation(setNextAuthorityCommitment(genesisSigned(), nac0), auth0); // seq 1
  assert.equal(verifyDidDocument(m, { lastSeenSeq: 0, expectedAuthorityCommitment: nac0 }).ok, true);
  assert.equal(verifyDidDocument(m, { lastSeenSeq: 1, expectedAuthorityCommitment: nac0 }).ok, false); // replay
  assert.equal(verifyDidDocument(m, { lastSeenSeq: 2, expectedAuthorityCommitment: nac0 }).ok, false); // stale
});

test('★ STABLE ACROSS ROTATION: authority mutation swaps ALL operational keys, DID id unchanged (migratability)', () => {
  const genesis = genesisSigned();
  assert.equal(verifyDidDocument(genesis).ok, true);
  // "rotate": add a brand-new device (new operational keys), then revoke the genesis device — authority-signed.
  const withNew = addDevice(genesis, laptop); // seq 1 (2 devices)
  const rotated = revokeDevice(withNew, 'genesis'); // seq 2 (genesis keys gone)
  const signedRotated = signDidDocMutation(rotated, auth0);
  // the current operational keys are entirely new…
  assert.equal(resolveVerificationMethod(signedRotated, `${DID}#genesis-sign`), undefined);
  assert.ok(resolveVerificationMethod(signedRotated, `${DID}#laptop-sign`));
  // …but the identity (the durable DID handle) did NOT change — this is exactly what fp=SHA256(currentKeys) could not do.
  assert.equal(signedRotated.id, DID);
  assert.equal(verifyDidDocument(signedRotated, { lastSeenSeq: 1, expectedAuthorityCommitment: nac0 }).ok, true);
});

test('AUTHORITY ROTATION lineage: a doc can pin a NEW authority; the next hop must be signed by it', () => {
  // seq 1: still auth0-signed, but pins nac1 for the successor (authority rotation announced).
  const rotateAuth = signDidDocMutation(setNextAuthorityCommitment(genesisSigned(), nac1), auth0);
  const r1 = verifyDidDocument(rotateAuth, { expectedAuthorityCommitment: nac0 });
  assert.equal(r1.ok, true, r1.reason);
  assert.equal(r1.nextAuthorityCommitment, nac1); // edge now expects auth1 for the next doc
  // seq 2: must be signed by auth1 (matches nac1); auth0 would now be rejected.
  const next = signDidDocMutation(setNextAuthorityCommitment(rotateAuth, nac1), auth1);
  assert.equal(verifyDidDocument(next, { lastSeenSeq: 1, expectedAuthorityCommitment: r1.nextAuthorityCommitment }).ok, true);
  const nextWrongAuth = signDidDocMutation(setNextAuthorityCommitment(rotateAuth, nac1), auth0);
  assert.equal(verifyDidDocument(nextWrongAuth, { lastSeenSeq: 1, expectedAuthorityCommitment: nac1 }).ok, false);
});

test('multi-device: cannot add a duplicate; cannot revoke the last device', () => {
  const withLaptop = addDevice(genesisSigned(), laptop);
  assert.throws(() => addDevice(withLaptop, laptop)); // duplicate slug
  const revoked = revokeDevice(withLaptop, 'genesis');
  assert.throws(() => revokeDevice(revoked, 'laptop')); // last device
});

test('EMIT co-verify vector — genesis (self-sign) + mutation (authority) byte-exact seams', () => {
  const genesis = signDidDocGenesis(buildDidDocument({
    did: DID,
    devices: [genesisDevice],
    nextAuthorityCommitment: nac0,
    services: [{ id: `${DID}#mbox`, type: 'SvrntyMailbox', purpose: 'human', serviceEndpoint: 'svrnty-relay://blinded-tag-0001' }],
    seq: 0,
  }), operationalSigner);
  const gCanon = canonicalDidDocInput(genesis);
  const gSignedBytes = buildSignedBytes(DOMAIN_DID_DOC, SUITE_HYBRID, gCanon);

  const mutation = signDidDocMutation(addDevice(genesis, laptop), auth0); // seq 1
  const mCanon = canonicalDidDocInput(mutation);
  const mSignedBytes = buildSignedBytes(DOMAIN_DID_DOC, SUITE_HYBRID, mCanon);

  const vector = {
    _note: 'T1 (c) DID-Doc co-verify vector (Apollo). BYTE-EXACT seam = canonical_input + signed_bytes (reproduce EXACTLY). ed25519 legs deterministic; ML-DSA verify-only. anchor = durable_id = deriveCanonicalFingerprintHex(genesis op keys).',
    master_secret_hex: bytesToHex(masterSecret),
    did: DID,
    durable_id: DURABLE,
    genesis_sign_pub_hex: bytesToHex(gSignPub),
    genesis_sig_pub_sha256: bytesToHex(sha256(gSig.publicKey)),
    genesis_enc_pub_hex: bytesToHex(gEncPub),
    genesis_kem_pub_sha256: bytesToHex(sha256(gKemPub)),
    next_authority_commitment: nac0,
    authority_ed_pub_hex: bytesToHex(auth0.edPublic),
    authority_dsa_pub_sha256: bytesToHex(sha256(auth0.dsaPublic)),
    genesis: {
      mode: 'genesis-operational',
      canonical_input: gCanon,
      signed_bytes_prefix: gSignedBytes.slice(0, 140),
      signed_bytes_len: new TextEncoder().encode(gSignedBytes).length,
      sig_ed25519_leg_hex: genesis.proof!.sig.slice(0, 128), // first 64B (ed25519) — deterministic
      expect: 'verifyDidDocument(genesis).ok === true (self-cert: op keys hash to durable_id)',
    },
    mutation: {
      mode: 'authority-mutation',
      seq: mutation.seq,
      canonical_input: mCanon,
      signed_bytes_prefix: mSignedBytes.slice(0, 140),
      signed_bytes_len: new TextEncoder().encode(mSignedBytes).length,
      sig_ed25519_leg_hex: mutation.proof!.sig.slice(0, 128),
      revealed_authority_sign_hex: mutation.proof!.authorityPubkeys!.sign,
      expect: 'verifyDidDocument(mutation, {expectedAuthorityCommitment: nac0}).ok === true; H(reveal)===nac0',
    },
  };
  console.log('\n===DIDDOC_C_VECTOR_BEGIN===');
  console.log(JSON.stringify(vector, null, 2));
  console.log('===DIDDOC_C_VECTOR_END===\n');

  assert.equal(verifyDidDocument(genesis).ok, true);
  assert.equal(verifyDidDocument(mutation, { expectedAuthorityCommitment: nac0 }).ok, true);
});
