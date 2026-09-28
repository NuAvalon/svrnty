// src/lib/identity/did-peer.test.ts
// Run: npx tsx --test src/lib/identity/did-peer.test.ts
//
// T1 DID + DID-Document: stable-anchor id (migratability), build, hybrid authority sign/verify (reuses X5),
// multi-device add/revoke, monotonic seq, tamper, and the STABLE-ACROSS-ROTATION property. The last test
// EMITS the byte-exact co-verify vector (canonical_input + signed_bytes + sig) for Flint's review + a Python
// cross-impl — signed_bytes is the byte-exact seam; the ed25519 leg is reproducible, ML-DSA is verify-only.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { deriveNextAuthorityKeypair } from './fingerprint';
import { buildSignedBytes, SUITE_HYBRID } from '../crypto/sign-envelope';
import { DOMAIN_DID_DOC } from '../format/envelope';
import {
  addDevice,
  anchorFromAuthorityReveal,
  buildDidDocument,
  canonicalDidDocInput,
  deriveDid,
  parseDid,
  resolveVerificationMethod,
  revokeDevice,
  signDidDocument,
  verifyDidDocument,
  type DeviceKeys,
} from './did-peer';

// ── deterministic fixtures ──
const masterSecret = new Uint8Array(32).fill(0x07); // stand-in cold seed
const auth0 = deriveNextAuthorityKeypair(masterSecret, 0); // genesis (epoch-0) authority
const authority = { edPublic: auth0.edPublic, edSecret: auth0.edSecret, dsaPublic: auth0.dsaPublic, dsaSecret: auth0.dsaSecret };
const DID = deriveDid(auth0.edPublic, auth0.dsaPublic);

function dev(slug: string, fill: number): DeviceKeys {
  return {
    device: slug,
    signPub: new Uint8Array(32).fill(fill),
    encPub: new Uint8Array(32).fill(fill + 1),
    kemPub: new Uint8Array(1568).fill(fill + 2),
    sigPub: new Uint8Array(2592).fill(fill + 3),
  };
}
const phone = dev('phone', 0x10);
const laptop = dev('laptop', 0x20);

test('deriveDid: deterministic + stable, 64-hex anchor, parseable', () => {
  assert.equal(DID, deriveDid(auth0.edPublic, auth0.dsaPublic)); // deterministic
  assert.ok(DID.startsWith('did:svrnty:'));
  const { anchorHex } = parseDid(DID);
  assert.match(anchorHex, /^[0-9a-f]{64}$/);
  assert.equal(anchorFromAuthorityReveal(bytesToHex(auth0.edPublic), bytesToHex(auth0.dsaPublic)), DID);
});

test('buildDidDocument: shape — VMs, keyAgreement, authentication, service, seq', () => {
  const doc = buildDidDocument({ did: DID, devices: [phone], seq: 0 });
  assert.equal(doc.id, DID);
  assert.equal(doc.verificationMethod.length, 2); // ed25519 + ML-DSA-87
  assert.equal(doc.keyAgreement.length, 2); // x25519 + ML-KEM
  assert.deepEqual(doc.authentication, [`${DID}#phone-sign`, `${DID}#phone-sig`]);
  assert.equal(doc.seq, 0);
  assert.equal(resolveVerificationMethod(doc, `${DID}#phone-sign`)?.publicKeyHex, bytesToHex(phone.signPub));
});

test('build fail-closed: bad slug, duplicate device, no devices', () => {
  assert.throws(() => buildDidDocument({ did: DID, devices: [dev('Phone!', 1)] })); // uppercase/!
  assert.throws(() => buildDidDocument({ did: DID, devices: [phone, dev('phone', 0x30)] })); // dup slug
  assert.throws(() => buildDidDocument({ did: DID, devices: [] }));
});

test('sign → verify roundtrip (genesis epoch 0)', () => {
  const doc = signDidDocument(buildDidDocument({ did: DID, devices: [phone] }), authority, 0);
  assert.ok(doc.proof);
  const r = verifyDidDocument(doc);
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.seq, 0);
});

test('tamper: mutating a signed field → verify fails', () => {
  const doc = signDidDocument(buildDidDocument({ did: DID, devices: [phone] }), authority, 0);
  const tampSeq = { ...doc, seq: doc.seq + 5 };
  assert.equal(verifyDidDocument(tampSeq).ok, false);
  const tampKey = { ...doc, verificationMethod: doc.verificationMethod.map((v, i) => (i === 0 ? { ...v, publicKeyHex: v.publicKeyHex.replace(/^../, 'ff') } : v)) };
  assert.equal(verifyDidDocument(tampKey).ok, false);
  const tampSvc = { ...doc, service: [{ id: `${DID}#m`, type: 'SvrntyMailbox', serviceEndpoint: 'relay://evil' }] };
  assert.equal(verifyDidDocument(tampSvc).ok, false);
});

test('authority binding: pubs that do not hash to the id anchor cannot sign it', () => {
  const other = deriveNextAuthorityKeypair(new Uint8Array(32).fill(0x09), 0);
  const otherAuthority = { edPublic: other.edPublic, edSecret: other.edSecret, dsaPublic: other.dsaPublic, dsaSecret: other.dsaSecret };
  // signing DID (anchored to auth0) with a DIFFERENT authority → fail-closed at sign time
  assert.throws(() => signDidDocument(buildDidDocument({ did: DID, devices: [phone] }), otherAuthority, 0));
  // and a forged doc whose proof reveals the wrong authority → verify rejects (anchor mismatch)
  const forged = signDidDocument(buildDidDocument({ did: deriveDid(other.edPublic, other.dsaPublic), devices: [phone] }), otherAuthority, 0);
  const spliced = { ...forged, id: DID }; // claim DID but proof authority hashes to other's anchor
  assert.equal(verifyDidDocument(spliced).ok, false);
});

test('seq monotonic: a doc with seq ≤ last-seen is rejected at the edge', () => {
  const doc = signDidDocument(buildDidDocument({ did: DID, devices: [phone], seq: 3 }), authority, 0);
  assert.equal(verifyDidDocument(doc, { lastSeenSeq: 2 }).ok, true);
  assert.equal(verifyDidDocument(doc, { lastSeenSeq: 3 }).ok, false); // replay of same seq
  assert.equal(verifyDidDocument(doc, { lastSeenSeq: 4 }).ok, false); // stale
});

test('multi-device: add a device (seq++), verify; revoke it (seq++), verify; cannot revoke last', () => {
  const g = buildDidDocument({ did: DID, devices: [phone], seq: 0 });
  const withLaptop = addDevice(g, laptop);
  assert.equal(withLaptop.seq, 1);
  assert.ok(resolveVerificationMethod(withLaptop, `${DID}#laptop-sign`));
  const signed2 = signDidDocument(withLaptop, authority, 0);
  assert.equal(verifyDidDocument(signed2).ok, true);
  assert.throws(() => addDevice(withLaptop, laptop)); // duplicate

  const revoked = revokeDevice(withLaptop, 'laptop');
  assert.equal(revoked.seq, 2);
  assert.equal(resolveVerificationMethod(revoked, `${DID}#laptop-sign`), undefined);
  assert.equal(verifyDidDocument(signDidDocument(revoked, authority, 0)).ok, true);
  assert.throws(() => revokeDevice(revoked, 'phone')); // last device
});

test('★ STABLE ACROSS ROTATION: new operational keys, SAME authority anchor → SAME DID (the migratability fix)', () => {
  // "rotate" the operational keys: a brand-new device key set entirely.
  const rotated = dev('phone', 0x40); // different sign/enc/kem/sig bytes
  const before = buildDidDocument({ did: DID, devices: [phone] });
  const after = buildDidDocument({ did: DID, devices: [rotated] });
  // operational keys changed…
  assert.notEqual(resolveVerificationMethod(before, `${DID}#phone-sign`)?.publicKeyHex, resolveVerificationMethod(after, `${DID}#phone-sign`)?.publicKeyHex);
  // …but the identity (the DID) did NOT. This is exactly what a fp=SHA256(keys) identity could NOT do.
  assert.equal(before.id, after.id);
  assert.equal(verifyDidDocument(signDidDocument(after, authority, 0)).ok, true);
});

test('EMIT co-verify vector (canonical_input + signed_bytes byte-exact; ed25519 leg reproducible)', () => {
  const doc = signDidDocument(buildDidDocument({
    did: DID,
    devices: [phone],
    services: [{ id: `${DID}#mbox`, type: 'SvrntyMailbox', purpose: 'human', serviceEndpoint: 'svrnty-relay://blinded-tag-0001' }],
    seq: 0,
  }), authority, 0);
  const canonicalInput = canonicalDidDocInput(doc);
  const signedBytes = buildSignedBytes(DOMAIN_DID_DOC, SUITE_HYBRID, canonicalInput);
  const vector = {
    _note: 'T1 DID-Doc co-verify vector (Apollo). BYTE-EXACT seam = canonical_input + signed_bytes (reproduce EXACTLY). ed25519 leg deterministic; ML-DSA verify-only.',
    master_secret_hex: bytesToHex(masterSecret),
    did: DID,
    authority_ed_pub_hex: bytesToHex(auth0.edPublic),
    authority_dsa_pub_sha256: bytesToHex(sha256(auth0.dsaPublic)), // 2592B pub → hash for brevity
    canonical_input: canonicalInput,
    signed_bytes_prefix: signedBytes.slice(0, 120),
    signed_bytes_len: new TextEncoder().encode(signedBytes).length,
    sig_ed25519_leg_hex: doc.proof!.sig.slice(0, 128), // first 64B (ed25519) — deterministic, byte-checkable
    seq: doc.seq,
    expect: 'verifyDidDocument(doc).ok === true',
  };
  console.log('\n===DIDDOC_VECTOR_BEGIN===');
  console.log(JSON.stringify(vector, null, 2));
  console.log('===DIDDOC_VECTOR_END===\n');
  assert.equal(verifyDidDocument(doc).ok, true);
});
