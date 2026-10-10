// src/lib/identity/introduce-shell.test.ts
// Run: npx tsx --test src/lib/identity/introduce-shell.test.ts
//
// Introduce-shell (Devin dogfood, KB#91090): the headless agent-introduction artifact. Covers subject_type
// BOUND into the signed genesis DID-Doc (non-strippable, tamper-evident), the "must carry attestation" gate,
// same-crypto-path reuse, the enum, and the byte-exact co-verify vector for Flint.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { deriveCanonicalFingerprintHex } from './fingerprint';
import {
  buildDidDocument,
  canonicalDidDocInput,
  deriveDid,
  signDidDocGenesis,
  verifyDidDocument,
  type GenesisOperationalSigner,
} from './did-peer';
import { buildSignedBytes, SUITE_HYBRID } from '../crypto/sign-envelope';
import { DOMAIN_DID_DOC } from '../format/envelope';
import {
  buildAgentIntroduction,
  deriveGenesisAuthorityCommitment,
  verifyAgentIntroduction,
  type AgentGenesisKeys,
} from './introduce-shell';

// ── deterministic fixtures: an agent's genesis operational bundle + its cold-seed authority commitment ──
const signSeed = new Uint8Array(32).fill(0x21);
const signPub = ed25519.getPublicKey(signSeed);
const sig = ml_dsa87.keygen(new Uint8Array(32).fill(0x22)); // { secretKey, publicKey }
const encPub = new Uint8Array(32).fill(0x23);
const kemPub = new Uint8Array(1568).fill(0x24);
const keys: AgentGenesisKeys = { deviceSlug: 'genesis', signPub, encPub, kemPub, sigPub: sig.publicKey };
const signer: GenesisOperationalSigner = { signSeed, sigSecret: sig.secretKey };
const coldSeed = new Uint8Array(32).fill(0x2a);
const authorityCommitment = deriveGenesisAuthorityCommitment(coldSeed);

test('buildAgentIntroduction: reuses the SAME crypto paths (durable_id / did) + defaults subject_type=agent', () => {
  const intro = buildAgentIntroduction({ keys, signer, authorityCommitment });
  assert.equal(intro.durableId, deriveCanonicalFingerprintHex(signPub, encPub, kemPub, sig.publicKey));
  assert.equal(intro.did, deriveDid(signPub, encPub, kemPub, sig.publicKey));
  assert.equal(intro.did, `did:svrnty:${intro.durableId}`);
  assert.equal(intro.subjectType, 'agent');
  assert.equal(intro.signedDidDoc.subjectType, 'agent');
});

test('verifyAgentIntroduction: a valid agent introduction verifies + surfaces subject_type', () => {
  const intro = buildAgentIntroduction({ keys, signer, authorityCommitment });
  const v = verifyAgentIntroduction(intro);
  assert.ok(v, 'expected a verified introduction');
  assert.equal(v.subjectType, 'agent');
  assert.equal(v.durableId, intro.durableId);
  assert.equal(v.did, intro.did);
});

test('★ subject_type is BOUND under the signature — tampering it breaks verify (non-strippable)', () => {
  const intro = buildAgentIntroduction({ keys, signer, authorityCommitment });
  // flip the attestation on the SIGNED doc → the signature no longer covers the doc → verify fails
  const tampered = { ...intro, signedDidDoc: { ...intro.signedDidDoc, subjectType: 'human' as const } };
  assert.equal(verifyDidDocument(tampered.signedDidDoc).ok, false); // sig covers subjectType
  assert.equal(verifyAgentIntroduction(tampered), null);
  // stripping the attestation entirely also fails (introduction MUST carry it) AND breaks the sig
  const stripped = { ...intro.signedDidDoc } as Record<string, unknown>;
  delete stripped.subjectType;
  assert.equal(verifyDidDocument(stripped as unknown as typeof intro.signedDidDoc).ok, false);
});

test('an introduction WITHOUT a subject_type attestation is rejected (the honest declaration is mandatory)', () => {
  // build a valid genesis doc that omits subjectType, wrap it as an "introduction" → must be rejected
  const did = deriveDid(signPub, encPub, kemPub, sig.publicKey);
  const doc = signDidDocGenesis(
    buildDidDocument({ did, devices: [{ device: 'genesis', signPub, encPub, kemPub, sigPub: sig.publicKey }], nextAuthorityCommitment: authorityCommitment, seq: 0 }),
    signer,
  );
  assert.equal(doc.subjectType, undefined); // no attestation
  assert.equal(verifyDidDocument(doc).ok, true); // still a valid DID-Doc…
  // …but NOT a valid introduction (no honest self-declaration to verify socially)
  const fakeIntro = { did, durableId: deriveCanonicalFingerprintHex(signPub, encPub, kemPub, sig.publicKey), subjectType: 'agent' as const, signedDidDoc: doc };
  assert.equal(verifyAgentIntroduction(fakeIntro), null);
});

test('subject_type enum: human + org introductions verify; the attestation actually changes the signed bytes', () => {
  for (const st of ['human', 'org'] as const) {
    const intro = buildAgentIntroduction({ keys, signer, authorityCommitment, subjectType: st });
    const v = verifyAgentIntroduction(intro);
    assert.ok(v, `${st} introduction should verify`);
    assert.equal(v.subjectType, st);
  }
  // a doc WITH subjectType canonicalizes DIFFERENTLY from one without → the attestation is genuinely in the bytes
  const did = deriveDid(signPub, encPub, kemPub, sig.publicKey);
  const withAttest = buildDidDocument({ did, devices: [{ device: 'genesis', signPub, encPub, kemPub, sigPub: sig.publicKey }], nextAuthorityCommitment: authorityCommitment, subjectType: 'agent', seq: 0 });
  const without = buildDidDocument({ did, devices: [{ device: 'genesis', signPub, encPub, kemPub, sigPub: sig.publicKey }], nextAuthorityCommitment: authorityCommitment, seq: 0 });
  assert.notEqual(canonicalDidDocInput(withAttest), canonicalDidDocInput(without));
});

test('claimed durableId/did must match the signed doc (a spliced claim is rejected)', () => {
  const intro = buildAgentIntroduction({ keys, signer, authorityCommitment });
  assert.equal(verifyAgentIntroduction({ ...intro, durableId: 'f'.repeat(64) }), null);
  assert.equal(verifyAgentIntroduction({ ...intro, did: 'did:svrnty:' + 'a'.repeat(64) }), null);
});

test('EMIT co-verify vector — agent introduction (subject_type-bound genesis DID-Doc)', () => {
  const intro = buildAgentIntroduction({
    keys,
    signer,
    authorityCommitment,
    services: [{ id: `${deriveDid(signPub, encPub, kemPub, sig.publicKey)}#mbox`, type: 'SvrntyMailbox', purpose: 'agent', serviceEndpoint: 'svrnty-relay://blinded-agent-tag-0001' }],
  });
  const canon = canonicalDidDocInput(intro.signedDidDoc);
  const signedBytes = buildSignedBytes(DOMAIN_DID_DOC, SUITE_HYBRID, canon);
  const vector = {
    _note: 'introduce-shell co-verify vector (Apollo). subject_type is BOUND in the signed genesis DID-Doc canonical_input (verify it appears in canonical_input + that flipping it breaks the sig). Reuses SAME crypto paths as T1. ed25519 leg deterministic; ML-DSA verify-only.',
    did: intro.did,
    durable_id: intro.durableId,
    subject_type: intro.subjectType,
    authority_commitment: authorityCommitment,
    genesis_sign_pub_hex: bytesToHex(signPub),
    genesis_sig_pub_sha256: bytesToHex(sha256(sig.publicKey)),
    subject_type_in_canonical: canon.includes('"subjectType":"agent"'),
    canonical_input: canon,
    signed_bytes_prefix: signedBytes.slice(0, 140),
    signed_bytes_len: new TextEncoder().encode(signedBytes).length,
    sig_ed25519_leg_hex: intro.signedDidDoc.proof!.sig.slice(0, 128),
    expect: 'verifyAgentIntroduction(intro) !== null; subject_type==="agent"; subject_type_in_canonical===true',
  };
  console.log('\n===INTRODUCE_VECTOR_BEGIN===');
  console.log(JSON.stringify(vector, null, 2));
  console.log('===INTRODUCE_VECTOR_END===\n');
  assert.ok(verifyAgentIntroduction(intro));
  assert.ok(canon.includes('"subjectType":"agent"'));
});
