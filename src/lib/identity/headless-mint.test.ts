// src/lib/identity/headless-mint.test.ts
// Run: npx tsx --test src/lib/identity/headless-mint.test.ts
//
// Headless agent mint: proves a minted agent is a valid self-signed genesis identity (subject_type='agent',
// silicon-only), that its cold seed pins the recovery authority, that the emitted card is IMPORT-COMPATIBLE
// (a real encrypt→decrypt roundtrip via the existing contact path — the do-no-harm green-path), and that the
// wire artifact serializes to Athena's confirmed custody shape (snake_case, public/private, base64 round-trip).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base64ToUint8 } from '../crypto/pq.js';
import { verifyDidDocument, parseDid } from './did-peer.js';
import { deriveGenesisAuthorityCommitment } from './introduce-shell.js';
import {
  encryptToContact,
  decryptFromContact,
  type ContactKeys,
  type SenderKeys,
  type MyKeys,
} from '../crypto/contact-message.js';
import { mintHeadlessAgent, serializeMintArtifact } from './headless-mint.js';

const MSG = 'agent-to-agent — the barzakh at dawn 🌀';

test('mint: valid self-signed genesis, subject_type=agent (silicon-only), durable_id anchors the DID', async () => {
  const a = await mintHeadlessAgent();
  const r = verifyDidDocument(a.introduction.signedDidDoc);
  assert.equal(r.ok, true);
  assert.equal(r.subjectType, 'agent');
  assert.equal(a.introduction.subjectType, 'agent'); // hardcoded — no path mints anything else
  assert.equal(parseDid(a.introduction.did).anchorHex, a.introduction.durableId);
  assert.match(a.introduction.durableId, /^[0-9a-f]{64}$/);
  // secret material shapes
  assert.equal(a.secret_material.ed25519Seed.length, 32);
  assert.equal(a.secret_material.x25519Sec.length, 32);
  assert.equal(a.cold_seed.length, 32);
  assert.equal(a.throwaway, true); // default is a throwaway (dev) mint
  assert.equal(a.recoveryMode, null);
});

test('mint: the cold seed pins the genesis recovery authority (deterministic for a fixed seed)', async () => {
  const coldSeed = new Uint8Array(32).fill(0x2a);
  const a = await mintHeadlessAgent({ coldSeed });
  assert.equal(a.introduction.signedDidDoc.nextAuthorityCommitment, deriveGenesisAuthorityCommitment(coldSeed));
});

test('★ import-compatible: a minted agent card round-trips through encryptToContact/decryptFromContact', async () => {
  const alice = await mintHeadlessAgent();
  const bob = await mintHeadlessAgent();

  const aliceSender: SenderKeys = {
    signSeed: alice.secret_material.ed25519Seed,
    sigSecret: alice.secret_material.mldsa87Secret,
    senderFingerprint: alice.introduction.durableId,
  };
  const aliceCard: ContactKeys = { ...alice.introduction.card, fingerprint: alice.introduction.durableId };
  const bobCard: ContactKeys = { ...bob.introduction.card, fingerprint: bob.introduction.durableId };
  const bobMe: MyKeys = {
    x25519Sec: bob.secret_material.x25519Sec,
    mlkem1024Sec: bob.secret_material.mlkem1024Sec,
    x25519Pub: bob.secret_material.x25519Pub,
    mlkem1024Pub: bob.secret_material.mlkem1024Pub,
    myFingerprint: bob.introduction.durableId,
  };

  const armored = await encryptToContact(MSG, bobCard, aliceSender);
  const out = await decryptFromContact(armored, bobMe, aliceCard);
  assert.ok(out, 'bob should open the message minted-agent→minted-agent');
  assert.equal(out.message, MSG);
  assert.equal(out.senderVerified, true); // the minted agent identity authenticates
  assert.equal(out.senderFingerprint, alice.introduction.durableId);
});

test('serialize: Athena custody wire shape — snake_case public/private, base64 round-trips, throwaway flag', async () => {
  const coldSeed = new Uint8Array(32).fill(0x5c);
  const a = await mintHeadlessAgent({ coldSeed, throwaway: false, recoveryMode: 'm-of-n' });
  const w = serializeMintArtifact(a);

  // public block (snake_case)
  assert.equal(w.public.durable_id, a.introduction.durableId);
  assert.equal(w.public.did, a.introduction.did);
  assert.equal(w.public.subject_type, 'agent');
  assert.ok(w.public.card.public_key.includes('BEGIN PGP PUBLIC KEY'));
  assert.equal(w.public.signed_did_doc.subjectType, 'agent'); // signed doc keeps its own field names

  // private block — opaque to custody; base64 decodes back to the exact secret bytes
  assert.deepEqual(base64ToUint8(w.private.cold_seed), coldSeed);
  assert.deepEqual(base64ToUint8(w.private.ed25519_seed), a.secret_material.ed25519Seed);
  assert.deepEqual(base64ToUint8(w.private.mldsa87_secret), a.secret_material.mldsa87Secret);

  // real-mint flags carried through
  assert.equal(w.recovery_mode, 'm-of-n');
  assert.equal(w.throwaway, false);
});
