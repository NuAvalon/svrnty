// Mint-build recipe v2 — next_authority_commitment + rotation verifier.
// Run: npx tsx --test src/lib/identity/next-authority.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { randomBytes } from '@noble/hashes/utils.js';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { seedPhraseToMasterSecret } from '../crypto/recovery';
import {
  DOMAIN_ROTATION,
  DOMAIN_IDENTITY_CARD,
  DOMAIN_CONTACT_UPDATE,
  DOMAIN_KEY_ROTATION,
} from '../format/envelope';
import {
  deriveNextAuthorityCommitment,
  deriveNextAuthorityKeypair,
  encodeAuthorityPubkeys,
  authorityCommitmentFromReveal,
  signRotationAuthority,
  mintCanonicalFingerprint,
} from './fingerprint';
import { signIdentityCard, verifySignedIdentityCard, buildSignedIdentityCard, classifyImportedCard } from './identity-card-sign';
import { recordToKnownContact } from '../sync/live-book-poll';
import type { ContactRecord } from './client-store';
import type { IdentityCard } from '../format/envelope';
import { rotationSigningInput } from '../format/envelope';
import {
  verifyRotationSuccessor,
  ContactUpdateRejected,
  type KnownContactIdentity,
  type RotationSuccessorInput,
} from '../trust/contact-update';
import { SoverentityIdentity } from './core';

function hex64(n = 0xa): string {
  return n.toString(16).repeat(64).slice(0, 64);
}

async function makeOperational(name: string) {
  const pass = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase: pass,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked,
    kemPublicKey: pq.kem.publicKey,
    sigPublicKey: pq.signing.publicKey,
  });
  return {
    fingerprint,
    publicKey,
    privateKey,
    passphrase: pass,
    kemB64: uint8ToBase64(pq.kem.publicKey),
    sigB64: uint8ToBase64(pq.signing.publicKey),
  };
}

function canonCard(id: Awaited<ReturnType<typeof makeOperational>>, over: Partial<IdentityCard['identity']> = {}): IdentityCard {
  return {
    version: '1.1',
    type: 'identity-exchange',
    created_at: '2026-09-07T00:00:00.000Z',
    identity: {
      fingerprint: id.fingerprint,
      display_name: id.fingerprint.slice(0, 8),
      public_key: id.publicKey,
      email: 'a@x.test',
      pq_sig_public_key: id.sigB64,
      pq_kem_public_key: id.kemB64,
      next_authority_commitment: '',
      ...over,
    },
  };
}

test('domain tag svrnty:rotation:v1 is dedicated (does not collide with card / contact-update / key-rotation)', () => {
  assert.equal(DOMAIN_ROTATION, 'svrnty:rotation:v1');
  assert.notEqual(DOMAIN_ROTATION, DOMAIN_IDENTITY_CARD);
  assert.notEqual(DOMAIN_ROTATION, DOMAIN_CONTACT_UPDATE);
  assert.notEqual(DOMAIN_ROTATION, DOMAIN_KEY_ROTATION);
});

test('commitment determinism: same masterSecret+epoch re-derives the same 64-hex pin', () => {
  const masterSecret = randomBytes(32);
  const a = deriveNextAuthorityCommitment(masterSecret, 1);
  const b = deriveNextAuthorityCommitment(masterSecret, 1);
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(a, deriveNextAuthorityCommitment(masterSecret, 2));
  assert.notEqual(a, deriveNextAuthorityCommitment(randomBytes(32), 1));
});

test('reveal-match encoding parity: decode-then-hash of hex pubs === derive-then-hash', () => {
  const masterSecret = randomBytes(32);
  const commitment = deriveNextAuthorityCommitment(masterSecret, 1);
  const kp = deriveNextAuthorityKeypair(masterSecret, 1);
  assert.equal(kp.edPublic.length, 32);
  assert.equal(kp.dsaPublic.length, 2592);
  const revealed = encodeAuthorityPubkeys(kp.edPublic, kp.dsaPublic);
  assert.equal(authorityCommitmentFromReveal(revealed.sign, revealed.pq_sig), commitment);
});

test('grown-card guard: genesis wrapper identity puts a 64-hex pin on card.identity (version 1.1)', async () => {
  const id = await makeOperational('grown');
  const masterSecret = randomBytes(32);
  const pin = deriveNextAuthorityCommitment(masterSecret, 1);
  const wrapper = {
    identity: { fingerprint: id.fingerprint, public_key: id.publicKey, display_name: 'Grown', email: 'g@x.test' },
    post_quantum: { sig_public_key: id.sigB64, kem_public_key: id.kemB64 },
    next_authority_commitment: pin,
    durable: { fingerprint: id.fingerprint, epoch: 0, next_authority_commitment: pin },
  };
  const signed = await buildSignedIdentityCard(wrapper, id.privateKey, id.passphrase);
  assert.equal(signed.version, '1.1');
  assert.equal(signed.identity.next_authority_commitment, pin);
  assert.match(signed.identity.next_authority_commitment, /^[0-9a-f]{64}$/);
  assert.equal(await verifySignedIdentityCard(signed), true);
});

test('signed-input: tampering next_authority_commitment breaks the card signature', async () => {
  const id = await makeOperational('tamper');
  const pin = hex64(0xb);
  const signed = await signIdentityCard(canonCard(id, { next_authority_commitment: pin }), id.privateKey, id.passphrase);
  assert.equal(await verifySignedIdentityCard(signed), true);
  const tampered = {
    ...signed,
    identity: { ...signed.identity, next_authority_commitment: hex64(0xc) },
  };
  assert.equal(await verifySignedIdentityCard(tampered), false);
});

async function validRotation(opts?: { kind?: string; flipSig?: boolean; wrongAuth?: boolean }) {
  const masterSecret = randomBytes(32);
  const pin = deriveNextAuthorityCommitment(masterSecret, 1);
  const authKp = deriveNextAuthorityKeypair(masterSecret, 1);
  const genesis = await makeOperational('ep0');
  const nextOp = await makeOperational('ep1');
  const nextPin = deriveNextAuthorityCommitment(masterSecret, 2);
  const revealed = opts?.wrongAuth
    ? encodeAuthorityPubkeys(randomBytes(32), randomBytes(2592))
    : encodeAuthorityPubkeys(authKp.edPublic, authKp.dsaPublic);
  const fields = {
    durable_id: genesis.fingerprint,
    prior_epoch: 0,
    prior_authority_commitment: pin,
    successor_epoch: 1,
    new_fingerprint: nextOp.fingerprint,
    next_authority_commitment: nextPin,
  };
  const canonical = rotationSigningInput(fields);
  let sig = signRotationAuthority(canonical, authKp.edSecret, authKp.dsaSecret);
  if (opts?.flipSig) sig = (sig.startsWith('ff') ? '00' : 'ff') + sig.slice(2);

  const successor: RotationSuccessorInput = {
    durable_id: genesis.fingerprint,
    prior_epoch: 0,
    successor_epoch: 1,
    new_fingerprint: nextOp.fingerprint,
    new_public_key: nextOp.publicKey,
    new_pq_kem_public_key: nextOp.kemB64,
    new_pq_sig_public_key: nextOp.sigB64,
    next_authority_commitment: nextPin,
    auth: opts?.kind && opts.kind !== 'rotation'
      ? { kind: opts.kind }
      : { kind: 'rotation', auth_pubkeys: revealed, sig_by_authority: sig },
  };
  const known: KnownContactIdentity = {
    fingerprint: genesis.fingerprint,
    epoch: 0,
    version: 0,
    classicalPublicKeyArmored: genesis.publicKey,
    next_authority_commitment: pin,
  };
  return { successor, known, nextOp, nextPin, pin, genesis };
}

test('rotation round-trip: mint pin → reveal K_auth → verifier ACCEPTS and advances epoch', async () => {
  const { successor, known, nextOp, nextPin } = await validRotation();
  const adopted = await verifyRotationSuccessor(successor, known);
  assert.equal(adopted.epoch, 1);
  assert.equal(adopted.fingerprint, nextOp.fingerprint);
  assert.equal(adopted.next_authority_commitment, nextPin);
  assert.equal(adopted.classicalPublicKeyArmored, nextOp.publicKey);
});

// #535 pin-at-import — the AC-8 POSITIVE integration: the pin must survive the IMPORT wiring
// (classifyImportedCard → ContactRecord → recordToKnownContact) and still verify a legit rotation.
// Proves green≠working (Archie #131560): without the projection the SAME legit successor fail-closes.
test('#535 AC-8: pin flows classify→record→project → verifier ACCEPTS a legit rotation; empty-pin REJECTS', async () => {
  const { successor, pin, genesis, nextPin } = await validRotation();
  // (1) genesis mints the pin onto its signed card → the importer's classifyImportedCard extracts it (4b).
  const card = await signIdentityCard(canonCard(genesis, { next_authority_commitment: pin }), genesis.privateKey, genesis.passphrase);
  const d = await classifyImportedCard(card);
  assert.equal(d.branch, '4b');
  assert.equal(d.next_authority_commitment, pin);
  // (2) stored on the ContactRecord, projected into the verify seam.
  const rec = {
    id: 'peer', fingerprint: genesis.fingerprint, name: 'peer', email: '',
    public_key: genesis.publicKey, trust_level: 'known', added_at: '2026-09-07T00:00:00.000Z',
    epoch: 0, version: 0, next_authority_commitment: d.next_authority_commitment,
  } as ContactRecord;
  const known = recordToKnownContact(rec);
  assert.equal(known.next_authority_commitment, pin);
  // (3) a legit successor for that contact VERIFIES against the imported + pinned commitment.
  const adopted = await verifyRotationSuccessor(successor, known);
  assert.equal(adopted.epoch, 1);
  assert.equal(adopted.next_authority_commitment, nextPin);
  // (4) load-bearing: had the pin NOT been projected ('' / legacy), the SAME successor fail-closes (AC-4).
  const unpinned = recordToKnownContact({ ...rec, next_authority_commitment: '' } as ContactRecord);
  await assert.rejects(() => verifyRotationSuccessor(successor, unpinned), ContactUpdateRejected);
});

test('rotation negative: wrong K_auth (H mismatch) → REJECT', async () => {
  const { successor, known } = await validRotation({ wrongAuth: true });
  await assert.rejects(
    () => verifyRotationSuccessor(successor, known),
    (e: unknown) => e instanceof ContactUpdateRejected && e.reason === 'rotation-commitment-mismatch',
  );
});

test('rotation negative: bad authority sig → REJECT', async () => {
  const { successor, known } = await validRotation({ flipSig: true });
  await assert.rejects(
    () => verifyRotationSuccessor(successor, known),
    (e: unknown) => e instanceof ContactUpdateRejected && e.reason === 'rotation-bad-authority-sig',
  );
});

test('rotation negative: unknown kind FAIL-CLOSES', async () => {
  const { successor, known } = await validRotation({ kind: 'revocation' });
  await assert.rejects(
    () => verifyRotationSuccessor(successor, known),
    (e: unknown) => e instanceof ContactUpdateRejected && e.reason === 'rotation-unknown-kind',
  );
});

test('genesis path (core.ts): pin is minted before fill(0) and re-derives from the recovery code', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'svrnty-mint-'));
  try {
    const id = new SoverentityIdentity({ storageDir: dir });
    const { identity, seedPhrase } = await id.generateIdentity(
      { name: 'Mint', email: 'mint@x.test' },
      { shamirThreshold: 2, shamirShares: 3 },
    );
    const pin = identity.next_authority_commitment;
    assert.ok(pin);
    assert.match(pin, /^[0-9a-f]{64}$/);
    assert.equal(identity.durable?.epoch, 0);
    assert.equal(identity.durable?.next_authority_commitment, pin);
    assert.equal(identity.durable?.fingerprint, identity.identity.fingerprint);
    const masterSecret = seedPhraseToMasterSecret(seedPhrase);
    assert.equal(deriveNextAuthorityCommitment(masterSecret, 1), pin);
    masterSecret.fill(0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
