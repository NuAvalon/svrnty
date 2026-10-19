// src/lib/identity/introduction.test.ts
// Transitive introduction — build/verify round-trip + the 3 bindings (recipient / subject-card / voucher-sig),
// forged-card rejection, and the structural trust-blind guarantee. Real keys, minted once in before().
// Run: npx tsx --test src/lib/identity/introduction.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { buildIntroduction, verifyIntroduction, type SignedIntroduction } from './introduction';
import {
  signIdentityCard, type SignedIdentityCard,
} from './identity-card-sign';
import type { IdentityCard, IntroductionEnvelope } from '../format/envelope';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from './fingerprint';

interface CanonId { fingerprint: string; publicKey: string; privateKey: string; passphrase: string; kemB64: string; sigB64: string; }
async function makeCanonicalId(name: string): Promise<CanonId> {
  const pass = 'pw-' + name;
  const { privateKey: priv, publicKey: pub } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same keygen as core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }], passphrase: pass, format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: priv });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey,
  });
  return { fingerprint, publicKey: pub, privateKey: priv, passphrase: pass, kemB64: uint8ToBase64(pq.kem.publicKey), sigB64: uint8ToBase64(pq.signing.publicKey) };
}
function canonCard(id: CanonId, display: string): IdentityCard {
  return {
    version: '1.0', type: 'identity-exchange', created_at: '2026-08-17T00:00:00.000Z',
    identity: {
      fingerprint: id.fingerprint, display_name: display, public_key: id.publicKey, email: `${display}@x.test`,
      pq_sig_public_key: id.sigB64, pq_kem_public_key: id.kemB64, next_authority_commitment: '',
    },
  };
}

const TS = '2026-10-16T00:00:00.000Z';
let B: CanonId, A: CanonId, C: CanonId, D: CanonId, Mallory: CanonId;
let aCard: SignedIdentityCard, dCard: SignedIdentityCard;

before(async () => {
  // B = voucher (C holds B's key), A = subject, C = recipient, D = unrelated, Mallory = attacker.
  [B, A, C, D, Mallory] = await Promise.all([
    makeCanonicalId('Bruno'), makeCanonicalId('Alice'), makeCanonicalId('Cara'),
    makeCanonicalId('Dave'), makeCanonicalId('Mallory'),
  ]);
  aCard = await signIdentityCard(canonCard(A, 'Alice'), A.privateKey, A.passphrase);
  dCard = await signIdentityCard(canonCard(D, 'Dave'), D.privateKey, D.passphrase);
});

function introEnv(over: Partial<IntroductionEnvelope> = {}): IntroductionEnvelope {
  return { voucher_fingerprint: B.fingerprint, subject_fingerprint: A.fingerprint, recipient_fingerprint: C.fingerprint, ts: TS, ...over };
}

test('happy path: B introduces A to C → accept, provenance-only, subject imports as KNOWN', async () => {
  const intro = await buildIntroduction(introEnv(), B.privateKey, B.passphrase);
  // launch posture = classical-only signature (PQ-ready via the envelope, but not bound at launch)
  assert.equal(intro.pq_signature, undefined);
  const v = await verifyIntroduction({
    intro, subjectCard: aCard, recipientFingerprint: C.fingerprint, voucherHeldPublicKeyArmored: B.publicKey,
  });
  assert.equal(v.ok, true);
  if (!v.ok) return;
  assert.equal(v.provenance.introduced_by, B.fingerprint);
  assert.equal(v.provenance.subject_fingerprint, A.fingerprint);
  assert.equal(v.provenance.ts, TS);
  assert.equal(v.subjectCard.identity.fingerprint, A.fingerprint);
  assert.equal(v.subjectImport.importClassical, true); // A's card verified end-to-end, carrier-independent
});

test('recipient binding: B\'s intro for C cannot be replayed to introduce A to D', async () => {
  const intro = await buildIntroduction(introEnv(), B.privateKey, B.passphrase);
  const v = await verifyIntroduction({
    intro, subjectCard: aCard, recipientFingerprint: D.fingerprint, voucherHeldPublicKeyArmored: B.publicKey,
  });
  assert.equal(v.ok, false);
  if (v.ok) return;
  assert.equal(v.reason, 'recipient-mismatch');
});

test('subject binding: a card that is not the vouched subject is rejected', async () => {
  const intro = await buildIntroduction(introEnv(), B.privateKey, B.passphrase); // vouches subject = A
  const v = await verifyIntroduction({
    intro, subjectCard: dCard, recipientFingerprint: C.fingerprint, voucherHeldPublicKeyArmored: B.publicKey,
  });
  assert.equal(v.ok, false);
  if (v.ok) return;
  assert.equal(v.reason, 'subject-card-mismatch');
});

test('envelope tamper: mutating a signed field after signing invalidates the voucher signature', async () => {
  const intro = await buildIntroduction(introEnv(), B.privateKey, B.passphrase);
  const tampered: SignedIntroduction = { ...intro, ts: '2099-01-01T00:00:00.000Z' }; // ts is signed, not a binding check
  const v = await verifyIntroduction({
    intro: tampered, subjectCard: aCard, recipientFingerprint: C.fingerprint, voucherHeldPublicKeyArmored: B.publicKey,
  });
  assert.equal(v.ok, false);
  if (v.ok) return;
  assert.equal(v.reason, 'voucher-signature-invalid');
});

test('voucher authenticity: verifying against the wrong held key (Mallory, not B) is rejected', async () => {
  const intro = await buildIntroduction(introEnv(), B.privateKey, B.passphrase);
  const v = await verifyIntroduction({
    intro, subjectCard: aCard, recipientFingerprint: C.fingerprint, voucherHeldPublicKeyArmored: Mallory.publicKey,
  });
  assert.equal(v.ok, false);
  if (v.ok) return;
  assert.equal(v.reason, 'voucher-signature-invalid');
});

test('forged subject card: fp↔key mismatch (swapped key) is rejected at the card gate', async () => {
  const intro = await buildIntroduction(introEnv(), B.privateKey, B.passphrase);
  // keep A's fingerprint (so subject-binding passes) but swap in Mallory's public key → fp no longer binds
  const forged = { ...aCard, identity: { ...aCard.identity, public_key: Mallory.publicKey } } as SignedIdentityCard;
  const v = await verifyIntroduction({
    intro, subjectCard: forged, recipientFingerprint: C.fingerprint, voucherHeldPublicKeyArmored: B.publicKey,
  });
  assert.equal(v.ok, false);
  if (v.ok) return;
  assert.equal(v.reason, 'subject-card-invalid');
});

test('structurally trust-blind: the envelope carries NO trust-grant field, and accept yields provenance only', async () => {
  const intro = await buildIntroduction(introEnv(), B.privateKey, B.passphrase);
  const keys = Object.keys(intro);
  for (const forbidden of ['trust', 'trusted', 'trust_level', 'vouch_strength', 'verified']) {
    assert.equal(keys.includes(forbidden), false, `introduction must not carry a trust-grant field: ${forbidden}`);
  }
  const v = await verifyIntroduction({
    intro, subjectCard: aCard, recipientFingerprint: C.fingerprint, voucherHeldPublicKeyArmored: B.publicKey,
  });
  assert.equal(v.ok, true);
  if (!v.ok) return;
  // The verdict exposes provenance + the normal card import — nothing that asserts trust.
  const vKeys = Object.keys(v);
  for (const forbidden of ['trust', 'trusted', 'trust_level', 'verified']) {
    assert.equal(vKeys.includes(forbidden), false);
  }
  assert.deepEqual(Object.keys(v.provenance).sort(), ['introduced_by', 'subject_fingerprint', 'ts']);
});
