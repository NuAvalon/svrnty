// Introduce (3-party, KNOW-layer) crypto — proves the dual-signature handshake is sound end-to-end and
// fails CLOSED on every attack surface: the survivor-safety crux (no introduction without recipient-scoped
// consent), consent-reuse-to-another-recipient, the know-set gate, recipient-binding, Invariant-1 spoof,
// introducer forgery, tamper, anti-downgrade, wrong-type demux, noise, and domain separation.
// Run: npx tsx --test src/lib/trust/introduction.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey, readPrivateKey, decryptKey } from 'openpgp';
import {
  buildIntroductionConsent,
  signIntroductionConsent,
  buildIntroductionEnvelope,
  buildSignedIntroduction,
  encryptIntroductionTo,
  verifyIntroduction,
  CONSENT_MAX_AGE_MS,
  CONSENT_FUTURE_SKEW_MS,
  IntroductionSignError,
  type BuildIntroductionArgs,
} from './introduction';
import {
  DOMAIN_INTRODUCTION,
  DOMAIN_INTRODUCTION_CONSENT,
  DOMAIN_JOINER_RESPONSE,
  introductionSigningInput,
  introductionConsentSigningInput,
} from '../format/envelope';
import { verifyWithEnvelope, signWithEnvelope } from '../crypto/sign-envelope';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint, fingerprintMatchesKey } from '../identity/fingerprint';
import { sealLivingBookHybrid } from '../crypto/living-book-sleeve';
import { mintHybridRecipient, type HybridRecipient } from '../sync/hybrid-test-fixture';

import { createHash } from 'node:crypto';

const pass = 'test-passphrase-intro';
// Introducer and "other recipient" fingerprints are opaque canonical-form labels (lowercase 64-hex): the verifier now refuses any fingerprint that is not exactly that.
const label = (name: string) => createHash('sha256').update(name).digest('hex');
const NONCE = 'INTRO-7K9QX';

// Introducer (Ivan) — already in the recipient's KNOW set; signs the envelope. Recipient (Rachel) — receives
// + decrypts. Stranger (Sybil) — NOT in Rachel's know set / forges. Carol — a different recipient (scoping).
let ivanPriv: string, ivanPub: string, ivanFp: string;
let rachelPub: string, rachelFp: string;
let sybilPriv: string, sybilPubKey: string;
let carolPriv: string, carolPub: string, carolFp: string;

// A §5 CANONICAL newcomer (64-hex fp): ed25519 + ML-KEM/ML-DSA → fingerprintMatchesKey (canonical-only) passes.
interface CanonicalIdentity {
  fingerprint: string; publicKey: string; privateKey: string; passphrase: string;
  kemPublicKeyB64: string; sigPublicKeyB64: string; sigPublicKey: Uint8Array; sigSecretKey: Uint8Array;
}
async function makeCanonicalIdentity(name: string): Promise<CanonicalIdentity> {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' valid at runtime (same keygen as identity/core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }], passphrase, format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey,
  });
  return {
    fingerprint, publicKey, privateKey, passphrase,
    kemPublicKeyB64: uint8ToBase64(pq.kem.publicKey), sigPublicKeyB64: uint8ToBase64(pq.signing.publicKey),
    sigPublicKey: pq.signing.publicKey, sigSecretKey: pq.signing.secretKey,
  };
}

let newt: CanonicalIdentity; // the newcomer being introduced
// The RECIPIENTS hold real hybrid mailbox secrets (the introduction is sealed ML-KEM-1024 + X25519, no classical leg since #310). Their `*Fp` stays the
// OpenPGP fp the envelopes are addressed to; the recipient-binding check compares THAT to the fingerprint the verifier claims as its own.
let rachelH: HybridRecipient, carolH: HybridRecipient;

before(async () => {
  const mk = async (name: string) => {
    const { privateKey, publicKey } = await generateKey({
      type: 'curve25519', userIDs: [{ name, email: `${name}@example.test` }], passphrase: pass, format: 'armored',
    });
    const fp = (await readKey({ armoredKey: publicKey })).getFingerprint();
    return { privateKey, publicKey, fp };
  };
  ({ privateKey: ivanPriv, publicKey: ivanPub } = await mk('Ivan'));
  ivanFp = label('ivan');
  ({ publicKey: rachelPub } = await mk('Rachel'));
  ({ privateKey: sybilPriv, publicKey: sybilPubKey } = await mk('Sybil'));
  ({ privateKey: carolPriv, publicKey: carolPub } = await mk('Carol'));
  carolFp = label('carol');
  newt = await makeCanonicalIdentity('Newt');
  rachelH = await mintHybridRecipient();
  rachelFp = rachelH.fingerprint; // the recipient's real canonical fingerprint
  carolH = await mintHybridRecipient();
});

const rachel = () => ({ fingerprint: rachelFp, hybrid: rachelH.hybrid });
// The recipient's clock for these tests: every fixture consent is dated 2026-10-19, inside the 7-day window of this clock.
const TEST_NOW = Date.parse('2026-10-20T00:00:00Z');
const verifyAt = (blob: string, recipient: Parameters<typeof verifyIntroduction>[1], lookup: Parameters<typeof verifyIntroduction>[2], opts: Parameters<typeof verifyIntroduction>[3] = {}) =>
  verifyIntroduction(blob, recipient, lookup, { nowMs: TEST_NOW, ...opts });
const toRachel = (signed: Parameters<typeof encryptIntroductionTo>[0]) => encryptIntroductionTo(signed, rachelH.publicKeyArmored, rachelH.pqKemPublicKey);
// Rachel's know-set oracle: Ivan is known (return his held key); anyone else → null (gate rejects).
const knowsIvan = (fp: string) => (fp === ivanFp ? { publicKeyArmored: ivanPub } : null);

// Build Newt's recipient-scoped consent (signed by Newt), then Ivan's honest introduction args.
async function newtConsent(o: { recipientFp?: string; introducerFp?: string; nonce?: string; displayName?: string; classicalConsent?: boolean; ts?: string } = {}) {
  const consent = buildIntroductionConsent({
    introducedFp: newt.fingerprint,
    introducerFp: o.introducerFp ?? ivanFp,
    recipientFp: o.recipientFp ?? rachelFp,
    displayName: o.displayName ?? 'Newt',
    nonce: o.nonce ?? NONCE,
    ts: o.ts ?? '2026-10-19T00:00:00Z',
  });
  const consentSignature = await signIntroductionConsent(consent, newt.privateKey, newt.passphrase, o.classicalConsent ? undefined : newt.sigSecretKey); // a canonical newcomer signs hybrid; the floor refuses classical-only
  return { consent, consentSignature };
}
function ivanArgs(consent: Awaited<ReturnType<typeof newtConsent>>, o: Partial<BuildIntroductionArgs> = {}): BuildIntroductionArgs {
  return {
    introducerFp: ivanFp, recipientFp: rachelFp,
    introducedFp: newt.fingerprint, introducedPubKeyArmored: newt.publicKey,
    introducedPqKemPublicKey: newt.kemPublicKeyB64, introducedPqSigPublicKey: newt.sigPublicKeyB64,
    introducedName: 'Newt', consent: consent.consent, consentSignature: consent.consentSignature,
    context: 'met at the conference', ts: '2026-10-19T00:00:00Z', ...o,
  };
}

// ── Happy path: Ivan introduces Newt to Rachel; Rachel surfaces Newt as KNOWN ─────
test('round-trip: a valid dual-signed introduction verifies → newcomer surfaced KNOWN with introducer provenance', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  const blob = await toRachel(signed);
  const result = await verifyAt(blob, rachel(), knowsIvan);
  assert.ok(result, 'valid introduction must verify');
  assert.equal(result!.fingerprint, newt.fingerprint);
  assert.equal(result!.introducedByFingerprint, ivanFp, 'introducer provenance recorded');
  assert.equal(result!.displayName, 'Newt');
  assert.equal(result!.context, 'met at the conference');
  assert.equal(result!.nonce, NONCE);
  assert.equal(uint8ToBase64(result!.pqKemPublicKey!), newt.kemPublicKeyB64, 'KEM leg round-trips');
});

// ── Hybrid PQ + anti-downgrade ────────────────────────────────────────────────────
test('round-trip (hybrid): Newt consent-signs hybrid + Ivan signs hybrid → verifies under requirePq', async () => {
  const consent = buildIntroductionConsent({
    introducedFp: newt.fingerprint, introducerFp: ivanFp, recipientFp: rachelFp, displayName: 'Newt', nonce: NONCE, ts: '2026-10-19T00:00:00Z',
  });
  const consentSignature = await signIntroductionConsent(consent, newt.privateKey, newt.passphrase, newt.sigSecretKey);
  assert.ok(consentSignature.pq_signature, 'consent must carry a pq half');
  // Ivan is classical here (plain curve25519 key, no ML-DSA) — so requirePq SHOULD still fail unless Ivan is hybrid.
  const signedClassicalIvan = await buildSignedIntroduction(ivanArgs({ consent, consentSignature }), ivanPriv, pass);
  const blobCl = await toRachel(signedClassicalIvan);
  assert.equal(await verifyAt(blobCl, rachel(), knowsIvan, { requirePq: true }), null,
    'requirePq rejects when the INTRODUCER half is classical-only');
  // Without requirePq, the hybrid-consent + classical-introducer introduction still verifies.
  const ok = await verifyAt(blobCl, rachel(), knowsIvan);
  assert.ok(ok, 'hybrid-consent + classical-introducer verifies without requirePq');
  assert.deepEqual(ok!.pqSigningPublicKey, newt.sigPublicKey, 'newcomer pq sig key round-trips');
});

test('anti-downgrade: stripping the pq half of a hybrid introducer signature fails (→ null)', async () => {
  const c = await newtConsent();
  // Make Ivan hybrid by signing the ENVELOPE with a PQ key — reuse Newt's ML-DSA secret purely as a stand-in
  // PQ signer for Ivan (the test only needs a hybrid signature shape to then strip).
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass, newt.sigSecretKey);
  assert.ok(signed.signature.pq_signature);
  delete signed.signature.pq_signature; // suite flips → signed bytes differ → classical half fails
  const blob = await toRachel(signed);
  assert.equal(await verifyAt(blob, rachel(), () => ({ publicKeyArmored: ivanPub, pqSigningPublicKey: newt.sigPublicKey })), null);
});

// ── ★ S1 survivor-safety: no introduction without the newcomer's valid consent ───
test('S1: a forged/absent newcomer consent signature is rejected — cannot introduce without consent (→ null)', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  signed.consent_signature = { classical: 'Zm9yZ2Vk' }; // garbage consent sig
  const blob = await toRachel(signed);
  assert.equal(await verifyAt(blob, rachel(), knowsIvan), null);
});

test('S1: a consent signed by someone OTHER than the newcomer is rejected (→ null)', async () => {
  // Sybil signs a consent token that claims Newt's fingerprint. The signature verifies against Sybil's key,
  // but step 8 verifies against introduced_public_key (Newt's) → mismatch → null. Consent must be the newcomer's.
  const consent = buildIntroductionConsent({
    introducedFp: newt.fingerprint, introducerFp: ivanFp, recipientFp: rachelFp, displayName: 'Newt', nonce: NONCE, ts: '2026-10-19T00:00:00Z',
  });
  const sybilSig = await signIntroductionConsent(consent, sybilPriv, pass);
  const signed = await buildSignedIntroduction(ivanArgs({ consent, consentSignature: sybilSig }), ivanPriv, pass);
  const blob = await toRachel(signed);
  assert.equal(await verifyAt(blob, rachel(), knowsIvan), null);
});

test('★ consent recipient-SCOPING: a consent Newt gave for Carol cannot be reused to introduce Newt to Rachel (→ null)', async () => {
  // Newt consents to be introduced to CAROL. Ivan tries to forward it to RACHEL. buildIntroductionEnvelope
  // refuses at build (consent-mismatch), AND if an attacker hand-crafts the envelope, verify's step-5 drops it.
  const consentForCarol = buildIntroductionConsent({
    introducedFp: newt.fingerprint, introducerFp: ivanFp, recipientFp: carolFp, displayName: 'Newt', nonce: NONCE, ts: '2026-10-19T00:00:00Z',
  });
  const sig = await signIntroductionConsent(consentForCarol, newt.privateKey, newt.passphrase);
  // Hand-craft: claim recipient=Rachel in the envelope but embed the Carol-scoped consent token.
  const forged = {
    envelope: {
      introducer_fingerprint: ivanFp, recipient_fingerprint: rachelFp,
      introduced_fingerprint: newt.fingerprint, introduced_public_key: newt.publicKey,
      introduced_pq_kem_public_key: newt.kemPublicKeyB64, introduced_pq_sig_public_key: newt.sigPublicKeyB64,
      introduced_display_name: 'Newt', consent: consentForCarol, context: 'x', nonce: NONCE, ts: '2026-10-19T00:00:00Z',
    },
    signature: { classical: 'x' }, consent_signature: sig,
  };
  const blob = await sealLivingBookHybrid(new TextEncoder().encode(JSON.stringify(forged)), rachelH.publicKeyArmored, rachelH.pqKemPublicKey);
  assert.equal(await verifyAt(blob, rachel(), knowsIvan), null,
    'a consent scoped to Carol must not authorize an introduction to Rachel');
});

test('★ S1 deadname-bind: a consent signed for "Newt" cannot introduce them as "Deadname" (build-throws + verify→null)', async () => {
  // (a) Build-side: the introducer cannot assemble an envelope whose card name differs from the consented name.
  const c = await newtConsent({ displayName: 'Newt' });
  assert.throws(
    () => buildIntroductionEnvelope(ivanArgs(c, { introducedName: 'Deadname' })),
    (e: unknown) => e instanceof IntroductionSignError && e.reason === 'consent-mismatch',
  );
  // (b) Verify-side (hand-crafted past the build guard): rename the card AFTER signing — consent says "Newt",
  // card says "Deadname" → dropped at the step-5 display_name cross-check (deadname/survivor-safety).
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  signed.envelope.introduced_display_name = 'Deadname';
  const blob = await toRachel(signed);
  assert.equal(await verifyAt(blob, rachel(), knowsIvan), null,
    'renaming the card away from the consented name must drop');
});

// ── Know-set gate (Fork 1 pending dismissal) ──────────────────────────────────────
test('know-set gate: an introduction from someone NOT in the recipient know-set is dropped (→ null)', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  const blob = await toRachel(signed);
  assert.equal(await verifyAt(blob, rachel(), () => null), null, 'introducer not in know-set → dismissed');
});

test('know-set gate: a throwing lookup oracle fails closed (→ null)', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  const blob = await toRachel(signed);
  assert.equal(await verifyAt(blob, rachel(), () => { throw new Error('store down'); }), null);
});

// ── Recipient-binding: an introduction for another recipient is rejected ──────────
test('recipient-binding: an introduction addressed to Carol is rejected by Rachel even if she can decrypt (→ null)', async () => {
  const c = await newtConsent({ recipientFp: carolFp });
  const signed = await buildSignedIntroduction(ivanArgs(c, { recipientFp: carolFp }), ivanPriv, pass);
  const blobToRachel = await toRachel(signed); // encrypt to Rachel so she CAN open it
  assert.equal(await verifyAt(blobToRachel, rachel(), knowsIvan), null, 'recipient_fp=Carol ≠ Rachel');
});

// ── Introducer forgery + tamper ───────────────────────────────────────────────────
test('introducer forgery: Sybil signs the envelope but claims to be Ivan → fails vs the held Ivan key (→ null)', async () => {
  const c = await newtConsent();
  // Sybil signs the (introducer=Ivan) envelope with HER key. Rachel verifies against the HELD Ivan key → fails.
  const signed = await buildSignedIntroduction(ivanArgs(c), sybilPriv, pass);
  const blob = await toRachel(signed);
  assert.equal(await verifyAt(blob, rachel(), knowsIvan), null);
});

test('tamper: mutating the context after signing fails the introducer signature (→ null)', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  signed.envelope.context = 'tampered';
  const blob = await toRachel(signed);
  assert.equal(await verifyAt(blob, rachel(), knowsIvan), null);
});

test('tamper: swapping the newcomer public key (keep fp) fails (Invariant-1 or signature) (→ null)', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  signed.envelope.introduced_public_key = carolPub; // fp no longer hashes to the key
  const blob = await toRachel(signed);
  assert.equal(await verifyAt(blob, rachel(), knowsIvan), null);
});

// ── Invariant-1 spoof ─────────────────────────────────────────────────────────────
test('Invariant-1: a newcomer fingerprint that does not hash to its public key is refused (→ null)', async () => {
  // Hand-craft past the build-time consent guard: claim carolFp as the newcomer but present NEWT's key, with a
  // SELF-CONSISTENT consent (also naming carolFp) so step-5 cross-binding PASSES → we genuinely reach step-6
  // Invariant-1, which must drop it because carolFp ≠ H(newt.publicKey). (Consent sig is irrelevant — step 6
  // runs before step 8.)
  const consent = buildIntroductionConsent({
    introducedFp: carolFp, introducerFp: ivanFp, recipientFp: rachelFp, displayName: 'x', nonce: NONCE, ts: '2026-10-19T00:00:00Z',
  });
  const sig = await signIntroductionConsent(consent, carolPriv, pass);
  const forged = {
    envelope: {
      introducer_fingerprint: ivanFp, recipient_fingerprint: rachelFp,
      introduced_fingerprint: carolFp, introduced_public_key: newt.publicKey,
      introduced_display_name: 'x', consent, context: 'x', nonce: NONCE, ts: '2026-10-19T00:00:00Z',
    },
    signature: { classical: 'x' }, consent_signature: sig,
  };
  const blob = await sealLivingBookHybrid(new TextEncoder().encode(JSON.stringify(forged)), rachelH.publicKeyArmored, rachelH.pqKemPublicKey);
  assert.equal(await verifyAt(blob, rachel(), knowsIvan), null);
});

// ── Confidentiality, demux, noise ──────────────────────────────────────────────────
test('confidentiality: a blob encrypted to Rachel cannot be opened by Carol (→ null)', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  const blobToRachel = await toRachel(signed);
  const carol = { fingerprint: carolFp, hybrid: carolH.hybrid };
  assert.equal(await verifyAt(blobToRachel, carol, knowsIvan), null);
});

test('demux: a joiner-response-shaped blob is dropped by verifyIntroduction (→ null)', async () => {
  const notAnIntro = { envelope: { joiner_fingerprint: 'x', joiner_epoch: 1, joiner_public_key: 'k', joiner_display_name: 'n', giver_fingerprint: 'g', invite_nonce: 'c', ts: 't' }, signature: { classical: 'x' } };
  const blob = await sealLivingBookHybrid(new TextEncoder().encode(JSON.stringify(notAnIntro)), rachelH.publicKeyArmored, rachelH.pqKemPublicKey);
  assert.equal(await verifyAt(blob, rachel(), knowsIvan), null);
});

test('noise: a non-PGP blob decrypts-fails and drops (→ null)', async () => {
  assert.equal(await verifyAt('not-an-armored-message', rachel(), knowsIvan), null);
});

// ── Domain separation ───────────────────────────────────────────────────────────────
test('domain separation: the introducer signature verifies under DOMAIN_INTRODUCTION but NOT under CONSENT/JOINER', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  const input = introductionSigningInput(signed.envelope);
  assert.equal(await verifyWithEnvelope(DOMAIN_INTRODUCTION, input, signed.signature, ivanPub), true);
  assert.equal(await verifyWithEnvelope(DOMAIN_INTRODUCTION_CONSENT, input, signed.signature, ivanPub), false);
  assert.equal(await verifyWithEnvelope(DOMAIN_JOINER_RESPONSE, input, signed.signature, ivanPub), false);
});

// ── Fail-loud at BUILD (introducer controls its own inputs) ──────────────────────────
test('build: forwarding a consent whose recipient ≠ the envelope recipient is refused (consent-mismatch)', async () => {
  const consentForCarol = buildIntroductionConsent({
    introducedFp: newt.fingerprint, introducerFp: ivanFp, recipientFp: carolFp, displayName: 'Newt', nonce: NONCE, ts: '2026-10-19T00:00:00Z',
  });
  const sig = await signIntroductionConsent(consentForCarol, newt.privateKey, newt.passphrase);
  assert.throws(
    () => buildIntroductionEnvelope(ivanArgs({ consent: consentForCarol, consentSignature: sig }, { recipientFp: rachelFp })),
    (e: unknown) => e instanceof IntroductionSignError && e.reason === 'consent-mismatch',
  );
});

test('build: empty introducer fingerprint refused (bad-introducer-fingerprint)', async () => {
  const c = await newtConsent();
  assert.throws(() => buildIntroductionEnvelope(ivanArgs(c, { introducerFp: '' })),
    (e: unknown) => e instanceof IntroductionSignError && e.reason === 'bad-introducer-fingerprint');
});

test('build: optional pq keys OMITTED (not null) when absent — canonical stays null-free', async () => {
  const c = await newtConsent();
  const env = buildIntroductionEnvelope(ivanArgs(c, { introducedPqKemPublicKey: undefined, introducedPqSigPublicKey: undefined }));
  assert.equal('introduced_pq_kem_public_key' in env, false);
  assert.equal('introduced_pq_sig_public_key' in env, false);
});

// ── Hybrid-only (no classical leg, #310 posture) ──────────────────────────────────────────────────────────
test('no-downgrade (send): sealing an introduction WITHOUT the recipient ML-KEM key THROWS; it never produces a classical blob', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  await assert.rejects(encryptIntroductionTo(signed, rachelH.publicKeyArmored), /refusing to seal without the recipient ML-KEM key/);
  await assert.rejects(encryptIntroductionTo(signed, rachelH.publicKeyArmored, ''), /no classical downgrade/);
});

test('no-downgrade (receive): a CLASSICAL OpenPGP blob of a perfectly valid introduction is dropped, and a recipient with no hybrid secrets opens nothing', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  const { createMessage, encrypt, readKey } = await import('openpgp');
  const classical = (await encrypt({ message: await createMessage({ text: JSON.stringify(signed) }), encryptionKeys: await readKey({ armoredKey: rachelPub }) })) as string;
  assert.equal(await verifyAt(classical, rachel(), knowsIvan), null, 'classical blob: no fallback leg');
  const hybridBlob = await toRachel(signed);
  assert.ok(await verifyAt(hybridBlob, rachel(), knowsIvan), 'control: the same introduction sealed hybrid verifies');
  assert.equal(await verifyAt(hybridBlob, { fingerprint: rachelFp }, knowsIvan), null, 'no hybrid secrets => nothing opens');
});

test('open-leg counter: a successful open reports the hybrid leg once; a counter that throws never changes the result', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  const blob = await toRachel(signed);
  const legs: string[] = [];
  assert.ok(await verifyAt(blob, { ...rachel(), onOpenLeg: (l) => legs.push(l) }, knowsIvan));
  assert.deepEqual(legs, ['hybrid']);
  assert.ok(await verifyAt(blob, { ...rachel(), onOpenLeg: () => { throw new Error('counter fault'); } }, knowsIvan));
});

test('a hybrid blob sealed to SOMEONE ELSE (Carol) does not open for Rachel', async () => {
  const c = await newtConsent();
  const signed = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  const toCarol = await encryptIntroductionTo(signed, carolH.publicKeyArmored, carolH.pqKemPublicKey);
  assert.equal(await verifyAt(toCarol, rachel(), knowsIvan), null);
});

test('recipient-binding: an introduction FULLY valid for Carol (consent and envelope both name Carol), sealed to Rachel, is dropped by Rachel', async () => {
  const forCarol = await newtConsent({ recipientFp: carolFp });
  const signed = await buildSignedIntroduction(ivanArgs(forCarol, { recipientFp: carolFp }), ivanPriv, pass);
  const blob = await toRachel(signed); // Rachel CAN open it, so only the binding to HER fingerprint can stop it
  assert.equal(await verifyAt(blob, rachel(), knowsIvan), null, 'addressed to Carol, not Rachel');
  assert.ok(await verifyAt(blob, { fingerprint: carolFp, hybrid: rachelH.hybrid }, knowsIvan), 'control: with the claimed fingerprint = Carol, the same blob verifies (so nothing else was rejecting it)');
});

// ── Hostile INTRODUCER cases: the introducer RE-SIGNS the hostile envelope, so both signatures verify and ONLY the cross-checks stop it ──
const resignAsIvan = async (envelope: ReturnType<typeof buildIntroductionEnvelope>, consentSignature: Awaited<ReturnType<typeof newtConsent>>['consentSignature']) => ({
  envelope,
  signature: await signWithEnvelope(DOMAIN_INTRODUCTION, introductionSigningInput(envelope), ivanPriv, pass),
  consent_signature: consentSignature,
});

test('★ S1 deadname (real attack): the INTRODUCER signs an envelope naming "Deadname" while carrying Newt\'s GENUINE consent for "Newt"; both signatures verify, and the display_name cross-check alone drops it', async () => {
  const c = await newtConsent({ displayName: 'Newt' });
  const env = buildIntroductionEnvelope(ivanArgs(c)); // honest build: name = Newt
  env.introduced_display_name = 'Deadname'; // hostile edit BEFORE the introducer signs
  const signed = await resignAsIvan(env, c.consentSignature);
  assert.ok(await verifyWithEnvelope(DOMAIN_INTRODUCTION, introductionSigningInput(signed.envelope), signed.signature, ivanPub), 'precondition: the introducer\'s signature over the hostile envelope IS valid');
  assert.ok(await verifyWithEnvelope(DOMAIN_INTRODUCTION_CONSENT, introductionConsentSigningInput(c.consent), c.consentSignature, newt.publicKey, newt.sigPublicKey), 'precondition: Newt\'s consent signature IS valid');
  assert.equal(await verifyAt(await toRachel(signed), rachel(), knowsIvan), null, 'only the name cross-check stops it');
});

test('★ Invariant-1 (real attack): the INTRODUCER signs introduced_fingerprint = a VICTIM\'s fp with the ATTACKER\'s key and a consent the attacker signs with that key; both signatures verify, and the fp-hashes-to-key check alone drops it', async () => {
  const consent = buildIntroductionConsent({ introducedFp: carolFp, introducerFp: ivanFp, recipientFp: rachelFp, displayName: 'Carol', nonce: NONCE, ts: '2026-10-19T00:00:00Z' });
  const consentSignature = await signIntroductionConsent(consent, sybilPriv, pass); // the attacker signs "Carol's" consent with ITS key
  const env = buildIntroductionEnvelope({
    introducerFp: ivanFp, recipientFp: rachelFp, introducedFp: carolFp, introducedPubKeyArmored: sybilPubKey,
    introducedName: 'Carol', consent, consentSignature, context: 'x', ts: '2026-10-19T00:00:00Z',
  });
  const signed = await resignAsIvan(env, consentSignature);
  assert.ok(await verifyWithEnvelope(DOMAIN_INTRODUCTION, introductionSigningInput(env), signed.signature, ivanPub), 'precondition: the introducer\'s signature IS valid');
  assert.ok(await verifyWithEnvelope(DOMAIN_INTRODUCTION_CONSENT, introductionConsentSigningInput(consent), consentSignature, sybilPubKey), 'precondition: the consent verifies under the presented (attacker) key');
  assert.equal(await verifyAt(await toRachel(signed), rachel(), knowsIvan), null, 'only Invariant-1 stops binding Carol\'s fp to the attacker\'s key');
});

// ── Suite floor: PQ signatures are REQUIRED whenever the key material says they exist ───────────────────────────────
test('suite floor (consent): a CANONICAL newcomer (PQ keys on the card) whose consent signature is classical-only is dropped; the same consent signed hybrid verifies', async () => {
  const classical = await newtConsent({ classicalConsent: true });
  const downgraded = await buildSignedIntroduction(ivanArgs(classical), ivanPriv, pass);
  assert.equal(await verifyAt(await toRachel(downgraded), rachel(), knowsIvan), null, 'a holder of only the classical key could mint this');
  const hybrid = await newtConsent();
  const ok = await buildSignedIntroduction(ivanArgs(hybrid), ivanPriv, pass);
  assert.ok(await verifyAt(await toRachel(ok), rachel(), knowsIvan), 'control');
});

test('suite floor (introducer): if the HELD introducer key has a PQ signing key, a classical-only introducer signature is dropped; the hybrid-signed one verifies', async () => {
  const ivanPq = generatePQKeypairBundle();
  const knowsIvanPq = (fp: string) => (fp === ivanFp ? { publicKeyArmored: ivanPub, pqSigningPublicKey: ivanPq.signing.publicKey } : null);
  const c = await newtConsent();
  const classicalOnly = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass);
  assert.equal(await verifyAt(await toRachel(classicalOnly), rachel(), knowsIvanPq), null, 'classical-only vs a held PQ key');
  const hybrid = await buildSignedIntroduction(ivanArgs(c), ivanPriv, pass, ivanPq.signing.secretKey);
  assert.ok(await verifyAt(await toRachel(hybrid), rachel(), knowsIvanPq), 'control: hybrid-signed');
  assert.ok(await verifyAt(await toRachel(classicalOnly), rachel(), knowsIvan), 'control: the same classical-only signature is fine when NO PQ key is held');
});

// ── Each guard on its own: single-fault cases ────────────────────────────────────────────────────────────────────────────────────────────
// verifyIntroduction rejects on several overlapping checks, so a hostile blob that breaks TWO of them proves nothing about either. Each case below
// builds an honest envelope, changes exactly ONE thing after the build (the builder itself refuses most of these), re-signs as the introducer so the
// introducer's signature is valid, and keeps the newcomer's consent signature GENUINE over the token the envelope actually carries. Every case has a
// control that proves nothing else was rejecting it.
async function honestFor(consent: Awaited<ReturnType<typeof newtConsent>>) {
  return buildIntroductionEnvelope(ivanArgs(consent));
}
const verifies = async (signed: Awaited<ReturnType<typeof resignAsIvan>>) => verifyAt(await toRachel(signed), rachel(), knowsIvan);

test('control for the single-fault cases: the unmodified, re-signed envelope verifies', async () => {
  const c = await newtConsent();
  assert.ok(await verifies(await resignAsIvan(await honestFor(c), c.consentSignature)));
});

test('guard: the ENVELOPE is addressed to someone else while the consent names Rachel: dropped (the envelope\'s own recipient binding)', async () => {
  const c = await newtConsent();
  const env = await honestFor(c);
  env.recipient_fingerprint = carolFp; // only this changes; the consent still names Rachel
  assert.equal(await verifies(await resignAsIvan(env, c.consentSignature)), null);
});

test('guard: the CONSENT names someone else as recipient (genuinely signed by the newcomer for that recipient), the envelope names Rachel: dropped', async () => {
  const c = await newtConsent();
  const forOther = await newtConsent({ recipientFp: carolFp });
  const env = await honestFor(c);
  env.consent = forOther.consent;
  assert.ok(await verifyWithEnvelope(DOMAIN_INTRODUCTION_CONSENT, introductionConsentSigningInput(forOther.consent), forOther.consentSignature, newt.publicKey, newt.sigPublicKey), 'precondition: the consent signature is valid over the token it carries');
  assert.equal(await verifies(await resignAsIvan(env, forOther.consentSignature)), null);
});

test('guard: the CONSENT names a different introduced fingerprint (genuinely signed), the envelope introduces Newt: dropped', async () => {
  const c = await newtConsent();
  const other = { consent: buildIntroductionConsent({ introducedFp: carolFp, introducerFp: ivanFp, recipientFp: rachelFp, displayName: 'Newt', nonce: NONCE, ts: '2026-10-19T00:00:00Z' }) };
  const consentSignature = await signIntroductionConsent(other.consent, newt.privateKey, newt.passphrase, newt.sigSecretKey);
  const env = await honestFor(c);
  env.consent = other.consent;
  assert.ok(await verifyWithEnvelope(DOMAIN_INTRODUCTION_CONSENT, introductionConsentSigningInput(other.consent), consentSignature, newt.publicKey, newt.sigPublicKey), 'precondition: valid over the token it carries');
  assert.equal(await verifies(await resignAsIvan(env, consentSignature)), null);
});

test('guard: the CONSENT names a different introducer (genuinely signed), the envelope is signed by Ivan: dropped', async () => {
  const c = await newtConsent();
  const forOtherIntroducer = await newtConsent({ introducerFp: carolFp });
  const env = await honestFor(c);
  env.consent = forOtherIntroducer.consent;
  assert.equal(await verifies(await resignAsIvan(env, forOtherIntroducer.consentSignature)), null);
});

test('guard: the CONSENT carries a different nonce (genuinely signed) than the envelope: dropped', async () => {
  const c = await newtConsent();
  const otherNonce = await newtConsent({ nonce: 'a-different-nonce-0123456789abcdef' });
  const env = await honestFor(c);
  env.consent = otherNonce.consent;
  assert.equal(await verifies(await resignAsIvan(env, otherNonce.consentSignature)), null);
});

test('guard: a FORGED consent signature (classical half from another key, PQ half genuine) is dropped by the verifier itself, not only by the builder', async () => {
  const c = await newtConsent();
  const sybilHalf = await signIntroductionConsent(c.consent, sybilPriv, pass);
  const forged = { ...c.consentSignature, classical: sybilHalf.classical };
  assert.ok(forged.pq_signature, 'precondition: it still carries the PQ half, so the suite floor does not stop it');
  assert.equal(await verifies(await resignAsIvan(await honestFor(c), forged)), null, 'only the consent-signature check stops it');
});

test('guard: a FORGED consent signature (PQ half altered, classical genuine) is dropped', async () => {
  const c = await newtConsent();
  const pq = c.consentSignature.pq_signature as string;
  const altered = { ...c.consentSignature, pq_signature: (pq[0] === 'A' ? 'B' : 'A') + pq.slice(1) };
  assert.equal(await verifies(await resignAsIvan(await honestFor(c), altered)), null);
});

// The legacy OpenPGP 40-hex identity basis is gone (fingerprintMatchesKey is canonical-only: a SHA-1 basis allowed mint-time equivocation), so a
// classical newcomer can never pass Invariant-1, whatever else is valid. This pins that refusal on the introduction path. One consequence worth
// knowing: the verifier's "a PQ half on the consent with no PQ key to check it against" guard sits BEHIND that gate and is unreachable, so it has no test.
test('a classical newcomer (40-hex OpenPGP fingerprint, no PQ keys on the card) is refused even when both signatures are valid: canonical identities only', async () => {
  const consent = buildIntroductionConsent({ introducedFp: carolFp, introducerFp: ivanFp, recipientFp: rachelFp, displayName: 'Carol', nonce: NONCE, ts: '2026-10-19T00:00:00Z' });
  const consentSignature = await signIntroductionConsent(consent, carolPriv, pass);
  const env = buildIntroductionEnvelope({ introducerFp: ivanFp, recipientFp: rachelFp, introducedFp: carolFp, introducedPubKeyArmored: carolPub, introducedName: 'Carol', consent, consentSignature, context: 'x', ts: '2026-10-19T00:00:00Z' });
  const signed = await resignAsIvan(env, consentSignature);
  assert.ok(await verifyWithEnvelope(DOMAIN_INTRODUCTION, introductionSigningInput(env), signed.signature, ivanPub), 'precondition: the introducer\'s signature is valid');
  assert.ok(await verifyWithEnvelope(DOMAIN_INTRODUCTION_CONSENT, introductionConsentSigningInput(consent), consentSignature, carolPub), 'precondition: the consent signature is valid');
  assert.equal(await verifies(signed), null);
});


// ── A fingerprint names an identity EXACTLY ──────────────────────────────────────────────────────────────────────────────────────────────
// fingerprintMatchesKey is a PREFIX matcher over a normalised string (16-64 hex, lower-cased, non-hex stripped): right for "does the short fingerprint I
// typed match", wrong for BINDING an identity. verifyIntroduction used to accept the newcomer under a prefix, an upper-case form and a colon-separated form
// and return it as spelled, so one person could be stored under several spellings. Each spelling below is signed consistently by the real newcomer (consent)
// and a known introducer, so ONLY the exact-equality check stops it, and each has the control that the canonical form verifies.
async function newcomerAs(spelling: string) {
  const consent = buildIntroductionConsent({ introducedFp: spelling, introducerFp: ivanFp, recipientFp: rachelFp, displayName: 'Newt', nonce: NONCE, ts: '2026-10-19T00:00:00Z' });
  const consentSignature = await signIntroductionConsent(consent, newt.privateKey, newt.passphrase, newt.sigSecretKey);
  const env = buildIntroductionEnvelope(ivanArgs({ consent, consentSignature }, { introducedFp: spelling }));
  return verifyAt(await toRachel(await resignAsIvan(env, consentSignature)), rachel(), knowsIvan);
}
test('exact fingerprint: the canonical form verifies and the result carries exactly the recomputed 64-hex value (control)', async () => {
  const r = await newcomerAs(newt.fingerprint);
  assert.ok(r);
  assert.equal(r!.fingerprint, newt.fingerprint);
  assert.match(r!.fingerprint, /^[0-9a-f]{64}$/);
});
const spellings: Array<[string, (f: string) => string]> = [
  ['a 16-hex PREFIX', (f) => f.slice(0, 16)],
  ['a 40-hex prefix', (f) => f.slice(0, 40)],
  ['UPPER case', (f) => f.toUpperCase()],
  ['colon-separated', (f) => f.match(/.{2}/g)!.join(':')],
  ['space-separated groups', (f) => f.match(/.{8}/g)!.join(' ')],
  ['one non-hex character', (f) => f.slice(0, 63) + 'z'],
  ['a trailing space', (f) => f + ' '],
  ['a 0x prefix', (f) => '0x' + f],
];
for (const [name, spell] of spellings) {
  test(`exact fingerprint: the newcomer named as ${name} is refused, though the old prefix check accepts it for the readable ones`, async () => {
    const spelling = spell(newt.fingerprint);
    assert.notEqual(spelling, newt.fingerprint);
    assert.equal(await newcomerAs(spelling), null);
  });
}
test('precondition for the spelling cases: fingerprintMatchesKey (a prefix matcher) accepts the prefix, upper-case and colon spellings, so only the exact-equality check can refuse them', async () => {
  const pq = { kem_public_key: newt.kemPublicKeyB64, sig_public_key: newt.sigPublicKeyB64 };
  for (const [name, spell] of spellings.slice(0, 4)) assert.equal(await fingerprintMatchesKey(spell(newt.fingerprint), newt.publicKey, pq), true, name);
});

// The introducer's and the recipient's fingerprints must already be canonical too. Each case keeps every comparison exact and consistent (consent and
// envelope name the same spelling, the lookup accepts it), so ONLY the canonical-form check can refuse it.
const lenientIvan = (fp: string) => (fp.toLowerCase() === ivanFp ? { publicKeyArmored: ivanPub } : null);
async function introducerAs(spelling: string) {
  const c = await newtConsent({ introducerFp: spelling });
  const signed = await resignAsIvan(buildIntroductionEnvelope(ivanArgs(c, { introducerFp: spelling })), c.consentSignature);
  return verifyAt(await toRachel(signed), rachel(), lenientIvan);
}
test('exact fingerprint: an introducer named in upper case is refused even when the know-set lookup would accept it; lower case verifies (control)', async () => {
  assert.ok(await introducerAs(ivanFp), 'control');
  assert.equal(await introducerAs(ivanFp.toUpperCase()), null);
  assert.equal(await introducerAs(ivanFp.slice(0, 32)), null);
});
async function recipientAs(spelling: string) {
  const c = await newtConsent({ recipientFp: spelling });
  const signed = await resignAsIvan(buildIntroductionEnvelope(ivanArgs(c, { recipientFp: spelling })), c.consentSignature);
  return verifyAt(await toRachel(signed), { fingerprint: spelling, hybrid: rachelH.hybrid }, knowsIvan);
}
test('exact fingerprint: a recipient named in upper case (envelope, consent AND the verifier\'s own claim all agree) is refused; lower case verifies (control)', async () => {
  assert.ok(await recipientAs(rachelFp), 'control');
  assert.equal(await recipientAs(rachelFp.toUpperCase()), null);
  assert.equal(await recipientAs(rachelFp.slice(0, 32)), null);
});

// ── The newcomer's consent is good for 7 days ───────────────────────────────────────────────────────────────────────────────────────────
// The consent's time is signed by the NEWCOMER, so it is the one that counts; the introducer's envelope time is not. A consent signed once must not let
// an introducer re-present it forever (the newcomer cannot withdraw), so it expires; one dated in the future beyond a small skew is refused too.
const RN = Date.parse('2026-11-01T12:00:00.000Z'); // the recipient's clock in these cases
const iso = (ms: number) => new Date(ms).toISOString();
async function consentDated(ts: string, envelopeTs?: string, clock: number | null = RN) { // null = pass no clock at all (a default parameter would swallow undefined)
  const c = await newtConsent({ ts });
  const signed = await resignAsIvan(buildIntroductionEnvelope(ivanArgs(c, envelopeTs ? { ts: envelopeTs } : {})), c.consentSignature);
  return verifyIntroduction(await toRachel(signed), rachel(), knowsIvan, clock === null ? {} : { nowMs: clock });
}
test('replay window: a consent signed an hour ago verifies (control)', async () => {
  assert.ok(await consentDated(iso(RN - 3_600_000)));
});
test('replay window: exactly 7 days old verifies, one millisecond older is refused', async () => {
  assert.ok(await consentDated(iso(RN - CONSENT_MAX_AGE_MS)));
  assert.equal(await consentDated(iso(RN - CONSENT_MAX_AGE_MS - 1)), null);
});
test('replay window: exactly 5 minutes ahead of the recipient\'s clock verifies, one millisecond more is refused', async () => {
  assert.ok(await consentDated(iso(RN + CONSENT_FUTURE_SKEW_MS)));
  assert.equal(await consentDated(iso(RN + CONSENT_FUTURE_SKEW_MS + 1)), null);
});
test('replay window: an unreadable or empty consent time is refused (fail-closed)', async () => {
  assert.equal(await consentDated('not-a-time'), null);
  assert.equal(await consentDated(''), null);
});
test('replay window: the consent time is read ONLY as strict ISO-8601 UTC (what toISOString writes); every other form is refused, never interpreted', async () => {
  const noOffset = (ms: number) => iso(ms).replace(/\.\d{3}Z$/, ''); // '2026-11-01T11:00:00': an hour before the clock IF read as UTC
  const was = process.env.TZ;
  try {
    for (const tz of ['UTC', 'America/New_York', 'Asia/Kolkata']) {
      process.env.TZ = tz;
      assert.equal(await consentDated(noOffset(RN - 3_600_000)), null, `no offset, ${tz}`);
    }
  } finally {
    if (was === undefined) delete process.env.TZ; else process.env.TZ = was;
  }
  assert.equal(await consentDated('2026-11-01'), null, 'a bare date');
  assert.equal(await consentDated('Nov 1 2026 11:00:00'), null, 'an engine-specific form Date.parse would read');
  assert.equal(await consentDated(iso(RN - 3_600_000).replace('Z', '+00:00')), null, 'an offset form, even +00:00');
  assert.equal(await consentDated('2026-11-01T06:00:00-05:00'), null, 'a non-UTC offset');
  assert.equal(await consentDated(iso(RN - 3_600_000).replace('.000Z', '.0001Z')), null, 'four fractional digits');
  assert.equal(await consentDated(iso(RN - 3_600_000).toLowerCase()), null, 'lower-case t and z');
  assert.equal(await consentDated(iso(RN - 3_600_000) + ' '), null, 'trailing space');
  assert.equal(await consentDated('2026-11-01T11:00Z'), null, 'no seconds: V8 reads this as a valid time, the strict pattern does not');
  assert.equal(await consentDated(' ' + iso(RN - 3_600_000)), null, 'a leading space');
  // the forms the honest builder writes still verify
  assert.ok(await consentDated(iso(RN - 3_600_000)), 'toISOString output (three digits)');
  assert.ok(await consentDated('2026-11-01T11:00:00Z'), 'no fractional digits');
  assert.ok(await consentDated('2026-11-01T11:00:00.5Z'), 'one fractional digit');
});
test('replay window: the NEWCOMER\'s time decides: a stale envelope time with a fresh consent verifies, a fresh envelope time with a stale consent is refused', async () => {
  assert.ok(await consentDated(iso(RN - 60_000), '2025-01-01T00:00:00Z'), 'old introducer time, fresh consent');
  assert.equal(await consentDated(iso(RN - 8 * 24 * 3_600_000), iso(RN)), null, 'fresh introducer time, 8-day-old consent');
});
test('replay window: with no clock given the real clock is used (a consent from an hour ago verifies, one from 30 days ago does not)', async () => {
  assert.ok(await consentDated(iso(Date.now() - 3_600_000), undefined, null));
  assert.equal(await consentDated(iso(Date.now() - 30 * 24 * 3_600_000), undefined, null), null);
});
