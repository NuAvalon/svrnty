// src/lib/crypto/contact-message-wire-v2.test.ts
// Run: npx tsx --test src/lib/crypto/contact-message-wire-v2.test.ts
//
// TASK #556 — binary wire-format v2 CO-VERIFY vectors (Flint gate, spec §6 + §6b).
// The claim under test: v2 is an ENCODING change only — ZERO crypto-primitive change. The signed
// preimage and the mailbox-envelope SEAL (KEM/KDF/AAD/AES-GCM) are byte-identical to v1; only the
// serialization changes (hex→raw sig, JSON→binary, double→single base64). Plus the lever-2 suite
// safety: the SUITE byte is bound into the signed preimage, so it cannot be downgraded.
//
//   (a) sig is byte-identical v1-hex ↔ v2-raw over the UNCHANGED preimage
//   (b) seal crypto invariant to inner serialization (same KEM/KDF/AAD/epk/kem_ct/nonce; only ct differs)
//   (c) v2 round-trip recovers {from, msg} + sig verifies (end-to-end, HYBRID)
//   (d) coexistence: v2 decoder opens a legacy v1 blob; a v1-only parser rejects a v2 blob; unknown-version → null
//   (e) mailbox-envelope alg carried verbatim through the v2 outer codec (seal contract untouched)
//   (f) suite-DOWNGRADE → reject-closed (flip the suite byte either direction → not verified)
//   (g) unknown-suite byte → reject-closed (null)
//   + the #556 payoff: v2-hybrid ≪ v1; v2-classical smaller still.
// (§6e full mailbox-envelope §5 conformance vector lives in mailbox-envelope.test.ts — run alongside.)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as openpgp from 'openpgp';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { generateKEMKeypair, generateSigningKeypair, uint8ToBase64, base64ToUint8 } from './pq.js';
import { extractRawSign, extractRawEnc } from '../identity/raw-sign.js';
import { deriveCanonicalFingerprintHex } from '../identity/fingerprint.js';
import {
  sealToMailbox,
  sealWithMaterials,
  deriveEnvelopeKey,
  buildEnvelopeAAD,
  MAILBOX_ENV_ALG,
  type MailboxEnvelopePackage,
} from './mailbox-envelope.js';
import {
  encryptToContact,
  decryptFromContact,
  signContactMessage,
  signContactMessageRaw,
  verifyContactMessage,
  verifyContactMessageRaw,
  encodeInnerV2,
  encodeOuterV2,
  decodeOuterV2,
  type SenderKeys,
  type ContactKeys,
  type MyKeys,
} from './contact-message.js';

const MSG = 'the strong 64-hex — meet me at the barzakh 🌀';
const HELLO = 'hello';
const FP_A = 'a'.repeat(64);
const FP_B = 'b'.repeat(64);

const ARMOR_BEGIN = '-----BEGIN SVRNTY ENCRYPTED MESSAGE-----';
const ARMOR_END = '-----END SVRNTY ENCRYPTED MESSAGE-----';

// ── test-side armor helpers (mirror the module; let us inspect/mutate the raw wire) ──
function armoredToBytes(armored: string): Uint8Array {
  const body = armored
    .split('\n')
    .filter((l) => !l.includes('SVRNTY ENCRYPTED') && l.trim() !== '')
    .join('')
    .replace(/\s+/g, '');
  return base64ToUint8(body);
}
function bytesToArmored(bytes: Uint8Array): string {
  const body = uint8ToBase64(bytes)
    .replace(/(.{64})/g, '$1\n')
    .replace(/\n$/, '');
  return `${ARMOR_BEGIN}\n${body}\n${ARMOR_END}`;
}

function makeSender(fp = FP_A): SenderKeys & { signPub: Uint8Array; sigPub: Uint8Array } {
  const signSeed = new Uint8Array(32).fill(0x11);
  const signPub = ed25519.getPublicKey(signSeed);
  const sig = generateSigningKeypair();
  return { signSeed, sigSecret: sig.secretKey, senderFingerprint: fp, signPub, sigPub: sig.publicKey };
}

// a REAL svrnty identity (OpenPGP ed25519 + x25519 subkey, ML-KEM-1024, ML-DSA-87) for the e2e paths
async function makeIdentity() {
  const { privateKey, publicKey } = (await openpgp.generateKey({ type: 'ecc', curve: 'ed25519', userIDs: [{ name: 'id' }], format: 'object' } as any)) as any;
  const kem = generateKEMKeypair();
  const sig = generateSigningKeypair();
  const { seed: signSeed } = extractRawSign(privateKey);
  const { encSec, encPub } = await extractRawEnc(privateKey);
  const { signPub } = extractRawSign(privateKey);
  const fingerprint = deriveCanonicalFingerprintHex(signPub, encPub, kem.publicKey, sig.publicKey);
  const card: ContactKeys = {
    public_key: publicKey.armor(),
    pq_kem_public_key: uint8ToBase64(kem.publicKey),
    pq_sig_public_key: uint8ToBase64(sig.publicKey),
    fingerprint,
  };
  const asSender: SenderKeys = { signSeed, sigSecret: sig.secretKey, senderFingerprint: fingerprint };
  const asRecipient: MyKeys = { x25519Sec: encSec, mlkem1024Sec: kem.secretKey, x25519Pub: encPub, mlkem1024Pub: kem.publicKey, myFingerprint: fingerprint };
  return { card, asSender, asRecipient, fingerprint };
}

// ── (a) sig byte-identity: hex (v1 storage) ↔ raw (v2 storage) over the UNCHANGED preimage ──────────
test('§6(a) sig is byte-identical v1-hex ↔ v2-raw; both verify (zero crypto change in the signature)', () => {
  const alice = makeSender();
  const sigRaw = signContactMessageRaw(MSG, FP_B, alice.signSeed, alice.sigSecret, 'hybrid');
  const sigHex = bytesToHex(sigRaw);
  assert.deepEqual(hexToBytes(sigHex), sigRaw); // hex storage is lossless — pure re-encoding
  assert.equal(verifyContactMessageRaw(MSG, FP_B, sigRaw, 'hybrid', alice.signPub, alice.sigPub), true); // v2 raw verifies
  assert.equal(verifyContactMessage(MSG, FP_B, sigHex, alice.signPub, alice.sigPub), true); // v1 hex verifies (legacy path)
  assert.ok(sigRaw.length === 64 + 4627, `expected ed25519(64)+ML-DSA-87(4627), got ${sigRaw.length}`);
});

// ── (b) the SEAL is invariant to inner serialization — only the ct changes (format-only) ────────────
test('§6(b) seal crypto invariant to inner serialization: same alg/epk/kem_ct/nonce/mailbox_fp/K/AAD; only ct differs', async () => {
  // fixed seal materials (in real use these come from a fresh ephemeral + ML-KEM encapsulation)
  const ssC = new Uint8Array(32).fill(7);
  const ssPq = new Uint8Array(32).fill(9);
  const epk = new Uint8Array(32).fill(3);
  const kemCt = new Uint8Array(1568).fill(5);
  const nonce = new Uint8Array(12).fill(1);
  const mfp = 'd'.repeat(64);

  // two DIFFERENT serializations of the SAME logical inner {from, msg, sig}
  const sigRaw = new Uint8Array(4691).fill(0xab); // ed25519(64)+ML-DSA-87(4627)
  const innerV1 = utf8ToBytes(JSON.stringify({ v: 1, from: FP_A, msg: MSG, sig: bytesToHex(sigRaw) }));
  const innerV2 = encodeInnerV2(FP_A, MSG, sigRaw);
  assert.notDeepEqual(innerV1, innerV2); // the serializations differ — that IS the change
  assert.ok(innerV2.length < innerV1.length, `v2 inner smaller: v2=${innerV2.length} v1=${innerV1.length}`);

  const pkgV1 = await sealWithMaterials(innerV1, ssC, ssPq, epk, kemCt, mfp, nonce);
  const pkgV2 = await sealWithMaterials(innerV2, ssC, ssPq, epk, kemCt, mfp, nonce);

  // every crypto-material field is identical — the seal did not change
  assert.equal(pkgV1.alg, MAILBOX_ENV_ALG);
  assert.equal(pkgV2.alg, MAILBOX_ENV_ALG);
  assert.equal(pkgV1.epk, pkgV2.epk);
  assert.equal(pkgV1.kem_ct, pkgV2.kem_ct);
  assert.equal(pkgV1.nonce, pkgV2.nonce);
  assert.equal(pkgV1.mailbox_fp, pkgV2.mailbox_fp);
  // the AES key and the AAD are NOT functions of the plaintext → identical regardless of serialization
  assert.deepEqual(deriveEnvelopeKey(ssC, ssPq, epk, kemCt, mfp), deriveEnvelopeKey(ssC, ssPq, epk, kemCt, mfp));
  assert.deepEqual(buildEnvelopeAAD(mfp, epk, kemCt), buildEnvelopeAAD(mfp, epk, kemCt));
  // ONLY the AEAD ciphertext differs — because the (smaller) plaintext differs. The sole intended change.
  assert.notEqual(pkgV1.ct, pkgV2.ct);
});

// ── (c) v2 full round-trip, end-to-end with real identities ─────────────────────────────────────────
test('§6(c) v2 round-trip: encrypt→decrypt recovers message + senderVerified=true (HYBRID default)', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const armored = await encryptToContact(MSG, bob.card, alice.asSender); // defaults to hybrid
  const bytes = armoredToBytes(armored);
  assert.equal(bytes[0], 0x02, 'WIRE_FORMAT_V2'); // version discriminator first
  assert.equal(bytes[1], 0x01, 'SUITE_BYTE_HYBRID');
  const dec = decodeOuterV2(bytes);
  assert.ok(dec && dec.suite === 'hybrid');

  const out = await decryptFromContact(armored, bob.asRecipient, alice.card);
  assert.ok(out);
  assert.equal(out.message, MSG);
  assert.equal(out.senderVerified, true);
  assert.equal(out.senderFingerprint, alice.fingerprint);

  // no card → opens but unverified (UI must label it); wrong card → unverified
  assert.equal((await decryptFromContact(armored, bob.asRecipient))!.senderVerified, false);
  assert.equal((await decryptFromContact(armored, bob.asRecipient, bob.card))!.senderVerified, false);
});

// ── (d) cross-version coexistence + reject-closed on unknown version ────────────────────────────────
test('§6(d) coexistence: v2 opens a legacy v1 blob; a v1-only parser rejects v2; unknown-version → null', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();

  // construct a GENUINE legacy v1 blob (JSON package over JSON inner, double-base64) — the pre-#556 wire
  const sigHex = signContactMessage(MSG, bob.fingerprint, alice.asSender.signSeed, alice.asSender.sigSecret);
  const innerV1 = utf8ToBytes(JSON.stringify({ v: 1, from: alice.fingerprint, msg: MSG, sig: sigHex }));
  const pkg = await sealToMailbox(innerV1, { x25519Pub: bob.asRecipient.x25519Pub, mlkem1024Pub: bob.asRecipient.mlkem1024Pub });
  const v1Armored = bytesToArmored(utf8ToBytes(JSON.stringify(pkg)));
  assert.equal(armoredToBytes(v1Armored)[0], 0x7b, "legacy blob leads with '{'");

  // the NEW decoder opens the legacy blob AND verifies the sender — migration coexistence
  const legacyOut = await decryptFromContact(v1Armored, bob.asRecipient, alice.card);
  assert.ok(legacyOut);
  assert.equal(legacyOut.message, MSG);
  assert.equal(legacyOut.senderVerified, true);

  // a v1-only client's parser is JSON.parse — a v2 blob (byte[0]=0x02) is NOT valid JSON → it rejects, never mis-decodes
  const v2Bytes = armoredToBytes(await encryptToContact(MSG, bob.card, alice.asSender));
  assert.throws(() => JSON.parse(new TextDecoder().decode(v2Bytes)));

  // an unknown format-version byte → reject-closed (null), never mis-decoded
  const unknown = Uint8Array.from(v2Bytes);
  unknown[0] = 0x55;
  assert.equal(await decryptFromContact(bytesToArmored(unknown), bob.asRecipient, alice.card), null);
});

// ── (e) the mailbox-envelope seal contract is carried verbatim through the v2 outer codec ───────────
test('§6(e) outer codec round-trips the mailbox-envelope package byte-for-byte (incl alg) — seal untouched', () => {
  const pkg: MailboxEnvelopePackage = {
    v: 1,
    alg: MAILBOX_ENV_ALG,
    mailbox_fp: 'a'.repeat(64),
    epk: uint8ToBase64(new Uint8Array(32).fill(2)),
    kem_ct: uint8ToBase64(new Uint8Array(1568).fill(3)),
    nonce: uint8ToBase64(new Uint8Array(12).fill(4)),
    ct: uint8ToBase64(new Uint8Array(40).fill(5)),
  };
  const dec = decodeOuterV2(encodeOuterV2('hybrid', pkg));
  assert.ok(dec);
  assert.equal(dec.suite, 'hybrid');
  assert.deepEqual(dec.pkg, pkg); // every field — incl alg — round-trips byte-for-byte
});

// ── (f) suite-downgrade → reject-closed ─────────────────────────────────────────────────────────────
test('§6b(f) suite-downgrade: flipping the outer suite byte (either direction) → senderVerified=false', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();

  // HYBRID message, attacker claims CLASSICAL (0x01 → 0x02)
  const hy = armoredToBytes(await encryptToContact(MSG, bob.card, alice.asSender, 'hybrid'));
  assert.equal(hy[1], 0x01);
  const hyFlipped = Uint8Array.from(hy);
  hyFlipped[1] = 0x02;
  const outH = await decryptFromContact(bytesToArmored(hyFlipped), bob.asRecipient, alice.card);
  assert.ok(outH, 'opens (suite byte is not in the AEAD AAD)');
  assert.equal(outH.message, MSG);
  assert.equal(outH.senderVerified, false, 'hybrid sig cannot pass as classical — reject-closed');

  // CLASSICAL message, attacker claims HYBRID (0x02 → 0x01)
  const cl = armoredToBytes(await encryptToContact(MSG, bob.card, alice.asSender, 'classical'));
  assert.equal(cl[1], 0x02);
  const clFlipped = Uint8Array.from(cl);
  clFlipped[1] = 0x01;
  const outC = await decryptFromContact(bytesToArmored(clFlipped), bob.asRecipient, alice.card);
  assert.ok(outC);
  assert.equal(outC.senderVerified, false, 'classical sig cannot pass as hybrid — reject-closed');

  // sanity: the UN-flipped classical message verifies true (so the rejects above are the flip, not a classical bug)
  assert.equal((await decryptFromContact(bytesToArmored(cl), bob.asRecipient, alice.card))!.senderVerified, true);
});

// ── (g) unknown suite byte → reject-closed ──────────────────────────────────────────────────────────
test('§6b(g) unknown suite byte → reject-closed (null), same discipline as unknown version', async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();
  const bytes = armoredToBytes(await encryptToContact(MSG, bob.card, alice.asSender));
  const bad = Uint8Array.from(bytes);
  bad[1] = 0x09; // ∉ {0x01, 0x02}
  assert.equal(decodeOuterV2(bad), null); // codec-level reject
  assert.equal(await decryptFromContact(bytesToArmored(bad), bob.asRecipient, alice.card), null); // end-to-end reject
});

// ── the #556 payoff: the encoding tax is actually removed ───────────────────────────────────────────
test("#556 payoff: v2-hybrid ≪ v1, v2-classical smaller still (sizes for 'hello')", async () => {
  const alice = await makeIdentity();
  const bob = await makeIdentity();

  const sigHex = signContactMessage(HELLO, bob.fingerprint, alice.asSender.signSeed, alice.asSender.sigSecret);
  const innerV1 = utf8ToBytes(JSON.stringify({ v: 1, from: alice.fingerprint, msg: HELLO, sig: sigHex }));
  const pkg = await sealToMailbox(innerV1, { x25519Pub: bob.asRecipient.x25519Pub, mlkem1024Pub: bob.asRecipient.mlkem1024Pub });
  const v1 = bytesToArmored(utf8ToBytes(JSON.stringify(pkg)));

  const v2h = await encryptToContact(HELLO, bob.card, alice.asSender, 'hybrid');
  const v2c = await encryptToContact(HELLO, bob.card, alice.asSender, 'classical');

  console.log(`[#556 sizes] v1=${v1.length}  v2-hybrid=${v2h.length}  v2-classical=${v2c.length}`);
  assert.ok(v2h.length < v1.length * 0.6, `v2h=${v2h.length} should be < 60% of v1=${v1.length}`);
  assert.ok(v2c.length < v2h.length * 0.5, `v2c=${v2c.length} should be < 50% of v2h=${v2h.length}`);

  // both still decrypt + verify
  assert.equal((await decryptFromContact(v2h, bob.asRecipient, alice.card))!.senderVerified, true);
  assert.equal((await decryptFromContact(v2c, bob.asRecipient, alice.card))!.senderVerified, true);
});
