// src/lib/crypto/mailbox-envelope.test.ts
// Conformance + functional gate for the PQ-hybrid mailbox envelope (Flint's Track A contract §5/§6).
// Run: npx tsx --test src/lib/crypto/mailbox-envelope.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { encapsulate, decapsulate, generateKEMKeypair, base64ToUint8 } from './pq.js';
import {
  MAILBOX_ENV_ALG,
  deriveMailboxFp,
  deriveEnvelopeKey,
  sealWithMaterials,
  sealToMailbox,
  openMailboxEnvelope,
  type MailboxPublicKeys,
  type MailboxSecretKeys,
} from './mailbox-envelope.js';

const fill = (byte: number, len: number): Uint8Array => new Uint8Array(len).fill(byte);
const enc = new TextEncoder();

// ── Contract §5 — deterministic conformance vector ──────────────────────────────────────────────
// Inputs are constant-byte fills; expected outputs are Flint's (Python cryptography = @noble byte-for-byte).
const V = {
  mailbox_x25519_sk_seed: fill(0x11, 32),
  eph_x25519_sk_seed: fill(0x22, 32),
  ss_pq: fill(0x33, 32),
  kem_ct: fill(0x44, 1568),
  mlkem1024_pub_stub: fill(0x55, 1568),
  nonce: hexToBytes('0a0b0c0d0e0f101112131415'),
  plaintext: enc.encode('svrnty trust-edge beacon: hello mailbox'),
  expect: {
    mailbox_x25519_pub: '7b4e909bbe7ffe44c465a220037d608ee35897d31ef972f07f74892cb0f73f13',
    epk: '0faa684ed28867b97f4a6a2dee5df8ce974e76b7018e3f22a1c4cf2678570f20',
    ss_c: '9e004098efc091d4ec2663b4e9f5cfd4d7064571690b4bea97ab146ab9f35056',
    mailbox_fp: '01ac93431c1d34a8994511844a3c7513e5a1b041acf3b460819e5e6521c7406a',
    K_hkdf: 'bd2eae44566faf50c6bad465ef57ebc2f5852bde35c5cc14d0993d733484ea45',
    ct_tag_b64: 'fZDykL6/L/hejoE1vJG+Nz4ZmZfF4lfK3HDLN+I59TehtdxXGdRfe1Yo3yjzzLPqBi/UOvaBWw==',
  },
};

test('§5 vector: X25519 pub derivation (mailbox + ephemeral)', () => {
  assert.equal(bytesToHex(x25519.getPublicKey(V.mailbox_x25519_sk_seed)), V.expect.mailbox_x25519_pub);
  assert.equal(bytesToHex(x25519.getPublicKey(V.eph_x25519_sk_seed)), V.expect.epk);
});

test('§5 vector: ss_c raw ECDH', () => {
  const mailboxPub = hexToBytes(V.expect.mailbox_x25519_pub);
  const ssC = x25519.getSharedSecret(V.eph_x25519_sk_seed, mailboxPub);
  assert.equal(bytesToHex(ssC), V.expect.ss_c);
});

test('§5 vector: mailbox_fp = SHA256(x_pub || kem_pub)', () => {
  const mfp = deriveMailboxFp(hexToBytes(V.expect.mailbox_x25519_pub), V.mlkem1024_pub_stub);
  assert.equal(mfp, V.expect.mailbox_fp);
});

test('§5 vector: K = HKDF combiner (byte-exact)', () => {
  const K = deriveEnvelopeKey(
    hexToBytes(V.expect.ss_c),
    V.ss_pq,
    hexToBytes(V.expect.epk),
    V.kem_ct,
    V.expect.mailbox_fp,
  );
  assert.equal(bytesToHex(K), V.expect.K_hkdf);
});

test('§5 vector: full SEAL core → ct||tag byte-exact', async () => {
  const pkg = await sealWithMaterials(
    V.plaintext,
    hexToBytes(V.expect.ss_c),
    V.ss_pq,
    hexToBytes(V.expect.epk),
    V.kem_ct,
    V.expect.mailbox_fp,
    V.nonce,
  );
  assert.equal(pkg.ct, V.expect.ct_tag_b64);
  assert.equal(pkg.alg, MAILBOX_ENV_ALG);
  assert.equal(pkg.mailbox_fp, V.expect.mailbox_fp);
  assert.equal(base64ToUint8(pkg.ct).length, 55); // 39B plaintext + 16B tag
});

// ── Contract §6 — functional gate (real ML-KEM encap/decap) ──────────────────────────────────────
function freshMailbox(): { pub: MailboxPublicKeys; sec: MailboxSecretKeys; fp: string } {
  const xSk = x25519.utils.randomSecretKey();
  const xPub = x25519.getPublicKey(xSk);
  const kem = generateKEMKeypair();
  const fp = deriveMailboxFp(xPub, kem.publicKey);
  return {
    pub: { x25519Pub: xPub, mlkem1024Pub: kem.publicKey },
    sec: { x25519Sec: xSk, mlkem1024Sec: kem.secretKey },
    fp,
  };
}

test('§6 KEM round-trip: SEAL → OPEN returns the plaintext', async () => {
  const mb = freshMailbox();
  const msg = enc.encode('trust-edge beacon :: mutual? yes');
  const pkg = await sealToMailbox(msg, mb.pub, mb.fp);
  const opened = await openMailboxEnvelope(pkg, mb.sec, mb.fp);
  assert.ok(opened, 'open must succeed');
  assert.equal(new TextDecoder().decode(opened!), 'trust-edge beacon :: mutual? yes');
  // raw ML-KEM self-check: decapsulate(encapsulate) round-trips the shared secret
  const { ciphertext, sharedSecret } = encapsulate(mb.pub.mlkem1024Pub);
  assert.deepEqual(decapsulate(ciphertext, mb.sec.mlkem1024Sec), sharedSecret);
});

test('§6 reject-classical / wrong-PQ-key: kem_ct re-encapsulated to a DIFFERENT key → null', async () => {
  const alice = freshMailbox();
  const mallory = freshMailbox();
  const pkg = await sealToMailbox(enc.encode('secret'), alice.pub, alice.fp);
  // Swap in a kem_ct encapsulated to Mallory's KEM key (a downgraded/forged PQ leg). ss_pq Alice decaps
  // will differ → wrong K → tag fail. No classical fallback exists.
  const { ciphertext: malloryCt } = encapsulate(mallory.pub.mlkem1024Pub);
  const forged = { ...pkg, kem_ct: Buffer.from(malloryCt).toString('base64') };
  const opened = await openMailboxEnvelope(forged, alice.sec, alice.fp);
  assert.equal(opened, null);
});

test('§6 anti-swap: flipping any bound field → null', async () => {
  const mb = freshMailbox();
  const pkg = await sealToMailbox(enc.encode('payload'), mb.pub, mb.fp);
  const flipB64 = (b64: string): string => {
    const b = base64ToUint8(b64);
    b[0] ^= 0x01;
    return Buffer.from(b).toString('base64');
  };
  for (const field of ['epk', 'kem_ct', 'nonce', 'ct'] as const) {
    const tampered = { ...pkg, [field]: flipB64(pkg[field]) };
    assert.equal(await openMailboxEnvelope(tampered, mb.sec, mb.fp), null, `flip ${field} must reject`);
  }
});

test('§6 wrong-recipient mailbox_fp → reject before crypto', async () => {
  const alice = freshMailbox();
  const bob = freshMailbox();
  const pkg = await sealToMailbox(enc.encode('for alice'), alice.pub, alice.fp);
  // Bob tries to open Alice's envelope with his own fp as "mine" → mailbox_fp mismatch → null.
  assert.equal(await openMailboxEnvelope(pkg, bob.sec, bob.fp), null);
  // And tampering the package's own mailbox_fp to Bob's also rejects (AAD/step-1 bind).
  assert.equal(await openMailboxEnvelope({ ...pkg, mailbox_fp: bob.fp }, bob.sec, bob.fp), null);
});

test('§6 no plaintext at rest: package carries only the opaque fields', async () => {
  const mb = freshMailbox();
  const pkg = await sealToMailbox(enc.encode('no-leak'), mb.pub, mb.fp);
  assert.deepEqual(Object.keys(pkg).sort(), ['alg', 'ct', 'epk', 'kem_ct', 'mailbox_fp', 'nonce', 'v']);
  assert.ok(!JSON.stringify(pkg).includes('no-leak'));
});
