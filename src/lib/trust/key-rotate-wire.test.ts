// src/lib/trust/key-rotate-wire.test.ts — task #809: the key.rotate codec and its gate.
// Run: npx tsx --test src/lib/trust/key-rotate-wire.test.ts
// Real keys (OpenPGP + ML-KEM-1024 + ML-DSA-87), the real rotation verifier, the real hybrid seal. No network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import {
  deriveNextAuthorityCommitment,
  deriveNextAuthorityKeypair,
  encodeAuthorityPubkeys,
  signRotationAuthority,
  mintCanonicalFingerprint,
} from '../identity/fingerprint';
import { rotationSigningInput } from '../format/envelope';
import { sealLivingBookHybrid } from '../crypto/living-book-sleeve';
import { mintHybridRecipient } from '../sync/hybrid-test-fixture';
import { LpParseError } from '../crypto/lp-reader';
import {
  verifyRotationSuccessor,
  type RotationSuccessorInput,
  type KnownContactIdentity,
} from './contact-update';
import {
  encodeKeyRotate,
  parseKeyRotate,
  UnverifiedKeyRotate,
  KeyRotateRefused,
  KEY_ROTATE_ARMORED_MAX,
} from './key-rotate-wire';

// ---------- fixtures: a REAL successor, built the way the existing rotation tests build one ----------
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
  return { fingerprint, publicKey, kemB64: uint8ToBase64(pq.kem.publicKey), sigB64: uint8ToBase64(pq.signing.publicKey) };
}

async function realRotation() {
  const master = randomBytes(32);
  const pin = deriveNextAuthorityCommitment(master, 1);
  const authKp = deriveNextAuthorityKeypair(master, 1);
  const genesis = await makeOperational('g0');
  const nextOp = await makeOperational('g1');
  const nextPin = deriveNextAuthorityCommitment(master, 2);
  const fields = {
    durable_id: genesis.fingerprint,
    prior_epoch: 0,
    prior_authority_commitment: pin,
    successor_epoch: 1,
    new_fingerprint: nextOp.fingerprint,
    next_authority_commitment: nextPin,
  };
  const sig = signRotationAuthority(rotationSigningInput(fields), authKp.edSecret, authKp.dsaSecret);
  const successor: RotationSuccessorInput = {
    durable_id: genesis.fingerprint,
    prior_epoch: 0,
    successor_epoch: 1,
    new_fingerprint: nextOp.fingerprint,
    new_public_key: nextOp.publicKey,
    new_pq_kem_public_key: nextOp.kemB64,
    new_pq_sig_public_key: nextOp.sigB64,
    next_authority_commitment: nextPin,
    auth: { kind: 'rotation', auth_pubkeys: encodeAuthorityPubkeys(authKp.edPublic, authKp.dsaPublic), sig_by_authority: sig },
  };
  const known: KnownContactIdentity = {
    fingerprint: genesis.fingerprint,
    epoch: 0,
    version: 0,
    classicalPublicKeyArmored: genesis.publicKey,
    next_authority_commitment: pin,
  };
  return { successor, known, nextOp };
}

// A fixed, NOT verifiable object for the known-answer vector: every byte is a fixed pattern.
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
const KAT_INPUT: RotationSuccessorInput = {
  durable_id: '11'.repeat(32),
  prior_epoch: 7,
  successor_epoch: 8,
  new_fingerprint: '22'.repeat(32),
  new_public_key: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nKAT\n-----END PGP PUBLIC KEY BLOCK-----',
  new_pq_kem_public_key: uint8ToBase64(fill(1568, 0x33)),
  new_pq_sig_public_key: uint8ToBase64(fill(2592, 0x44)),
  next_authority_commitment: '55'.repeat(32),
  auth: { kind: 'rotation', auth_pubkeys: { sign: '66'.repeat(32), pq_sig: '77'.repeat(2592) }, sig_by_authority: '88'.repeat(64) + '99'.repeat(4627) },
};

const msgOf = (e: unknown) => (e instanceof Error ? e.message : String(e));

// ---------- KAT ----------
test('K1 known-answer vector: a fixed input encodes to exactly these bytes (length and SHA-256)', () => {
  const b = encodeKeyRotate(KAT_INPUT);
  assert.equal(b.length, 4 + 32 + 8 + 8 + 32 + 32 + (4 + KAT_INPUT.new_public_key.length) + 1568 + 2592 + 32 + 2592 + 64 + 4627);
  assert.equal(bytesToHex(b.slice(0, 4)), '4b520101', 'magic, version, kind');
  assert.equal(bytesToHex(b.slice(4, 36)), '11'.repeat(32));
  assert.equal(bytesToHex(b.slice(36, 44)), '0000000000000007');
  assert.equal(bytesToHex(b.slice(44, 52)), '0000000000000008');
  assert.equal(bytesToHex(sha256(b)), '1622fc62fb937c1e3602ac4a74924f72258d666e8c5ba18c1234cc2d18c7628d');
});

// ---------- round trip against the REAL verifier ----------
test('K2 round trip: encode, parse, verify gives exactly what the existing verifier gives', async () => {
  const { successor, known, nextOp } = await realRotation();
  const direct = await verifyRotationSuccessor(successor, known);
  const viaWire = await parseKeyRotate(encodeKeyRotate(successor)).verify(known);
  assert.deepEqual(viaWire.adopted, direct);
  assert.equal(viaWire.adopted.epoch, 1);
  assert.equal(viaWire.adopted.fingerprint, nextOp.fingerprint);
  assert.deepEqual({ ...viaWire.successor }, { ...successor });
});

// ---------- strict parse ----------
test('K3 strict parse: every malformation is refused with a stable reason', () => {
  const good = encodeKeyRotate(KAT_INPUT);
  const reason = (b: Uint8Array) => {
    try { parseKeyRotate(b); } catch (e) { return e instanceof LpParseError ? e.reason : 'other:' + msgOf(e); }
    return 'accepted';
  };
  const mut = (f: (b: Uint8Array) => void) => { const b = good.slice(); f(b); return b; };
  assert.equal(reason(good), 'accepted');
  assert.equal(reason(mut((b) => { b[0] = 0; })), 'bad-header');
  assert.equal(reason(mut((b) => { b[2] = 2; })), 'bad-header');
  assert.equal(reason(mut((b) => { b[3] = 9; })), 'bad-header');
  assert.equal(reason(new Uint8Array([...good, 0])), 'trailing-bytes');
  assert.equal(reason(good.slice(0, good.length - 1)), 'truncated');
  assert.equal(reason(good.slice(0, 3)), 'truncated');
  assert.equal(reason(new Uint8Array(0)), 'truncated');
  const lpAt = 4 + 32 + 8 + 8 + 32 + 32; // the armored key's length prefix
  assert.equal(reason(mut((b) => new DataView(b.buffer).setUint32(lpAt, KEY_ROTATE_ARMORED_MAX + 1, false))), 'length-over-max');
  assert.equal(reason(mut((b) => new DataView(b.buffer).setUint32(lpAt, good.length, false))), 'length-overrun');
  assert.equal(reason(mut((b) => new DataView(b.buffer).setUint32(lpAt, 0, false))), 'bad-field', 'a zero-length armored key is refused as soon as it is read');
  assert.equal(reason(mut((b) => { b[lpAt + 4] = 0xff; })), 'bad-utf8');
  assert.equal(reason(mut((b) => new DataView(b.buffer).setBigUint64(36, BigInt('1152921504606846976'), false))), 'unsafe-integer');
});

test('K4 a refusal never echoes the input: the message is the reason and nothing else', async () => {
  const marker = 'ATTACKER-CONTROLLED-MARKER';
  const odd = { ...KAT_INPUT, new_public_key: marker };
  const b = encodeKeyRotate(odd);
  const lpAt = 4 + 32 + 8 + 8 + 32 + 32;
  b[lpAt + 4] = 0xff; // invalid UTF-8 inside the marker region
  try { parseKeyRotate(b); assert.fail('should refuse'); } catch (e) {
    assert.ok(e instanceof LpParseError);
    assert.equal(msgOf(e), 'binary object refused (bad-utf8)');
    assert.ok(!msgOf(e).includes('ATTACKER'));
  }
  // a verify failure: the verifier's own detail text (which carries the sender's durable id) must be dropped
  const { successor, known } = await realRotation();
  const stranger = { ...successor, durable_id: 'ab'.repeat(32) };
  await assert.rejects(
    () => parseKeyRotate(encodeKeyRotate(stranger)).verify(known),
    (e: unknown) => e instanceof KeyRotateRefused && e.reason === 'wrong-origin' && !msgOf(e).includes('ab'.repeat(32)) && msgOf(e) === 'key.rotate refused (wrong-origin)',
  );
});

// ---------- verification is a real gate ----------
test('K5 flip one byte of each signed or bound field: verification refuses', async () => {
  const { successor, known } = await realRotation();
  const good = encodeKeyRotate(successor);
  const lpAt = 4 + 32 + 8 + 8 + 32 + 32;
  const armoredLen = new DataView(good.buffer, good.byteOffset).getUint32(lpAt, false);
  const kemAt = lpAt + 4 + armoredLen;
  const dsaAt = kemAt + 1568;
  const authEdAt = dsaAt + 2592;
  const authDsaAt = authEdAt + 32;
  const sigAt = authDsaAt + 2592;
  const flipped = async (at: number) => {
    const b = good.slice();
    b[at] ^= 0x01;
    try { await parseKeyRotate(b).verify(known); return 'accepted'; } catch (e) { return e instanceof KeyRotateRefused ? e.reason : 'other'; }
  };
  assert.equal(await flipped(4 + 5), 'wrong-origin', 'durable id');
  assert.equal(await flipped(4 + 32 + 8 + 7), 'rotation-epoch-not-next', 'successor epoch');
  assert.equal(await flipped(4 + 32 + 8 + 8 + 5), 'rotation-bad-authority-sig', 'new fingerprint is signed');
  assert.equal(await flipped(4 + 32 + 8 + 8 + 32 + 5), 'rotation-bad-authority-sig', 'next pin is signed');
  assert.equal(await flipped(kemAt + 10), 'rotation-fingerprint-mismatch', 'a new public key is bound by the fingerprint');
  assert.equal(await flipped(dsaAt + 10), 'rotation-fingerprint-mismatch');
  assert.equal(await flipped(authEdAt + 3), 'rotation-commitment-mismatch', 'reveal must hash to the pin');
  assert.equal(await flipped(authDsaAt + 3), 'rotation-commitment-mismatch');
  assert.equal(await flipped(sigAt + 3), 'rotation-bad-authority-sig');
  assert.equal(await flipped(sigAt + 64 + 100), 'rotation-bad-authority-sig');
});

test('K6 a successor signed by the OLD operational key only (no authority) cannot be encoded as a rotation', () => {
  const noAuth = { ...KAT_INPUT, auth: { kind: 'recovery', quorum_sigs: [], threshold: 3 } } as unknown as RotationSuccessorInput;
  assert.throws(() => encodeKeyRotate(noAuth), (e: unknown) => e instanceof KeyRotateRefused && e.reason === 'not-a-rotation');
});

// ---------- opacity ----------
test('K7 the parsed object exposes nothing before verify', async () => {
  const u = parseKeyRotate(encodeKeyRotate(KAT_INPUT));
  assert.ok(u instanceof UnverifiedKeyRotate);
  assert.deepEqual(Object.keys(u), []);
  assert.equal(JSON.stringify(u), '{}');
  assert.deepEqual(Object.getOwnPropertyNames(u), []);
  const proto = Object.getOwnPropertyNames(Object.getPrototypeOf(u)).sort();
  assert.deepEqual(proto, ['constructor', 'verify']);
});

// ---------- size, on the real hybrid seal ----------
test('K8 sealed size: the binary form fits one request with margin, and is about half the JSON form', async () => {
  const { successor } = await realRotation();
  const r = await mintHybridRecipient();
  const bin = encodeKeyRotate(successor);
  const json = new TextEncoder().encode(JSON.stringify(successor));
  const sealedBin = (await sealLivingBookHybrid(bin, r.publicKeyArmored, r.pqKemPublicKey)).length;
  const sealedJson = (await sealLivingBookHybrid(json, r.publicKeyArmored, r.pqKemPublicKey)).length;
  console.log(`# sizes: binary ${bin.length} B -> sealed ${sealedBin} B; JSON ${json.length} B -> sealed ${sealedJson} B (relay request cap 65536)`);
  assert.ok(sealedBin <= 65536 * 0.75, 'at least 25% margin under the 65,536-byte request cap');
  assert.ok(Math.abs(sealedBin - (Math.ceil(bin.length / 3) * 4 + 2354)) <= 64, 'matches the measured blob = base64(P) + 2,354 B');
  assert.ok(sealedBin < sealedJson * 0.7, 'binary is much smaller than JSON');
});

// ---------- purity and darkness ----------
test('K9 the module is pure: no I/O, no clock, no randomness in the codec files', () => {
  const here = dirname(fileURLToPath(import.meta.url));
  for (const f of [join(here, 'key-rotate-wire.ts'), join(here, '..', 'crypto', 'lp-reader.ts')]) {
    const src = readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
    for (const bad of ['fetch(', 'localStorage', 'indexedDB', 'Date.now', 'new Date', 'Math.random', 'randomBytes', 'getRandomValues', "from 'fs'", 'process.env', 'XMLHttpRequest']) {
      assert.ok(!src.includes(bad), `${f} must not use ${bad}`);
    }
  }
});

test('K10 dark: nothing outside tests imports the codec modules', () => {
  const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
  const hits: string[] = [];
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      if (statSync(p).isDirectory()) { if (n !== 'node_modules') walk(p); continue; }
      if (!/\.(ts|tsx)$/.test(n) || /\.test\.(ts|tsx)$/.test(n)) continue;
      const s = readFileSync(p, 'utf8');
      if (/from ['"][^'"]*(key-rotate-wire|lp-reader)['"]/.test(s) && !/key-rotate-wire\.ts$|lp-reader\.ts$/.test(p)) hits.push(p);
    }
  };
  walk(root);
  assert.deepEqual(hits, []);
});

test('K11 encode refuses non-canonical text for the public keys (the same bytes spelled two ways)', () => {
  const b64 = KAT_INPUT.new_pq_kem_public_key;
  assert.ok(b64.endsWith('='), 'a 1568-byte key has one padding char');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const i = alphabet.indexOf(b64[b64.length - 2]);
  const alt = b64.slice(0, -2) + alphabet[i | 1] + '=';
  assert.notEqual(alt, b64);
  assert.throws(() => encodeKeyRotate({ ...KAT_INPUT, new_pq_kem_public_key: alt }), (e: unknown) => e instanceof KeyRotateRefused);
  assert.throws(() => encodeKeyRotate({ ...KAT_INPUT, durable_id: 'AB'.repeat(32) }), (e: unknown) => e instanceof KeyRotateRefused && e.reason === 'bad-hex32', 'upper-case hex is refused');
});
