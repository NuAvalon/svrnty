// src/lib/crypto/hybrid-seal.test.ts
// KAT + round-trip + reject for the key-agnostic PQ-hybrid seal core (Flint co-verifies these vectors).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  lpBin,
  deriveHybridSealKey,
  buildHybridSealAAD,
  sealHybridWithMaterials,
  openHybridWithMaterials,
  type HybridSealPackage,
} from './hybrid-seal';
import { base64ToUint8 } from './pq';

const NOTE_DOMAIN = 'svrnty:note-seal:v1';

// Deterministic KAT inputs — fixed byte patterns (no randomness) so the vector is reproducible.
const fill = (len: number, byte: number): Uint8Array => new Uint8Array(len).fill(byte);
const KAT = {
  ssX: fill(32, 0x11),
  ssPq: fill(32, 0x22),
  epk: fill(32, 0x33),
  kemCt: fill(1568, 0x44),
  nonce: fill(12, 0x55),
  recipFp: 'a'.repeat(64),
  senderFp: 'b'.repeat(64),
  plaintext: new TextEncoder().encode('{"type":"svrnty-note-v0","body":"hi"}'),
};

test('lpBin = uint32_be(len) ‖ x (byte-pin grammar)', () => {
  assert.equal(bytesToHex(lpBin(new Uint8Array())), '00000000');
  assert.equal(bytesToHex(lpBin(Uint8Array.of(0xab))), '00000001ab');
  assert.equal(bytesToHex(lpBin(fill(0x0100, 0x00))).slice(0, 8), '00000100');
});

test('KAT: deriveHybridSealKey + buildHybridSealAAD + package are byte-stable', async () => {
  const K = deriveHybridSealKey(KAT.ssX, KAT.ssPq, KAT.epk, KAT.kemCt, NOTE_DOMAIN, KAT.recipFp);
  const aad = buildHybridSealAAD(1, NOTE_DOMAIN, KAT.recipFp, KAT.senderFp, KAT.kemCt);
  const pkg = await sealHybridWithMaterials({
    plaintext: KAT.plaintext, ssX: KAT.ssX, ssPq: KAT.ssPq, epk: KAT.epk, kemCt: KAT.kemCt,
    domain: NOTE_DOMAIN, recipFp: KAT.recipFp, senderFp: KAT.senderFp, nonce: KAT.nonce,
  });
  // Print for baking + Flint's independent recompute.
  console.log('KAT_K       =', bytesToHex(K));
  console.log('KAT_AAD     =', bytesToHex(aad));
  console.log('KAT_CT_b64  =', pkg.ct);
  console.log('KAT_CT_hex  =', bytesToHex(base64ToUint8(pkg.ct)));
  // BAKED KAT (Flint recomputes independently and byte-verifies — same loop as the rendezvous byte-pin).
  // ssX=0x11*32, ssPq=0x22*32, epk=0x33*32, kemCt=0x44*1568, nonce=0x55*12, recipFp='a'*64, senderFp='b'*64,
  // plaintext='{"type":"svrnty-note-v0","body":"hi"}', domain='svrnty:note-seal:v1', version=1.
  assert.equal(bytesToHex(K), '088ab7e29392c6a9130ae811a5df8a6260a8795675e0714c56483642b15c9375');
  // AAD = LP(u8 ver) ‖ LP(domain) ‖ LP(recipFp) ‖ LP(senderFp) ‖ LP(kem_ct); length fully determined.
  assert.equal(aad.length, 1736); // 5 + (4+19) + (4+64) + (4+64) + (4+1568)
  assert.equal(bytesToHex(aad).slice(0, 56), '0000000101000000137376726e74793a6e6f74652d7365616c3a7631');
  assert.equal(
    bytesToHex(base64ToUint8(pkg.ct)),
    'f7c34b79552bf36bcf143ec5f91a7c4a3ba2acad9d9c954cb2e6191d89d9f3513c03a0ed1b2a2a83bfa195a9b162db978caa8a4f66',
  );
});

test('round-trip: seal → open recovers plaintext (same materials)', async () => {
  const pkg = await sealHybridWithMaterials({
    plaintext: KAT.plaintext, ssX: KAT.ssX, ssPq: KAT.ssPq, epk: KAT.epk, kemCt: KAT.kemCt,
    domain: NOTE_DOMAIN, recipFp: KAT.recipFp, senderFp: KAT.senderFp, nonce: KAT.nonce,
  });
  const pt = await openHybridWithMaterials({
    pkg, ssX: KAT.ssX, ssPq: KAT.ssPq, myFp: KAT.recipFp, expectDomain: NOTE_DOMAIN,
  });
  assert.ok(pt, 'open returned null on a valid package');
  assert.equal(new TextDecoder().decode(pt!), new TextDecoder().decode(KAT.plaintext));
});

async function sealKat(): Promise<HybridSealPackage> {
  return sealHybridWithMaterials({
    plaintext: KAT.plaintext, ssX: KAT.ssX, ssPq: KAT.ssPq, epk: KAT.epk, kemCt: KAT.kemCt,
    domain: NOTE_DOMAIN, recipFp: KAT.recipFp, senderFp: KAT.senderFp, nonce: KAT.nonce,
  });
}

test('reject: wrong recipient fp → null (before crypto)', async () => {
  const pkg = await sealKat();
  const pt = await openHybridWithMaterials({ pkg, ssX: KAT.ssX, ssPq: KAT.ssPq, myFp: 'c'.repeat(64), expectDomain: NOTE_DOMAIN });
  assert.equal(pt, null);
});

test('reject: wrong domain → null (domain-sep)', async () => {
  const pkg = await sealKat();
  const pt = await openHybridWithMaterials({ pkg, ssX: KAT.ssX, ssPq: KAT.ssPq, myFp: KAT.recipFp, expectDomain: 'svrnty:beacon:v1' });
  assert.equal(pt, null);
});

test('reject: tampered PQ secret (ss_mlkem) → wrong K → tag fails → null', async () => {
  const pkg = await sealKat();
  const badPq = KAT.ssPq.slice(); badPq[0] ^= 0x01;
  const pt = await openHybridWithMaterials({ pkg, ssX: KAT.ssX, ssPq: badPq, myFp: KAT.recipFp, expectDomain: NOTE_DOMAIN });
  assert.equal(pt, null, 'a wrong PQ shared secret must fail the tag (reject-classical-by-construction)');
});

test('reject: tampered ct → null', async () => {
  const pkg = await sealKat();
  const raw = base64ToUint8(pkg.ct); raw[0] ^= 0x01;
  const tampered = { ...pkg, ct: Buffer.from(raw).toString('base64') };
  const pt = await openHybridWithMaterials({ pkg: tampered, ssX: KAT.ssX, ssPq: KAT.ssPq, myFp: KAT.recipFp, expectDomain: NOTE_DOMAIN });
  assert.equal(pt, null);
});

test('reject: tampered sender_fp (AAD binding) → null', async () => {
  const pkg = await sealKat();
  const tampered = { ...pkg, sender_fp: 'd'.repeat(64) };
  const pt = await openHybridWithMaterials({ pkg: tampered, ssX: KAT.ssX, ssPq: KAT.ssPq, myFp: KAT.recipFp, expectDomain: NOTE_DOMAIN });
  assert.equal(pt, null, 'sender_fp is AAD-bound; changing it must break the tag');
});
