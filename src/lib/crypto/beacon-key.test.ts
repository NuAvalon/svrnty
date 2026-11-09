// src/lib/crypto/beacon-key.test.ts
// #588 T4, first piece: the beacon KEY (generate, pack, and the receiver's checks on a key that arrives on a card). Trust stays DARK; nothing imports this.
// Receiver rules in order (T4 note v0.2 §3): canonical decode, on curve, not the identity, not small order, l*Y = O, not my own. A failure
// drops the KEY only, so every check returns a result and none throws.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateBeaconSecret, beaconPublicKey, checkBeaconPublicKey, BEACON_KEY_BYTES } from './beacon-key';

const L = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const P_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let libs: Promise<any> | undefined;
const curve = () => (libs ??= import('circomlibjs').then((m: any) => m.buildBabyjub()));
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const fromB64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

/** The pinned encoding in pure BigInt (no curve library): y little-endian, bit 7 of byte 31 set iff x > (p-1)/2. */
function packPure(x: bigint, y: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let v = y;
  for (let i = 0; i < 32; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
  if (x > (P_FIELD - 1n) / 2n) out[31] |= 0x80;
  return out;
}
async function pack(pt: [bigint, bigint]): Promise<string> {
  return b64(packPure(pt[0], pt[1]));
}
const BASE8: [bigint, bigint] = [
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
];

/** A point of order 8 (in the cofactor-8 torsion), found by clearing the prime-order part of a curve point. */
async function torsionPoint(): Promise<[bigint, bigint]> {
  const bj: any = await curve();
  for (let y = 5n; y < 400n; y++) {
    const bytes = new Uint8Array(32);
    let v = y;
    for (let i = 0; i < 32; i++) { bytes[i] = Number(v & 0xffn); v >>= 8n; }
    const pt = bj.unpackPoint(bytes);
    if (!pt) continue;
    const t = bj.mulPointEscalar(pt, L);
    const q = bj.mulPointEscalar(t, 4n);
    const isId = (p: any) => bj.F.toObject(p[0]) === 0n && bj.F.toObject(p[1]) === 1n;
    if (!isId(t) && !isId(q)) return [bj.F.toObject(t[0]), bj.F.toObject(t[1])]; // order 8: 4*t is not the identity
  }
  throw new Error('no order-8 point found');
}

test('K1 a generated secret is in [1, L) and two draws differ (CSPRNG default)', async () => {
  const a = await generateBeaconSecret(), b = await generateBeaconSecret();
  for (const x of [a, b]) assert.ok(x >= 1n && x < L, 'in range');
  assert.notEqual(a, b);
});

test('K2 the random source is a seam: all-zero bytes are rejected (x = 0 is never returned), a good draw after is taken', async () => {
  let calls = 0;
  const x = await generateBeaconSecret((n) => {
    calls++;
    return calls === 1 ? new Uint8Array(n) : Uint8Array.from({ length: n }, (_, i) => (i === 0 ? 7 : 0));
  });
  assert.equal(calls, 2, 'the zero draw was rejected and redrawn');
  assert.equal(x, 7n);
});

test('K3 a draw >= L is rejected, not reduced (no modular bias)', async () => {
  let calls = 0;
  const big = new Uint8Array(32).fill(0xff); // 2^256-1: masked to 251 bits it is far above L
  const x = await generateBeaconSecret((n) => { calls++; return calls === 1 ? big : Uint8Array.from({ length: n }, (_, i) => (i === 0 ? 9 : 0)); });
  assert.equal(calls, 2);
  assert.equal(x, 9n);
});

test('K4 the public key is 32 bytes, base64, canonical, and the receiver accepts it', async () => {
  const x = await generateBeaconSecret();
  const pub = await beaconPublicKey(x);
  assert.equal(fromB64(pub).length, BEACON_KEY_BYTES);
  assert.equal(b64(fromB64(pub)), pub, 'canonical base64');
  const r = await checkBeaconPublicKey(pub);
  assert.equal(r.ok, true);
  if (r.ok) {
    const bj: any = await curve();
    const P = bj.mulPointEscalar(bj.Base8, x);
    assert.deepEqual([r.point[0], r.point[1]], [bj.F.toObject(P[0]), bj.F.toObject(P[1])], 'the decoded point is x*Base8');
  }
});

test('K5 a known secret gives a pinned public key (a fixed vector from plain BigInt, so an encoding change is loud)', async () => {
  const pub = await beaconPublicKey(1n);
  assert.equal(pub, await pack(BASE8), 'x = 1 encodes Base8');
  // and spelled out: y little-endian, sign bit clear (Base8.x < (p-1)/2)
  const bytes = fromB64(pub);
  assert.equal(bytes[31] & 0x80, 0);
  let y = 0n;
  for (let j = 31; j >= 0; j--) y = (y << 8n) | BigInt(bytes[j]);
  assert.equal(y, BASE8[1]);
});

test('K5b the sign bit follows x: over 40 random keys the encoder, the decoder and the BigInt packer agree, and both halves of the field occur', async () => {
  const bj: any = await curve();
  let hi = 0, lo = 0;
  for (let i = 0; i < 40; i++) {
    const x = await generateBeaconSecret();
    const pub = await beaconPublicKey(x);
    const P = bj.mulPointEscalar(bj.Base8, x);
    const px = bj.F.toObject(P[0]) as bigint, py = bj.F.toObject(P[1]) as bigint;
    assert.equal(pub, await pack([px, py]), 'encoder == pure packer');
    const r = await checkBeaconPublicKey(pub);
    assert.equal(r.ok, true);
    if (r.ok) assert.deepEqual([r.point[0], r.point[1]], [px, py], 'decoder returns exactly x*Base8');
    if (px > (P_FIELD - 1n) / 2n) hi++; else lo++;
  }
  assert.ok(hi > 0 && lo > 0, `both sign halves exercised (hi=${hi}, lo=${lo})`);
});

test('K6 reject the identity point', async () => {
  const r = await checkBeaconPublicKey(await pack([0n, 1n]));
  assert.deepEqual(r, { ok: false, reason: 'identity' });
});

test('K7 reject a point of order 2 (0, -1) as small order', async () => {
  const r = await checkBeaconPublicKey(await pack([0n, P_FIELD - 1n]));
  assert.deepEqual(r, { ok: false, reason: 'small-order' });
});

test('K8 reject a torsion point and a subgroup key plus a torsion point (the l*Y = O check)', async () => {
  const bj: any = await curve();
  const T = await torsionPoint();
  const rT = await checkBeaconPublicKey(await pack(T));
  assert.equal(rT.ok, false);
  const Y = bj.mulPointEscalar(bj.Base8, 12345n);
  const YT = bj.addPoint(Y, [bj.F.e(T[0]), bj.F.e(T[1])]);
  const r = await checkBeaconPublicKey(await pack([bj.F.toObject(YT[0]), bj.F.toObject(YT[1])]));
  assert.deepEqual(r, { ok: false, reason: 'not-in-subgroup' }, 'a good key with a torsion component is hostile, not merely odd');
});

test('K9 reject an encoding that does not decode to a curve point', async () => {
  const bj: any = await curve();
  let bad: string | undefined;
  for (let y = 2n; y < 200n && !bad; y++) {
    const bytes = new Uint8Array(32);
    let v = y;
    for (let i = 0; i < 32; i++) { bytes[i] = Number(v & 0xffn); v >>= 8n; }
    if (!bj.unpackPoint(bytes)) bad = b64(bytes);
  }
  assert.ok(bad, 'found an off-curve y');
  // The decoder's field sqrt never returns on a non-residue (measured), so a missing isSquare guard shows up as a HANG: race it, so the mutant fails fast.
  const verdict = await Promise.race([
    checkBeaconPublicKey(bad!),
    new Promise((resolve) => setTimeout(() => resolve('HUNG'), 8000).unref()),
  ]);
  assert.deepEqual(verdict, { ok: false, reason: 'off-curve' });
});

test('K10 reject malformed input: wrong length, not base64, non-canonical base64, not a string', async () => {
  const good = await beaconPublicKey(77n);
  for (const bad of ['', 'AAAA', good + 'AA', good.slice(0, -2), '!!!!', good.replace(/=+$/, ''), good + '\n', ' ' + good]) {
    assert.deepEqual(await checkBeaconPublicKey(bad), { ok: false, reason: 'encoding' }, JSON.stringify(bad));
  }
  for (const bad of [undefined, null, 5, {}, []]) {
    assert.deepEqual(await checkBeaconPublicKey(bad as any), { ok: false, reason: 'encoding' });
  }
});

test('K11 reject a NON-CANONICAL encoding: y >= p, and the sign bit set on x = 0; the other sign of a good key is a different valid key', async () => {
  const bj: any = await curve();
  const P = bj.mulPointEscalar(bj.Base8, 31337n);
  const px = bj.F.toObject(P[0]) as bigint, py = bj.F.toObject(P[1]) as bigint;
  const good = packPure(px, py);
  const flipped = new Uint8Array(good);
  flipped[31] ^= 0x80;
  const a = await checkBeaconPublicKey(b64(good));
  const b = await checkBeaconPublicKey(b64(flipped));
  assert.equal(a.ok, true);
  assert.equal(b.ok, true, '-P is a valid, different key');
  if (a.ok && b.ok) { assert.notDeepEqual(a.point, b.point); assert.equal(a.point[1], b.point[1]); assert.equal((a.point[0] + b.point[0]) % P_FIELD, 0n, 'x and -x'); }
  // y >= p: the encoder never emits it, so the checker must refuse it (here the alias of the identity's y = 1)
  const alias = new Uint8Array(32);
  let v = P_FIELD + 1n;
  for (let i = 0; i < 32; i++) { alias[i] = Number(v & 0xffn); v >>= 8n; }
  assert.deepEqual(await checkBeaconPublicKey(b64(alias)), { ok: false, reason: 'encoding' });
  // x = 0 has no negative side: the identity with the sign bit set is not the identity's encoding
  const idNeg = packPure(0n, 1n);
  idNeg[31] |= 0x80;
  assert.deepEqual(await checkBeaconPublicKey(b64(idNeg)), { ok: false, reason: 'encoding' });
});

test('K12 reject my own key', async () => {
  const mine = await beaconPublicKey(424242n);
  assert.deepEqual(await checkBeaconPublicKey(mine, mine), { ok: false, reason: 'own-key' });
  const other = await beaconPublicKey(424243n);
  assert.equal((await checkBeaconPublicKey(other, mine)).ok, true);
});

test('K13 the checks never throw and never echo the input in a reason (reason codes are fixed words)', async () => {
  const reasons = new Set(['encoding', 'off-curve', 'identity', 'small-order', 'not-in-subgroup', 'own-key']);
  for (const input of ['', 'x'.repeat(100), await pack([0n, 1n]), await pack([0n, P_FIELD - 1n])]) {
    const r = await checkBeaconPublicKey(input);
    if (!r.ok) assert.ok(reasons.has(r.reason), r.reason);
  }
});
