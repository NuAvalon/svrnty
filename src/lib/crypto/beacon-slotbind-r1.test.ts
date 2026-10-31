// src/lib/crypto/beacon-slotbind-r1.test.ts
// #588 R1 (Flint 532343bb): canonical public inputs at the VERIFIER-SIDE matcher. Each NEG must be GREEN here and RED on its mutant.
// Run: npx tsx --test src/lib/crypto/beacon-slotbind-r1.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { BN254_P, encodeCanonical, parseCanonical, parsePublicInputs, type PublicInputs, type WirePublicInputs } from './beacon-public-inputs';
import { SlotBindMatcher, type VerifyProof } from './beacon-slotbind-matcher';

const HONEST_A: PublicInputs = { e: BigInt(2960), H_e: BigInt('16608581245364102359222889212037320848673918162519556768373025632180948293867'), N: BigInt('17479849361611788613431285104940551914898062981632818333493438554196066824511'), K: BigInt('507422428205051884756986542224392193326807114375840914147653') };
const HONEST_B: PublicInputs = { ...HONEST_A, N: BigInt('12345678901234567890123456789012345678901234567890'), K: BigInt('987654321987654321987654321') };
const wire = (p: PublicInputs): WirePublicInputs => ({ e: encodeCanonical(p.e), H_e: encodeCanonical(p.H_e), N: encodeCanonical(p.N), K: encodeCanonical(p.K) });
const mod = (v: bigint) => ((v % BN254_P) + BN254_P) % BN254_P;

/** A verifier that behaves like a library that REDUCES mod p (accepts N+p as N): the dangerous kind. It records what it was shown. */
function reducingVerifier(honest: PublicInputs[]) {
  const seen: PublicInputs[] = [];
  const verify: VerifyProof = (_proof, p) => {
    seen.push(p);
    return honest.some((h) => (['e', 'H_e', 'N', 'K'] as const).every((k) => mod(p[k]) === mod(h[k])));
  };
  return { verify, seen };
}

test('P0 pinned spelling: 64 lowercase hex, value < p; round-trips; rejects everything else', () => {
  assert.equal(encodeCanonical(BigInt(0)), '0'.repeat(64));
  assert.equal(encodeCanonical(HONEST_A.N).length, 64);
  assert.equal(parseCanonical(encodeCanonical(HONEST_A.N)), HONEST_A.N);
  assert.equal(parseCanonical(encodeCanonical(BN254_P - BigInt(1))), BN254_P - BigInt(1), 'p-1 is the largest canonical value');
  assert.equal(parseCanonical(BN254_P.toString(16).padStart(64, '0')), null, 'p itself is NOT canonical (it is 0)');
  assert.throws(() => encodeCanonical(BN254_P), RangeError);
  assert.throws(() => encodeCanonical(BigInt(-1)), RangeError);
});

test('R1-a: each public input given as v + p is REJECTED before verification (e, H_e, N, K separately)', async () => {
  for (const key of ['e', 'H_e', 'N', 'K'] as const) {
    const { verify, seen } = reducingVerifier([HONEST_A]);
    const m = new SlotBindMatcher(verify);
    const bad = { ...wire(HONEST_A), [key]: (HONEST_A[key] + BN254_P).toString(16).padStart(64, '0') };
    assert.deepEqual(await m.deposit({ proof: 'p', publicInputs: bad }), { status: 'rejected', reason: 'malformed-public-inputs' }, key);
    assert.equal(seen.length, 0, `${key}+p never reaches the verifier`);
  }
});

test('R1-b: non-canonical ENCODINGS are rejected: leading zeros stripped, uppercase, 0x, decimal, negative, whitespace, wrong length, wrong type, extra/missing key', async () => {
  const good = wire(HONEST_A);
  const hex = good.K; // K has ~42 leading zeros in its 64-char spelling, so "leading zeros stripped" is a REAL different string (N's top digit is non-zero)
  const variants: unknown[] = [
    hex.replace(/^0+/, ''), hex.toUpperCase(), '0x' + hex, HONEST_A.K.toString(10), '-' + HONEST_A.K.toString(10), ' ' + hex, hex + '\n', hex + '0', hex.slice(1),
    HONEST_A.K, Number(5), null, undefined, ['a'], { toString: () => hex },
  ];
  for (const v of variants) {
    const { verify, seen } = reducingVerifier([HONEST_A]);
    const m = new SlotBindMatcher(verify);
    const r = await m.deposit({ proof: 'p', publicInputs: { ...good, K: v as string } });
    assert.deepEqual(r, { status: 'rejected', reason: 'malformed-public-inputs' }, String(typeof v) + ':' + String(v).slice(0, 20));
    assert.equal(seen.length, 0);
  }
  assert.equal(parsePublicInputs({ ...good, extra: hex }), null, 'an extra key is refused');
  const { K: _k, ...missing } = good;
  assert.equal(parsePublicInputs(missing), null, 'a missing key is refused');
  assert.equal(parsePublicInputs([good.e, good.H_e, good.N, good.K]), null, 'an array is not an object');
  assert.equal(parsePublicInputs(null), null);
});

test('R1-c (the bond test): one honest A proof submitted at the same H_e, once canonical and once as N+p => NO match fires, the second is rejected', async () => {
  const { verify } = reducingVerifier([HONEST_A]); // reduces mod p, so it would VERIFY N+p
  const m = new SlotBindMatcher(verify);
  assert.deepEqual(await m.deposit({ proof: 'A', publicInputs: wire(HONEST_A) }), { status: 'deposited' });
  const fake = { ...wire(HONEST_A), N: (HONEST_A.N + BN254_P).toString(16).padStart(64, '0') };
  assert.deepEqual(await m.deposit({ proof: 'A', publicInputs: fake }), { status: 'rejected', reason: 'malformed-public-inputs' }, 'a lone A cannot fake a second nullifier');
});

test('R1-d: dedupe is on the CANONICAL value: the same N twice is "already deposited", never a match', async () => {
  const { verify } = reducingVerifier([HONEST_A]);
  const m = new SlotBindMatcher(verify);
  assert.deepEqual(await m.deposit({ proof: 'A', publicInputs: wire(HONEST_A) }), { status: 'deposited' });
  assert.deepEqual(await m.deposit({ proof: 'A', publicInputs: wire(HONEST_A) }), { status: 'already-deposited' });
});

test('control: two DISTINCT valid nullifiers at one slot fire the match; a third is refused; a bad proof is refused after the canonical check', async () => {
  const { verify, seen } = reducingVerifier([HONEST_A, HONEST_B]);
  const m = new SlotBindMatcher(verify);
  assert.deepEqual(await m.deposit({ proof: 'A', publicInputs: wire(HONEST_A) }), { status: 'deposited' });
  const r = await m.deposit({ proof: 'B', publicInputs: wire(HONEST_B) });
  assert.equal(r.status, 'match');
  if (r.status === 'match') assert.deepEqual(r.nullifiers, [encodeCanonical(HONEST_A.N), encodeCanonical(HONEST_B.N)]);
  assert.equal(seen.length, 2);
  const third: PublicInputs = { ...HONEST_A, N: BigInt(777) };
  assert.deepEqual(await m.deposit({ proof: 'C', publicInputs: wire(third) }), { status: 'rejected', reason: 'proof-invalid' }, 'unknown to the verifier => proof-invalid');
  const { verify: v2 } = reducingVerifier([HONEST_A, HONEST_B, third]);
  const m2 = new SlotBindMatcher(v2);
  await m2.deposit({ proof: 'A', publicInputs: wire(HONEST_A) });
  await m2.deposit({ proof: 'B', publicInputs: wire(HONEST_B) });
  assert.deepEqual(await m2.deposit({ proof: 'C', publicInputs: wire(third) }), { status: 'rejected', reason: 'slot-full' });
});

test('a verifier that THROWS is a rejection, and the verifier only ever sees canonical bigints', async () => {
  const m = new SlotBindMatcher(() => { throw new Error('boom'); });
  assert.deepEqual(await m.deposit({ proof: 'x', publicInputs: wire(HONEST_A) }), { status: 'rejected', reason: 'proof-invalid' });
  let shown: PublicInputs | undefined;
  const m2 = new SlotBindMatcher((_p, pub) => { shown = pub; return true; });
  await m2.deposit({ proof: 'x', publicInputs: wire(HONEST_A) });
  assert.deepEqual(shown, HONEST_A);
});

// ── Integration (measured, local only): the REAL snarkjs against the REAL throwaway-ceremony proof of the prototype. Skipped when the artifacts are absent (CI). ──
const ZK = '/home/appuser/e2e-scratch/zk/';
const HAVE_ZK = existsSync(ZK + 'vkey.json') && existsSync(ZK + 'proof.json') && existsSync(ZK + 'public.json') && existsSync(ZK + 'node_modules/snarkjs');
test('INTEGRATION (snarkjs 0.7.6, real proof): honest verifies; each public input + p is REJECTED by the library; so the matcher precheck is defence in depth for THIS library, and the only line for one that reduces', { skip: !HAVE_ZK }, async () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const snarkjs = require(ZK + 'node_modules/snarkjs');
  const vkey = JSON.parse(readFileSync(ZK + 'vkey.json', 'utf8'));
  const proof = JSON.parse(readFileSync(ZK + 'proof.json', 'utf8'));
  const pub = JSON.parse(readFileSync(ZK + 'public.json', 'utf8')) as string[];
  assert.equal(await snarkjs.groth16.verify(vkey, pub, proof), true);
  for (let i = 0; i < pub.length; i++) {
    const v = pub.slice();
    v[i] = (BigInt(pub[i]) + BN254_P).toString();
    assert.equal(await snarkjs.groth16.verify(vkey, v, proof), false, `public[${i}]+p`);
  }
});

test('R1-e (canonical round-trip): for EVERY spelling the parser accepts, encode(parse(s)) === s; so the wire string and the parsed value are the same key', () => {
  // deterministic xorshift, so a failure reproduces
  let st = 0x9e3779b9;
  const rnd = () => { st ^= st << 13; st >>>= 0; st ^= st >>> 17; st ^= st << 5; st >>>= 0; return st; };
  const hex = (n: number) => Array.from({ length: n }, () => '0123456789abcdef'[rnd() & 15]).join('');
  const canon = [hex(64), '0'.repeat(64), 'f'.repeat(64), encodeCanonical(BN254_P - BigInt(1)), encodeCanonical(BigInt(0)), encodeCanonical(BN254_P - BigInt(2))];
  const candidates: string[] = [...canon];
  for (let i = 0; i < 400; i++) {
    const base = i % 3 === 0 ? hex(64) : canon[i % canon.length];
    const mutants = [
      base.toUpperCase(), '0x' + base, base.replace(/^0+/, ''), ' ' + base, base + ' ', base + '\n', base.slice(0, 63), base + '0',
      base.slice(0, 10) + base[10].toUpperCase() + base.slice(11), base.replace(/^./, '+'), '-' + base.slice(1), BigInt('0x' + base).toString(10),
      (BigInt('0x' + base) + BN254_P).toString(16).padStart(64, '0'), hex(64),
    ];
    candidates.push(...mutants);
  }
  let accepted = 0;
  for (const s of candidates) {
    const v = parseCanonical(s);
    if (v === null) continue;
    accepted++;
    assert.equal(encodeCanonical(v), s, `parser accepted a second spelling: ${JSON.stringify(s)}`);
    assert.ok(v >= BigInt(0) && v < BN254_P);
  }
  assert.ok(accepted >= 100, 'the property must actually be exercised (got ' + accepted + ' accepted spellings)');
  // and the other direction: every canonical value parses back to itself
  for (const v of [BigInt(0), BigInt(1), BN254_P - BigInt(1), BigInt(2960), HONEST_A.N, HONEST_A.H_e]) assert.equal(parseCanonical(encodeCanonical(v)), v);
});

test('R1-e (matcher): the dedupe key is the parsed value; a second spelling of N never reaches the slot as a distinct entry', async () => {
  const { verify } = reducingVerifier([HONEST_A]);
  const m = new SlotBindMatcher(verify);
  const w = wire(HONEST_A);
  assert.equal((await m.deposit({ proof: 'p', publicInputs: w })).status, 'deposited');
  const aliases = [w.N.toUpperCase(), '0x' + w.N, w.N.replace(/^0+/, ''), ' ' + w.N, (BigInt('0x' + w.N) + BN254_P).toString(16)].filter((x) => x !== w.N);
  assert.ok(aliases.length >= 3, 'need real aliases (an alias equal to the canonical spelling tests nothing)');
  for (const alias of aliases) {
    const r = await m.deposit({ proof: 'p', publicInputs: { ...w, N: alias } });
    assert.deepEqual(r, { status: 'rejected', reason: 'malformed-public-inputs' });
  }
  assert.equal((await m.deposit({ proof: 'p', publicInputs: w })).status, 'already-deposited');
});
