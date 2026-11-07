// Run: node --test src/lib/crypto/beacon-wire.test.mjs
// Mutual-trust beacon, verifier half: the ONE wire parser/serializer, shared by prover and verifier.
// Deposit = { proof, publicSignals } and nothing else; slot = H_e, nullifier = N, poll key = K are DERIVED from the
// pinned signal order [e, H_e, N, K]. Every accepted input round-trips byte-for-byte, and dedupe keys are bigints.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { R, Q, MAX_DIGITS, parseSignals, serializeSignals, parseProof, parseDeposit, WireError } from './beacon-wire.mjs';

const R_STR = '21888242871839275222246405745257275088548364400416034343698204186575808495617';
const Q_STR = '21888242871839275222246405745257275088696311157297823662689037894645226208583';
const SIG = ['7', '12345678901234567890', '0', '21888242871839275222246405745257275088548364400416034343698204186575808495616'];
const P1 = '1';
const PROOF = {
  protocol: 'groth16',
  curve: 'bn128',
  pi_a: ['1', '2', '1'],
  pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
  pi_c: ['7', '8', '1'],
};
const refused = (fn) => assert.throws(fn, (e) => e instanceof WireError, 'must refuse with WireError');

test('constants are the BN254 scalar order r and base field q, both 77 digits', () => {
  assert.equal(R, BigInt(R_STR));
  assert.equal(Q, BigInt(Q_STR));
  assert.equal(MAX_DIGITS, 77);
});

test('canonical signals parse to bigints in the pinned order and round-trip byte-for-byte (one spelling)', () => {
  const s = parseSignals(SIG);
  assert.deepEqual(s, { e: 7n, H_e: 12345678901234567890n, N: 0n, K: BigInt(SIG[3]) });
  assert.deepEqual(serializeSignals(s), SIG);
});

for (const bad of ['007', '0x7', '+7', ' 7', '7 ', '7.0', '-0', '-1', '', '1e3', '٧', '0'.repeat(78)]) {
  test(`non-canonical spelling refused: ${JSON.stringify(bad)} `, () => {
    refused(() => parseSignals(['7', bad, '0', '1']));
  });
}

test('a 78-digit string is refused BEFORE any BigInt parse (cheap checks first)', () => {
  const orig = globalThis.BigInt;
  let calls = 0;
  globalThis.BigInt = (x) => { calls += 1; return orig(x); };
  try {
    refused(() => parseSignals(['7', '1'.repeat(78), '0', '1']));
  } finally {
    globalThis.BigInt = orig;
  }
  assert.equal(calls, 0, 'no BigInt work on an over-long input');
});

test('an over-long proof coordinate is refused BEFORE any BigInt parse too', () => {
  const orig = globalThis.BigInt;
  let calls = 0;
  globalThis.BigInt = (x) => { calls += 1; return orig(x); };
  try {
    refused(() => parseProof({ ...PROOF, pi_a: ['9'.repeat(5000), '2', '1'] }));
  } finally {
    globalThis.BigInt = orig;
  }
  assert.equal(calls, 0, 'no BigInt work on an over-long coordinate');
});

for (const [i, name] of ['e', 'H_e', 'N', 'K'].entries()) {
  test(`aliasing: ${name} = value + r refused (and r itself)`, () => {
    const plus = [...SIG];
    plus[i] = (BigInt(SIG[i]) + R).toString();
    refused(() => parseSignals(plus));
    const atR = [...SIG];
    atR[i] = R_STR;
    refused(() => parseSignals(atR));
  });
}

test('3 or 5 signals refused; non-strings refused', () => {
  refused(() => parseSignals(SIG.slice(0, 3)));
  refused(() => parseSignals([...SIG, '1']));
  refused(() => parseSignals([7, '1', '0', '1']));
  refused(() => parseSignals('7,1,0,1'));
});

test('a canonical proof parses and round-trips', () => {
  const p = parseProof(PROOF);
  assert.equal(p.pi_a[0], 1n);
  assert.equal(p.pi_b[1][1], 6n);
});

test('proof: exact keys, groth16 on bn128 only', () => {
  refused(() => parseProof({ ...PROOF, extra: 1 }));
  refused(() => parseProof({ ...PROOF, protocol: 'plonk' }));
  refused(() => parseProof({ ...PROOF, curve: 'bls12381' }));
  const { pi_c, ...missing } = PROOF;
  refused(() => parseProof(missing));
});

test('proof: affine only (z exactly "1" / ["1","0"]): the identity (z = 0) and projective z refused ', () => {
  refused(() => parseProof({ ...PROOF, pi_a: ['1', '2', '0'] }));
  refused(() => parseProof({ ...PROOF, pi_a: ['1', '2', '2'] }));
  refused(() => parseProof({ ...PROOF, pi_a: ['1', '2'] }));
  refused(() => parseProof({ ...PROOF, pi_b: [['3', '4'], ['5', '6'], ['0', '0']] }));
  refused(() => parseProof({ ...PROOF, pi_b: [['3', '4'], ['5', '6'], ['1', '1']] }));
  refused(() => parseProof({ ...PROOF, pi_c: ['0', '0', '1'] }));          // the affine "point at origin" encoding
});

test('proof: every coordinate canonical and < q ', () => {
  refused(() => parseProof({ ...PROOF, pi_a: [Q_STR, '2', P1] }));
  refused(() => parseProof({ ...PROOF, pi_c: ['7', '08', P1] }));
  refused(() => parseProof({ ...PROOF, pi_b: [['3', '4'], ['5', (Q + 1n).toString()], ['1', '0']] }));
});

test('deposit = { proof, publicSignals } and NOTHING else (slot/N/K are derived, never sent)', () => {
  const d = parseDeposit(JSON.stringify({ proof: PROOF, publicSignals: SIG }));
  assert.equal(d.signals.H_e, 12345678901234567890n);
  for (const extra of ['slot', 'N', 'K', 'nullifier', 'payload']) {
    refused(() => parseDeposit(JSON.stringify({ proof: PROOF, publicSignals: SIG, [extra]: '1' })));
  }
  refused(() => parseDeposit('not json'));
  refused(() => parseDeposit(JSON.stringify([PROOF, SIG])));
  refused(() => parseDeposit('x'.repeat(65 * 1024)));                     // raw size cap before JSON.parse
});
