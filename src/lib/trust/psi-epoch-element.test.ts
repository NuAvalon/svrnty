// Per-epoch PSI element: refusals first, then separation (layer, epoch, fingerprint, secret), then the known answers.
// The vectors come from scripts/psi-epoch-element-kat.py (stdlib HKDF, no shared code).
// Run: npx tsx --test src/lib/trust/psi-epoch-element.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { x25519 } from '@noble/curves/ed25519.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import {
  psiElement,
  mintEpochSecrets,
  PsiElementError,
  EPOCH_SECRET_LEN,
  PSI_LAYERS,
  type PsiLayer,
} from './psi-epoch-element';
import { hashFingerprintToPoint } from './mutual-trust-sync';
import { lpBin, lpStr } from '../crypto/lp-tlv';

const FP_A = createHash('sha256').update('kat-fp-A').digest('hex');
const FP_B = createHash('sha256').update('kat-fp-B').digest('hex');
const S1 = Uint8Array.from({ length: 32 }, (_, i) => i);
const S2 = Uint8Array.from({ length: 32 }, (_, i) => 32 + i);

const hex = (b: Uint8Array) => bytesToHex(b);
const codeOf = (fn: () => unknown) => {
  try {
    fn();
  } catch (e) {
    return e instanceof PsiElementError ? e.code : `other:${String(e)}`;
  }
  return 'no-throw';
};

// ── refusals ────────────────────────────────────────────────────────────────────────────────────────────────

test('a fingerprint that is not canonical lowercase 64-hex is refused', () => {
  for (const bad of [FP_A.toUpperCase(), FP_A.slice(0, 40), FP_A.slice(0, 63), FP_A + '0', ` ${FP_A}`, FP_A.replace(/^(..)/, '$1:'), '', 'zz'.repeat(32)]) {
    assert.equal(codeOf(() => psiElement(bad, 'know', 1, S1)), 'bad-fingerprint', JSON.stringify(bad));
  }
  assert.equal(codeOf(() => psiElement(undefined as unknown as string, 'know', 1, S1)), 'bad-fingerprint');
});

test('a layer other than know or trust is refused', () => {
  for (const bad of ['Know', 'TRUST', '', 'know ', 'both', 'trusted']) {
    assert.equal(codeOf(() => psiElement(FP_A, bad as PsiLayer, 1, S1)), 'bad-layer', JSON.stringify(bad));
  }
});

test('an epoch that is negative, fractional, not finite or beyond the safe range is refused', () => {
  for (const bad of [-1, 0.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER + 1, 2 ** 64]) {
    assert.equal(codeOf(() => psiElement(FP_A, 'know', bad, S1)), 'bad-epoch', String(bad));
  }
  assert.equal(codeOf(() => psiElement(FP_A, 'know', 0, S1)), 'no-throw');
  assert.equal(codeOf(() => psiElement(FP_A, 'know', Number.MAX_SAFE_INTEGER, S1)), 'no-throw');
});

test('a secret that is not exactly 32 bytes is refused', () => {
  for (const bad of [new Uint8Array(0), new Uint8Array(31), new Uint8Array(33), new Uint8Array(64), 'x'.repeat(32), null, undefined, [...S1]]) {
    assert.equal(codeOf(() => psiElement(FP_A, 'know', 1, bad as unknown as Uint8Array)), 'bad-secret', String(bad));
  }
});

test('two layer secrets that come out identical are refused; a source of the wrong width is refused', () => {
  assert.equal(codeOf(() => mintEpochSecrets(() => S1.slice())), 'secrets-not-independent');
  assert.equal(codeOf(() => mintEpochSecrets((n) => new Uint8Array(n - 1))), 'bad-secret');
  assert.equal(codeOf(() => mintEpochSecrets(() => 'x' as unknown as Uint8Array)), 'bad-secret');
});

// ── separation ──────────────────────────────────────────────────────────────────────────────────────────────

test('the same secret bytes give different elements at the two layers (the layer is in the key material)', () => {
  assert.notEqual(hex(psiElement(FP_A, 'know', 0, S1)), hex(psiElement(FP_A, 'trust', 0, S1)));
});

test('a different epoch, fingerprint or secret gives a different element; the same inputs give the same one', () => {
  const base = hex(psiElement(FP_A, 'know', 0, S1));
  assert.notEqual(base, hex(psiElement(FP_A, 'know', 1, S1)));
  assert.notEqual(base, hex(psiElement(FP_B, 'know', 0, S1)));
  assert.notEqual(base, hex(psiElement(FP_A, 'know', 0, S2)));
  assert.equal(base, hex(psiElement(FP_A, 'know', 0, S1.slice())));
  assert.equal(psiElement(FP_A, 'know', 0, S1).length, 32);
});

test('one flipped bit of the secret changes the element', () => {
  const s = S1.slice();
  s[31] ^= 1;
  assert.notEqual(hex(psiElement(FP_A, 'trust', 5, S1)), hex(psiElement(FP_A, 'trust', 5, s)));
});

test('minted secrets are two different 32-byte values and are copies the caller cannot alias', () => {
  const m = mintEpochSecrets();
  assert.equal(m.know.length, EPOCH_SECRET_LEN);
  assert.equal(m.trust.length, EPOCH_SECRET_LEN);
  assert.notEqual(hex(m.know), hex(m.trust));
  const shared = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  let n = 0;
  const m2 = mintEpochSecrets(() => (n++ === 0 ? shared : S2.slice()));
  shared[0] = 255;
  assert.equal(m2.know[0], 1, 'the minted value must not alias the source buffer');
});

test('the element is not the bare-fingerprint point, for either layer', () => {
  const bare = hex(hashFingerprintToPoint(FP_A));
  for (const layer of PSI_LAYERS) assert.notEqual(hex(psiElement(FP_A, layer, 0, S1)), bare);
});

test('the element works as an x25519 u-coordinate, where the bare point is used today', () => {
  const scalar = Uint8Array.from({ length: 32 }, (_, i) => 7 * i + 3);
  for (const layer of PSI_LAYERS) {
    const shared = x25519.getSharedSecret(scalar, psiElement(FP_A, layer, 3, S1));
    assert.equal(shared.length, 32);
  }
});

// ── known answers (python reference) ────────────────────────────────────────────────────────────────────────

const KAT: Array<[string, string, PsiLayer, number, Uint8Array, string]> = [
  ['know e=0 S1', FP_A, 'know', 0, S1, '80081d51ff00b1a368615005db419ce61f073b0e001f2e2c36f1fac9b8661b78'],
  ['trust e=0 S1', FP_A, 'trust', 0, S1, '6ddff8f3cfa5833d0c8be3770725da6a7873e3893b116ab6e9fbbe50bb72dc63'],
  ['know e=1 S1', FP_A, 'know', 1, S1, '1d837536690ed7a250acd5aac21e6a8d02bd8d03773a7d89f4b7eb903428853e'],
  ['know e=2^40+7 S2', FP_A, 'know', 2 ** 40 + 7, S2, '47451c8e3f5e11b871c227425a4eb479d7335347be6512ac5967f56cfca19d84'],
  ['know e=0 S1 other fp', FP_B, 'know', 0, S1, '9c03eaa570abd03c598fb0bed0fba25f423b229b37495891c0857a7ece8e64ee'],
];

// Framing: LP counts BYTES as a uint32 big-endian prefix (the pin in lp-tlv.ts). A u16 prefix, or a character count, fails here.
// Vectors from the python reference: sha256 of the whole LP(x) = prefix || x.
const FRAMING: Array<[string, Uint8Array, string, string]> = [
  ['empty', new Uint8Array(0), '00000000', 'df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119'],
  ['one byte 0xab', Uint8Array.of(0xab), '00000001', '319429560f6655d9905d7ce93edc3933301b6a63d4eb05f64ff63609d11ddb3f'],
  ['256 bytes of 0xab', new Uint8Array(256).fill(0xab), '00000100', '1fd27cf8e79d67c8d92763c9b595cd46a54ef3b7b430209d5f446c1973828e03'],
  ['65536 bytes of 0x01', new Uint8Array(65536).fill(1), '00010000', 'cd8cf72e8dd8da0fc3bc209efa621e52a5e586a7db88504cec6a595c4012857b'],
];

test('LP framing is a uint32 big-endian BYTE count, pinned against the python reference', () => {
  for (const [name, bytes, prefix, shaOfLp] of FRAMING) {
    const framed = lpBin(bytes);
    assert.equal(hex(framed.slice(0, 4)), prefix, name);
    assert.equal(framed.length, 4 + bytes.length, name);
    assert.equal(createHash('sha256').update(framed).digest('hex'), shaOfLp, name);
  }
  // A string with a non-ASCII character: 2 characters, 5 bytes. A character-count or u16 implementation differs.
  const s = 'é€';
  assert.equal(s.length, 2);
  assert.equal(hex(lpStr(s).slice(0, 4)), '00000005');
  assert.equal(createHash('sha256').update(lpStr(s)).digest('hex'), 'aaf3d558a70c78857c1407097d8c55b7b4491f3270dcc57980afd6c74e1f1ae0');
});

test('known answers agree with the independent python reference', () => {
  assert.equal(FP_A, 'd4ee8e51f0109341808b418f37f9aa1a1d9553dac333449ce14d7d855e91db9e');
  for (const [name, fp, layer, epoch, secret, want] of KAT) {
    assert.equal(hex(psiElement(fp, layer, epoch, secret)), want, name);
    assert.deepEqual(hexToBytes(want).length, 32);
  }
});
