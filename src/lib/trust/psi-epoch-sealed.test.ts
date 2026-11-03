// The plaintext of a sealed epoch package: the 106-byte wire, then the claimed sender fingerprint as 32 raw bytes. Run: npx tsx --test src/lib/trust/psi-epoch-sealed.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildEpochNote, EPOCH_NOTE_LEN } from './psi-epoch-note';
import { buildEpochSealedPlaintext, claimedFpOf, dispatchSealed, epochWireOf, CLAIMED_FP_BYTES, EPOCH_SEALED_LEN } from './psi-epoch-sealed';

const FP_S = createHash('sha256').update('sender').digest('hex');
const FP_R = createHash('sha256').update('receiver').digest('hex');
const S_PAIR = Uint8Array.from({ length: 32 }, (_, i) => 90 + i);
const KNOW = Uint8Array.from({ length: 32 }, (_, i) => i);
const TRUST = Uint8Array.from({ length: 32 }, (_, i) => 32 + i);
const wire = () => buildEpochNote({ sPair: S_PAIR, fpSender: FP_S, fpReceiver: FP_R, epoch: 7, know: KNOW, trust: TRUST });

test('the layout is 106 + 32 = 138 bytes', () => {
  assert.equal(EPOCH_NOTE_LEN, 106);
  assert.equal(CLAIMED_FP_BYTES, 32);
  assert.equal(EPOCH_SEALED_LEN, 138);
});

test('build -> dispatch -> read back: the wire and the fingerprint round-trip, the wire first', () => {
  const w = wire();
  const plain = buildEpochSealedPlaintext(w, FP_S);
  assert.equal(plain.length, 138);
  assert.equal(plain[0], 0x45);
  assert.equal(plain[1], 0x01);
  assert.equal(dispatchSealed(plain), 'epoch');
  assert.deepEqual(epochWireOf(plain), w);
  assert.equal(claimedFpOf(plain), FP_S);
});

test('dispatch: the epoch header with ANY other length is malformed, never epoch and never someone else\'s', () => {
  const plain = buildEpochSealedPlaintext(wire(), FP_S);
  for (const len of [2, 3, 105, 106, 107, 137, 139, 200]) {
    const bytes = new Uint8Array(len);
    bytes.set(plain.slice(0, Math.min(len, plain.length)));
    bytes[0] = 0x45;
    bytes[1] = 0x01;
    assert.equal(dispatchSealed(bytes), 'malformed', `length ${len}`);
  }
});

test('dispatch: anything without the epoch header is OTHER, whatever its length, so no existing package is misrouted', () => {
  const plain = buildEpochSealedPlaintext(wire(), FP_S);
  const otherHeader = plain.slice();
  otherHeader[0] = 0x46;
  assert.equal(dispatchSealed(otherHeader), 'other');
  const secondByte = plain.slice();
  secondByte[1] = 0x02;
  assert.equal(dispatchSealed(secondByte), 'other', 'right type byte, wrong version');
  for (const len of [0, 1, 138, 500]) assert.equal(dispatchSealed(new Uint8Array(len)), 'other', `zeros, length ${len}`);
  assert.equal(dispatchSealed('abc' as unknown as Uint8Array), 'other');
  assert.equal(dispatchSealed(null as unknown as Uint8Array), 'other');
});

test('dispatch reads the length and the first two bytes, and nothing else', () => {
  const plain = buildEpochSealedPlaintext(wire(), FP_S);
  const reads: string[] = [];
  const spy = new Proxy(plain, {
    get(t, p) {
      reads.push(String(p));
      const v = Reflect.get(t, p);
      return typeof v === 'function' ? v.bind(t) : v;
    },
  });
  assert.equal(dispatchSealed(spy), 'epoch');
  const indices = reads.filter((r) => /^\d+$/.test(r));
  assert.ok(indices.every((i) => Number(i) < 2), `touched only indices 0 and 1, got ${indices.join(',')}`);
  assert.ok(reads.includes('length'));
});

test('the accessors refuse a plaintext that is not an epoch one', () => {
  for (const bad of [new Uint8Array(138), wire(), buildEpochSealedPlaintext(wire(), FP_S).slice(0, 137)]) {
    assert.throws(() => epochWireOf(bad), TypeError);
    assert.throws(() => claimedFpOf(bad), TypeError);
  }
});

test('build refuses a wire that is not a 106-byte epoch note, and a fingerprint that is not canonical lowercase 64-hex', () => {
  for (const bad of [new Uint8Array(105), new Uint8Array(106), wire().slice(0, 105), 'x' as unknown as Uint8Array]) {
    assert.throws(() => buildEpochSealedPlaintext(bad, FP_S), TypeError);
  }
  for (const fp of [FP_S.toUpperCase(), FP_S.slice(0, 40), FP_S + '0', FP_S.slice(0, 63) + 'g', '', 5 as unknown as string]) {
    assert.throws(() => buildEpochSealedPlaintext(wire(), fp), TypeError);
  }
});

test('the trailer decodes to LOWERCASE canonical hex, so it can only equal a stored canonical fingerprint exactly', () => {
  const plain = buildEpochSealedPlaintext(wire(), FP_S);
  const fp = claimedFpOf(plain);
  assert.match(fp, /^[0-9a-f]{64}$/);
  assert.equal(fp.length, 64);
});
