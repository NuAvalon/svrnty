// In-person confirm and key-rotation pure modules: cases the C-vector red tests do not name (the framing function itself, and the three refusals the builder added).
/* eslint-disable @typescript-eslint/no-explicit-any */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { beaconFrame, hexField, u32Field, keyField } from './beacon-frame';
import { confirmCode, type ConfirmParty } from './beacon-confirm-code';
import { signRotate, verifyRotate, rotateMessage, type RotateStatement } from './beacon-rotate-sig';
import { BEACON_ORDER } from './beacon-key';

const refusedWith = (reasons: string[]) => (e: any) => reasons.includes(e?.reason);
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
// the fixed vector inputs (set v1): xA = sha256('svrnty-vector:x:A') mod (l-1) + 1, and the keys / fingerprints derived from them
const xA = BigInt('1429679130851773782447673504888857434826276299417929053131044593055708132699');
const keyA = 'BruHK2TADJNctDbz2sh6MSI9y5o4swCi/G4Sy/ggNQA=', keyB = 'VNanQR005Tm1ChF0cqpXycAXDuc3Clfn89Rqh0vwJ4c=';
const fpA = '4922c00a578eb6d974790a72911fda284ed387bae6061041c02746072456b497';
const fpB = '66b9f1c3806425db1fabd2cbee1d7b7d3175416a604c93016e2fc24340b2f3ba';
const A: ConfirmParty = { fingerprint: fpA, beaconKey: keyA, generation: 1 };
const B: ConfirmParty = { fingerprint: fpB, beaconKey: keyB, generation: 2 };
const st: RotateStatement = { durableId: 'a4833cbd9ad0f01be7177c057f6bbb9006ab144388be667099db40519b7dd485', identityFingerprint: fpA, oldPk: keyA, oldGen: 1, newPk: 'VNanQR005Tm1ChF0cqpXycAXDuc3Clfn89Rqh0vwJ4c=', newGen: 2 };

test('FRAME: every field is u32 BIG-endian length || bytes; an empty field is a field; a non-bytes field is refused', () => {
  assert.equal(hex(beaconFrame([Uint8Array.of(0x61), Uint8Array.of(0x62, 0x62)])), '00000001' + '61' + '00000002' + '6262');
  assert.equal(hex(beaconFrame([new Uint8Array(0), Uint8Array.of(1)])), '00000000' + '00000001' + '01');
  assert.equal(hex(beaconFrame([])), '');
  assert.throws(() => beaconFrame(['a' as any]), refusedWith(['statement']));
});

test('FRAME: framing is unambiguous: moving a byte between two fields changes the bytes', () => {
  assert.notEqual(hex(beaconFrame([Uint8Array.of(1, 2), Uint8Array.of(3)])), hex(beaconFrame([Uint8Array.of(1), Uint8Array.of(2, 3)])));
});

test('FIELDS: hex is exactly 64 lowercase characters (never normalised); a generation is an integer in [0, 2^31-1]; a key is strict card-form base64', () => {
  assert.equal(hexField(fpA).length, 64);
  for (const bad of [fpA.toUpperCase(), fpA.slice(1), fpA + '0', ' ' + fpA.slice(1), 5, null]) assert.throws(() => hexField(bad), refusedWith(['statement']));
  assert.equal(hex(u32Field(0)), '00000000');
  assert.equal(hex(u32Field(2 ** 31 - 1)), '7fffffff');
  for (const bad of [-1, 2 ** 31, 1.5, NaN, '1', null]) assert.throws(() => u32Field(bad), refusedWith(['statement']));
  assert.equal(keyField(keyA).length, 32);
  for (const bad of [keyA.slice(0, 43), keyA.replace('=', 'A'), 'not base64', 7]) assert.throws(() => keyField(bad), refusedWith(['statement']));
});

test('CONFIRM: a device never builds a code for an own key it does not hold: own.beaconKey that is not the key of x is refused [own-key]', async () => {
  const keyA2 = '6VLM7/vPurEYHoyDQDQPpUMdykT2Z1Z+bt5AjXKHMg0='; // a valid key that is NOT xA's public key (the C-vector's next-generation key)
  await assert.rejects(confirmCode(xA, { ...A, beaconKey: keyA2 }, B, 'ABCDEFGHIJ', 'KLMNOPQR23'), refusedWith(['own-key']));
  assert.equal(await confirmCode(xA, A, B, 'ABCDEFGHIJ', 'KLMNOPQR23'), '739644'); // control: the true own key gives the vector code
});

test('ROTATE: signRotate refuses a secret outside [1, l) [x-range], not with a RangeError', async () => {
  for (const x of [BigInt(0), BEACON_ORDER, BigInt(-1)]) await assert.rejects(signRotate(x, st), refusedWith(['x-range']));
});

test('ROTATE: verifyRotate reports old-key when the OLD key is well-formed but not a valid beacon key (here: a mixed-order point), after the statement check', async () => {
  const mixed = Buffer.from('010000fc647df850245c6e1e12fa0c4a175660a06d11146e0a684cb89c13190c', 'hex').toString('base64');
  const sig = await signRotate(xA, st);
  assert.deepEqual(await verifyRotate({ ...st, oldPk: mixed }, sig), { ok: false, reason: 'old-key' });
});

test('ROTATE: rotateMessage refuses a malformed field with a reason, never returns bytes', () => {
  assert.throws(() => rotateMessage({ ...st, durableId: st.durableId.toUpperCase() }), refusedWith(['statement']));
  assert.throws(() => rotateMessage({ ...st, newGen: 2 ** 31 }), refusedWith(['statement']));
});
