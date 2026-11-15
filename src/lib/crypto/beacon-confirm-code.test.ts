/* eslint-disable @typescript-eslint/no-explicit-any -- deliberately wrong inputs */
// Written first, from the spec, before the implementation. Expected values come from an INDEPENDENT stdlib-only Python implementation (not from this code); the fixed inputs are in the cases below.
// Refusal FORM (throw vs result) is the builder's choice except where verifyRotate's result type pins a reason.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { codeFromKey, confirmCode } from './beacon-confirm-code';
import { deriveConfirmKey, CONFIRM_DOMAIN } from './beacon-prover';
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const unhex = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));
// A refusal must carry a reason code (the ProverRefused convention): a bare throw, a TypeError from a bug or a stub must NOT pass.
const refusedWith = (reasons: string[]) => (e: any) => reasons.includes(e?.reason);

const xA = BigInt('1429679130851773782447673504888857434826276299417929053131044593055708132699'), xB = BigInt('1083667101206079933758553604621778006055144098509793385928654015637158298316');
const A = { fingerprint: '4922c00a578eb6d974790a72911fda284ed387bae6061041c02746072456b497', beaconKey: 'BruHK2TADJNctDbz2sh6MSI9y5o4swCi/G4Sy/ggNQA=', generation: 1 };
const B = { fingerprint: '66b9f1c3806425db1fabd2cbee1d7b7d3175416a604c93016e2fc24340b2f3ba', beaconKey: 'VNanQR005Tm1ChF0cqpXycAXDuc3Clfn89Rqh0vwJ4c=', generation: 2 };
const nA = 'ABCDEFGHIJ', nB = 'KLMNOPQR23';
const YB: [bigint, bigint] = [BigInt('16926288214254514817949011900135558519119511059172324594319420696253194025191'), BigInt('3236755430989558926971763721220899002903108600614195421435318453393726887508')];
const T = unhex('000000157376726e74793a3832323a636f6e6669726d3a763100000040343932326330306135373865623664393734373930613732393131666461323834656433383762616536303631303431633032373436303732343536623439370000002006bb872b64c00c935cb436f3dac87a31223dcb9a38b300a2fc6e12cbf8203500000000040000000100000040363662396631633338303634323564623166616264326362656531643762376433313735343136613630346339333031366532666332343334306232663362610000002054d6a7411d34e539b50a117472aa57c9c0170ee7370a57e7f3d46a874bf0278700000004000000020000000a4142434445464748494a0000000a4b4c4d4e4f5051523233');

test('V0 the domain tag is the raw string (it is also the HKDF salt)', () => { assert.equal(CONFIRM_DOMAIN, 'svrnty:822:confirm:v1'); });
test('V1 K-level: codeFromKey(K) = the vector code, no curve involved', () => { assert.equal(codeFromKey(unhex('1ce832fbbcbda857e0b80fad156e34829be84a062128ce15a80de8193c937960')), '739644'); });
test('V2 deriveConfirmKey(xA, YB, T) = the vector K (S = xA*YB, ikm Sx||Sy 32 B BE each)', async () => {
  assert.equal(hex(await deriveConfirmKey(xA, YB, T)), '1ce832fbbcbda857e0b80fad156e34829be84a062128ce15a80de8193c937960'); });
test('V3 both screens show the same code', async () => {
  assert.equal(await confirmCode(xA, A, B, nA, nB), '739644');
  assert.equal(await confirmCode(xB, B, A, nB, nA), '739644'); });
test('V4 codeFromKey: first 5 bytes big-endian mod 10^6, zero-padded', () => {
  const k = new Uint8Array(32); k[4] = 1; assert.equal(codeFromKey(k), '000001');
  k.fill(0xff, 0, 5); assert.equal(codeFromKey(k), '627775'); });
test('V5 codeFromKey refuses a key that is not 32 bytes', () => { assert.throws(() => codeFromKey(new Uint8Array(31)), refusedWith(['key-length'])); });
test('N1 equal nonces refused (a device scanning itself)', async () => { await assert.rejects(confirmCode(xA, A, B, nA, nA), refusedWith(['nonce'])); });
test('N2 a lowercase nonce is refused (the UI uppercases BEFORE the call)', async () => { await assert.rejects(confirmCode(xA, A, B, nA.toLowerCase(), nB), refusedWith(['nonce'])); });
test('N3 a nonce outside base32 A-Z2-7 or not 10 chars is refused', async () => {
  await assert.rejects(confirmCode(xA, A, B, 'ABCDEFGHI1', nB), refusedWith(['nonce'])); await assert.rejects(confirmCode(xA, A, B, 'ABCDEFGHIJK', nB), refusedWith(['nonce'])); });
test('N4 an uppercase-hex fingerprint is refused, never normalised', async () => {
  await assert.rejects(confirmCode(xA, { ...A, fingerprint: A.fingerprint.toUpperCase() }, B, nA, nB), refusedWith(['statement'])); });
test('N5 equal fingerprints refused', async () => { await assert.rejects(confirmCode(xA, A, { ...B, fingerprint: A.fingerprint }, nA, nB), refusedWith(['statement'])); });
test('N6 a generation out of range refused (2^31, -1, 1.5)', async () => {
  for (const g of [2 ** 31, -1, 1.5]) await assert.rejects(confirmCode(xA, { ...A, generation: g }, B, nA, nB), refusedWith(['statement'])); });
test('N7 the own key as the held key is refused (same reason path as the deposit)', async () => { await assert.rejects(confirmCode(xA, A, { ...B, beaconKey: A.beaconKey }, nA, nB), refusedWith(['y-self', 'own-key'])); });
test('N8 a held generation mislabelled gives a DIFFERENT code', async () => {
  assert.notEqual(await confirmCode(xA, A, { ...B, generation: B.generation + 1 }, nA, nB), '739644'); });
test('N9 one changed nonce gives a different code', async () => { assert.notEqual(await confirmCode(xA, A, B, nA, 'KLMNOPQR24'), '739644'); });
test('N10 a non-canonical card key (y >= p) is refused', async () => {
  await assert.rejects(confirmCode(xA, A, { ...B, beaconKey: 'AQAA8JP14UORcLl5SOgzKF1YgYG2RVC4KaAx4XJOZDA=' }, nA, nB), refusedWith(['encoding'])); });
test('N11 the NEGATED held key (sign bit flipped: a valid, different key) gives a DIFFERENT code', async () => {
  const k = Buffer.from(B.beaconKey, 'base64'); k[31] ^= 0x80; assert.notEqual(await confirmCode(xA, A, { ...B, beaconKey: k.toString('base64') }, nA, nB), '739644'); });
