/* eslint-disable @typescript-eslint/no-explicit-any -- deliberately wrong inputs */
// Written first, from the spec, before the implementation. Expected values come from an INDEPENDENT stdlib-only Python implementation (not from this code); the fixed inputs are in the cases below.
// Refusal FORM (throw vs result) is the builder's choice except where verifyRotate's result type pins a reason.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { rotateMessage, signRotate, verifyRotate } from './beacon-rotate-sig';
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const unhex = (h: string) => new Uint8Array(Buffer.from(h, 'hex'));
// A refusal must carry a reason code (the ProverRefused convention): a bare throw, a TypeError from a bug or a stub must NOT pass.
const refusedWith = (reasons: string[]) => (e: any) => reasons.includes(e?.reason);

const xA = BigInt('1429679130851773782447673504888857434826276299417929053131044593055708132699'), xB = BigInt('1083667101206079933758553604621778006055144098509793385928654015637158298316');
const st = { durableId: 'a4833cbd9ad0f01be7177c057f6bbb9006ab144388be667099db40519b7dd485', identityFingerprint: '4922c00a578eb6d974790a72911fda284ed387bae6061041c02746072456b497', oldPk: 'BruHK2TADJNctDbz2sh6MSI9y5o4swCi/G4Sy/ggNQA=', oldGen: 1,
  newPk: '6VLM7/vPurEYHoyDQDQPpUMdykT2Z1Z+bt5AjXKHMg0=', newGen: 2 };
const SIG = '27184441a7a2ccf87664aa1ad36865d102c35f81365e3753986a3aebdf53ce8394399ebcfeb59bf412a17ed6692dc195e529efac0b023f0b5be0a2fe9fc25503';

test('R1 rotateMessage = the vector M (every field LP-framed, tag included)', () => { assert.equal(hex(rotateMessage(st)), '000000177376726e74793a626561636f6e2d726f746174653a7631000000406134383333636264396164306630316265373137376330353766366262623930303661623134343338386265363637303939646234303531396237646434383500000040343932326330306135373865623664393734373930613732393131666461323834656433383762616536303631303431633032373436303732343536623439370000002006bb872b64c00c935cb436f3dac87a31223dcb9a38b300a2fc6e12cbf8203500000000040000000100000020e952cceffbcfbab1181e8c8340340fa5431dca44f667567e6ede408d7287320d0000000400000002'); });
test('R2 signRotate is deterministic and equals the vector', async () => {
  assert.equal(hex(await signRotate(xA, st)), SIG); assert.equal(hex(await signRotate(xA, st)), SIG); });
test('R3 verifyRotate accepts the vector', async () => { assert.deepEqual(await verifyRotate(st, unhex(SIG)), { ok: true }); });
test('R4 signing with a key that is not oldPk is refused', async () => { await assert.rejects(signRotate(xB, st), refusedWith(['old-key'])); });
for (const [f, val] of [['durableId', '0000000000000000000000000000000000000000000000000000000000000000'], ['identityFingerprint', '66b9f1c3806425db1fabd2cbee1d7b7d3175416a604c93016e2fc24340b2f3ba'], ['oldGen', 0], ['newGen', 3],
  ['newPk', 'VNanQR005Tm1ChF0cqpXycAXDuc3Clfn89Rqh0vwJ4c='], ['oldPk', 'VNanQR005Tm1ChF0cqpXycAXDuc3Clfn89Rqh0vwJ4c=']] as const) {
  test(`R5 a changed ${f} -> mismatch`, async () => { assert.deepEqual(await verifyRotate({ ...st, [f]: val } as any, unhex(SIG)), { ok: false, reason: 'mismatch' }); });
}
test('R6 s + l refused (no malleable s)', async () => { assert.deepEqual(await verifyRotate(st, unhex('27184441a7a2ccf87664aa1ad36865d102c35f81365e3753986a3aebdf53ce838560bff5da4d0e5c1d8f9f0f221b0041f1541f7dc20a49426014c95a6e4c6209')), { ok: false, reason: 's-range' }); });
test('R7 R outside the prime-order subgroup refused', async () => { assert.deepEqual(await verifyRotate(st, unhex('010000fc647df850245c6e1e12fa0c4a175660a06d11146e0a684cb89c13190c94399ebcfeb59bf412a17ed6692dc195e529efac0b023f0b5be0a2fe9fc25503')), { ok: false, reason: 'r-not-in-subgroup' }); });
test('R8 a 63-byte signature refused', async () => { assert.deepEqual(await verifyRotate(st, unhex(SIG).slice(0, 63)), { ok: false, reason: 'sig-length' }); });
test('R9 a malformed statement field is refused BEFORE curve math', async () => {
  for (const bad of [{ durableId: st.durableId.toUpperCase() }, { identityFingerprint: 'xyz' }, { oldGen: 2 ** 31 }, { newPk: 'AAAA' }])
    assert.deepEqual(await verifyRotate({ ...st, ...bad } as any, unhex(SIG)), { ok: false, reason: 'statement' }); });
test('R10 the sig moved onto another rotation (next step of the chain) -> mismatch', async () => {
  assert.deepEqual(await verifyRotate({ ...st, oldPk: st.newPk, oldGen: 2, newPk: 'VNanQR005Tm1ChF0cqpXycAXDuc3Clfn89Rqh0vwJ4c=', newGen: 3 }, unhex(SIG)), { ok: false, reason: 'mismatch' }); });
