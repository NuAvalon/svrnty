// A present-but-empty / non-string pq_signature must never verify (Apollo N12 F-2, Flint class fix).
// Before: verifyWithEnvelope picked the suite and acceptClassicalOnly by TRUTHINESS, so {classical, pq_signature: ''}
// verified as a classical-only signature. A caller whose PQ-required gate was `typeof pq_signature === 'string'`
// let a classical-key-only attacker through. The chokepoint now refuses the shape itself.
// Run: npx tsx --test src/lib/crypto/sign-envelope.empty-pq.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from 'openpgp';
import { signWithEnvelope, verifyWithEnvelope, type EnvelopeSignature } from './sign-envelope';
import { generateSigningKeypair } from './pq';

const DOMAIN = 'svrnty:test-empty-pq:v1';
const INPUT = '{"a":1}';
const pass = 'pw-under-test';
let priv: string, pub: string;
let pq: ReturnType<typeof generateSigningKeypair>;

before(async () => {
  ({ privateKey: priv, publicKey: pub } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'T', email: 't@example.test' }], passphrase: pass, format: 'armored',
  }));
  pq = generateSigningKeypair();
});

test('control: a classical signature (no pq_signature field) still verifies', async () => {
  const sig = await signWithEnvelope(DOMAIN, INPUT, priv, pass);
  assert.equal(sig.pq_signature, undefined);
  assert.equal(await verifyWithEnvelope(DOMAIN, INPUT, sig, pub), true);
  assert.equal(await verifyWithEnvelope(DOMAIN, INPUT, sig, pub, pq.publicKey), true);
});

test('control: a hybrid signature verifies', async () => {
  const sig = await signWithEnvelope(DOMAIN, INPUT, priv, pass, pq.secretKey);
  assert.ok(sig.pq_signature);
  assert.equal(await verifyWithEnvelope(DOMAIN, INPUT, sig, pub, pq.publicKey), true);
});

test('NEG: a classical signature carrying pq_signature "" (or a non-string) is refused', async () => {
  const sig = await signWithEnvelope(DOMAIN, INPUT, priv, pass);
  for (const bad of ['', null, false, 0, {}, []] as unknown[]) {
    const forged = { classical: sig.classical, pq_signature: bad } as unknown as EnvelopeSignature;
    assert.equal(await verifyWithEnvelope(DOMAIN, INPUT, forged, pub), false, `pq_signature=${JSON.stringify(bad)}`);
    assert.equal(await verifyWithEnvelope(DOMAIN, INPUT, forged, pub, pq.publicKey), false, `pq_signature=${JSON.stringify(bad)} (pq key given)`);
  }
});

test('explicit undefined is the same as absent (classical)', async () => {
  const sig = await signWithEnvelope(DOMAIN, INPUT, priv, pass);
  assert.equal(await verifyWithEnvelope(DOMAIN, INPUT, { classical: sig.classical, pq_signature: undefined }, pub), true);
});
