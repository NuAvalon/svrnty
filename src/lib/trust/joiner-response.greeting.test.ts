// Unit tests for the pre-gate 1-greeting (Peter #175594 / Flint security spec) — SIGNATURE-LEVEL.
// These verify the one property Flint needs co-verified: the greeting rides joinerResponseSigningInput
// (the canonical SIGNED input), so a content-blind relay cannot inject one into, or alter one on, a
// joiner-response. We check the signature directly (build+sign → verifyWithEnvelope over the signing
// input) rather than the full encrypt→decrypt→verify round-trip — that round-trip has a PRE-EXISTING,
// greeting-unrelated failure on this branch (send-joiner-response.test.ts #1 fails identically with
// these edits stashed), so testing through it would prove nothing about the greeting.
// Run: npx tsx --test src/lib/trust/joiner-response.greeting.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import {
  buildJoinerResponse,
  buildJoinerResponseEnvelope,
  JoinerResponseSignError,
  GREETING_MAX_CHARS,
} from './joiner-response';
import { verifyWithEnvelope } from '../crypto/sign-envelope';
import { DOMAIN_JOINER_RESPONSE, joinerResponseSigningInput } from '../format/envelope';

const pass = 'test-passphrase-greeting';
const CODE = 'GROW-GREET';
let jPriv: string, jPub: string, jFp: string;   // the joiner (signs the response)
let gFp: string;                                 // the giver's fp (binding target)

before(async () => {
  ({ privateKey: jPriv, publicKey: jPub } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Joiner', email: 'joiner@example.test' }], passphrase: pass, format: 'armored',
  }));
  jFp = (await readKey({ armoredKey: jPub })).getFingerprint();
  const { publicKey: gPub } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Giver', email: 'giver@example.test' }], passphrase: pass, format: 'armored',
  });
  gFp = (await readKey({ armoredKey: gPub })).getFingerprint();
});

function args(greeting?: string) {
  return {
    joinerFp: jFp, joinerEpoch: 0, joinerPubKeyArmored: jPub, joinerName: 'Nina',
    giverFp: gFp, inviteNonce: CODE, ts: '2026-10-23T10:00:00.000Z',
    ...(greeting !== undefined ? { greeting } : {}),
  };
}
// Verify a signed response's classical signature exactly as verifyJoinerResponse does internally (step 6).
const sigOk = (envelope: any, signature: any) =>
  verifyWithEnvelope(DOMAIN_JOINER_RESPONSE, joinerResponseSigningInput(envelope), signature, jPub, undefined);

test('WITH greeting: it is in the signed envelope + canonical input, and the signature verifies', async () => {
  const greeting = "hi, I'm Nina — we met at the conference";
  const signed = await buildJoinerResponse(args(greeting), jPriv, pass);
  assert.equal(signed.envelope.greeting, greeting, 'greeting is carried in the envelope');
  assert.ok(joinerResponseSigningInput(signed.envelope).includes(greeting), 'greeting is IN the canonical signed input');
  assert.equal(await sigOk(signed.envelope, signed.signature), true, 'honest signature verifies');
});

test('WITHOUT greeting: omitted (not null) + absent from canonical input (byte-identical = no regression)', async () => {
  const signed = await buildJoinerResponse(args(), jPriv, pass);
  assert.equal('greeting' in signed.envelope, false, 'greeting OMITTED when absent');
  assert.equal(joinerResponseSigningInput(signed.envelope).includes('greeting'), false, 'no greeting key in canonical input');
  assert.equal(await sigOk(signed.envelope, signed.signature), true, 'signature still verifies');
});

test('★ SECURITY: ALTERING the greeting after signing breaks the signature (greeting is in-signature)', async () => {
  const signed = await buildJoinerResponse(args('honest greeting'), jPriv, pass);
  assert.equal(await sigOk(signed.envelope, signed.signature), true, 'baseline honest sig verifies');
  signed.envelope.greeting = 'ALTERED IN TRANSIT BY THE RELAY';
  assert.equal(await sigOk(signed.envelope, signed.signature), false, 'a tampered greeting must fail verification');
});

test('★ SECURITY: INJECTING a greeting into a no-greeting response breaks the signature', async () => {
  const signed = await buildJoinerResponse(args(), jPriv, pass);
  assert.equal(await sigOk(signed.envelope, signed.signature), true, 'baseline no-greeting sig verifies');
  (signed.envelope as any).greeting = 'injected by the content-blind relay';
  assert.equal(await sigOk(signed.envelope, signed.signature), false, 'an injected greeting must fail verification');
});

test('greeting at the cap builds; over-cap throws bad-greeting at BUILD (never signed)', async () => {
  const atCap = 'x'.repeat(GREETING_MAX_CHARS);
  const signed = await buildJoinerResponse(args(atCap), jPriv, pass);
  assert.equal(signed.envelope.greeting, atCap);
  assert.equal(await sigOk(signed.envelope, signed.signature), true);

  assert.throws(
    () => buildJoinerResponseEnvelope(args('y'.repeat(GREETING_MAX_CHARS + 1))),
    (e: unknown) => e instanceof JoinerResponseSignError && e.reason === 'bad-greeting',
  );
});

test('a non-string greeting throws bad-greeting at build', () => {
  assert.throws(
    () => buildJoinerResponseEnvelope(args(42 as unknown as string)),
    (e: unknown) => e instanceof JoinerResponseSignError && e.reason === 'bad-greeting',
  );
});
