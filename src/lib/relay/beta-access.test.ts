// src/lib/relay/beta-access.test.ts
// Layer (A) beta-access token — crypto contract (format §1-§3, Apollo's ran-it bars): issuer-signed,
// pinned-issuer trust-root, tamper-reject, exp (omitted=no-expiry, NEVER null), decode fail-closed.
// Non-transferability (token.sub ↔ owner-auth) is exercised at the endpoint (claim-flow test).
// Run: PATH=~/.nvm/versions/node/v22.22.1/bin:$PATH npx tsx --test beta-access.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import {
  signBetaAccessToken,
  verifyBetaAccessToken,
  encodeBetaAccessToken,
  decodeBetaAccessToken,
  type PinnedIssuer,
} from './beta-access';

// The ISSUER (Peter's beta-gate) + a DIFFERENT key (wrong issuer). Classical ed25519 (the 0.x wire).
let ISSUER: { fp: string; pub: string; priv: string; pass: string };
let OTHER: { fp: string; pub: string; priv: string; pass: string };
async function mkKey(name: string) {
  const pass = `pw-${name}`;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart — 'ed25519' valid at runtime.
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase: pass,
    format: 'armored',
  });
  const fp = (await readKey({ armoredKey: publicKey })).getFingerprint();
  return { fp, pub: publicKey, priv: privateKey, pass };
}
before(async () => { ISSUER = await mkKey('issuer'); OTHER = await mkKey('other'); });

function pinned(): PinnedIssuer { return { fingerprint: ISSUER.fp, publicKeyArmored: ISSUER.pub }; }
const SUB = 'a'.repeat(64); // a canonical redeemer fp (opaque to the token-level checks)
const T0 = 1_760_000_000_000; // fixed epoch ms (integer) — canonicalize forbids floats

test('sign → verify round-trip (no expiry = exp omitted)', async () => {
  const tok = await signBetaAccessToken({ iss: ISSUER.fp, sub: SUB, jti: 'deadbeef', iat: T0 }, ISSUER.priv, ISSUER.pass);
  assert.equal(tok.exp, undefined, 'no-expiry → exp field is ABSENT, never null');
  assert.deepEqual(await verifyBetaAccessToken(tok, pinned(), T0 + 1000), { ok: true });
  // wire round-trips (base64url) and the decoded token still verifies.
  const decoded = decodeBetaAccessToken(encodeBetaAccessToken(tok));
  assert.ok(decoded);
  assert.deepEqual(await verifyBetaAccessToken(decoded!, pinned(), T0 + 1000), { ok: true });
});

test('tampered sub → bad-sig (beneficiary is cryptographically bound)', async () => {
  const tok = await signBetaAccessToken({ iss: ISSUER.fp, sub: SUB, jti: 'j1', iat: T0 }, ISSUER.priv, ISSUER.pass);
  const tampered = { ...tok, sub: 'b'.repeat(64) };
  assert.deepEqual(await verifyBetaAccessToken(tampered, pinned(), T0 + 1000), { ok: false, reason: 'bad-sig' });
});

test('wrong issuer fp (token.iss != pinned) → bad-issuer', async () => {
  const tok = await signBetaAccessToken({ iss: OTHER.fp, sub: SUB, jti: 'j2', iat: T0 }, OTHER.priv, OTHER.pass);
  // token is validly self-signed by OTHER, but OTHER is not the pinned issuer.
  assert.deepEqual(await verifyBetaAccessToken(tok, pinned(), T0 + 1000), { ok: false, reason: 'bad-issuer' });
});

test('right iss claim but signed by the wrong key → bad-sig (pin is the trust root)', async () => {
  // An attacker claims iss=ISSUER but signs with OTHER's key → sig fails against the pinned ISSUER pubkey.
  const tok = await signBetaAccessToken({ iss: ISSUER.fp, sub: SUB, jti: 'j3', iat: T0 }, OTHER.priv, OTHER.pass);
  assert.deepEqual(await verifyBetaAccessToken(tok, pinned(), T0 + 1000), { ok: false, reason: 'bad-sig' });
});

test('expired token → expired; future exp → ok', async () => {
  const past = await signBetaAccessToken({ iss: ISSUER.fp, sub: SUB, jti: 'j4', iat: T0, exp: T0 + 1000 }, ISSUER.priv, ISSUER.pass);
  assert.equal(past.exp, T0 + 1000, 'exp present = integer epoch ms');
  assert.deepEqual(await verifyBetaAccessToken(past, pinned(), T0 + 2000), { ok: false, reason: 'expired' });
  assert.deepEqual(await verifyBetaAccessToken(past, pinned(), T0 + 500), { ok: true }, 'before exp = ok');
});

test('decode fail-closed: malformed / null-exp / wrong-typ → null', async () => {
  const good = await signBetaAccessToken({ iss: ISSUER.fp, sub: SUB, jti: 'j5', iat: T0 }, ISSUER.priv, ISSUER.pass);
  assert.ok(decodeBetaAccessToken(encodeBetaAccessToken(good)));
  // null exp is INVALID (canonicalize never signs null) → reject at decode.
  const withNullExp = Buffer.from(JSON.stringify({ ...good, exp: null })).toString('base64url');
  assert.equal(decodeBetaAccessToken(withNullExp), null, 'exp:null → rejected');
  // wrong typ
  const wrongTyp = Buffer.from(JSON.stringify({ ...good, typ: 'svrnty:note:v0' })).toString('base64url');
  assert.equal(decodeBetaAccessToken(wrongTyp), null, 'wrong typ → rejected');
  // missing jti
  const noJti = { ...good } as Record<string, unknown>; delete noJti.jti;
  assert.equal(decodeBetaAccessToken(Buffer.from(JSON.stringify(noJti)).toString('base64url')), null, 'missing jti → rejected');
  // garbage
  assert.equal(decodeBetaAccessToken('not-base64url-$$$'), null);
  assert.equal(decodeBetaAccessToken(''), null);
});
