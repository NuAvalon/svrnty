// The signer for a portal sign-request (spec v0.7 §8; Flint #996 Q2/Q4/Q6; Archie #994).
// Run: npx --no-install tsx --test src/lib/compose/compose-sign.test.ts
// Real OpenPGP, a freshly generated throwaway key; the bytes it must sign are rebuilt HERE from the fixture's objects, independently of the module.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKey, readKey } from 'openpgp';
import { signWithEnvelope } from '../crypto/sign-envelope';
import { DOMAIN_LOOM_POST, DOMAIN_LOOM_TASK } from '../format/envelope';
import { buildSignedBytes } from '../crypto/sign-envelope';
import { composeSignedBytes, jcs } from './compose-rules';
import { signComposeRequest, verifyComposePacket, type SignDeps } from './compose-sign';

const fx = JSON.parse(readFileSync(join(__dirname, 'compose-vectors-v1.json'), 'utf8'));
const NOW = new Date('2026-10-25T03:02:00.000Z');
const POST = fx.preimage[0].object as Record<string, string>;
const HOSTILE = fx.preimage[1].object as Record<string, string>;
const TASK = fx.preimage[2].object as Record<string, string>;
const PASS = 'compose-sign-test';

let identity: { privateKeyArmored: string; passphrase: string };
let pub: Awaited<ReturnType<typeof readKey>>;
before(async () => {
  const k = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'compose-test' }], passphrase: PASS, format: 'armored' });
  identity = { privateKeyArmored: k.privateKey, passphrase: PASS };
  pub = await readKey({ armoredKey: k.publicKey });
});

test('signs a post: {object, sig_packet_b64}; the packet verifies DETACHED over the bytes rebuilt from the object; the object comes back unchanged', async () => {
  const r = await signComposeRequest(POST, NOW, identity);
  assert.equal(r.ok, true);
  if (!r.ok) return;
  assert.equal(r.signed.kind, 'post');
  assert.equal(r.signed.suite, 'ed25519');
  assert.deepEqual(r.signed.object, POST);
  assert.notEqual(r.signed.object, POST, 'a fresh copy');
  assert.match(r.signed.sig_packet_b64, /^[A-Za-z0-9+/]+=*$/);
  const bytes = composeSignedBytes('post', 'ed25519', POST);
  assert.equal(await verifyComposePacket(pub, r.signed.sig_packet_b64, bytes), true);
  // The packet is the small detached form, not the ~4.8 KB attached message (fits a URL fragment).
  assert.ok(r.signed.sig_packet_b64.length < 400, `packet is ${r.signed.sig_packet_b64.length} chars`);
});

test('signs the hostile-JSON post and the task; the task signs under the TASK domain and nothing else verifies it', async () => {
  for (const [obj, kind, domain, other] of [
    [HOSTILE, 'post', DOMAIN_LOOM_POST, DOMAIN_LOOM_TASK],
    [TASK, 'task', DOMAIN_LOOM_TASK, DOMAIN_LOOM_POST],
  ] as const) {
    const r = await signComposeRequest(obj, NOW, identity);
    assert.equal(r.ok, true, kind);
    if (!r.ok) continue;
    assert.equal(r.signed.kind, kind);
    const canonical = jcs(obj);
    assert.equal(await verifyComposePacket(pub, r.signed.sig_packet_b64, buildSignedBytes(domain, 'ed25519', canonical)), true, `${kind}: own domain`);
    assert.equal(await verifyComposePacket(pub, r.signed.sig_packet_b64, buildSignedBytes(other, 'ed25519', canonical)), false, `${kind}: other loom domain`);
    assert.equal(await verifyComposePacket(pub, r.signed.sig_packet_b64, buildSignedBytes('svrnty:identity-card:v1', 'ed25519', canonical)), false, `${kind}: card domain`);
    assert.equal(await verifyComposePacket(pub, r.signed.sig_packet_b64, buildSignedBytes(domain, 'ed25519+ml-dsa-87', canonical)), false, `${kind}: other suite`);
    assert.equal(await verifyComposePacket(pub, r.signed.sig_packet_b64, buildSignedBytes(domain, 'ed25519', canonical.replace(/.$/, ' }'))), false, `${kind}: tampered`);
  }
});

test('a request the validator refuses is NEVER signed: the signer is not even called', async () => {
  let calls = 0;
  const deps: SignDeps = { sign: (async (...a: Parameters<typeof signWithEnvelope>) => (calls++, signWithEnvelope(...a))) as typeof signWithEnvelope };
  for (const [bad, why] of [
    [{ ...POST, body: 'pe​ter' }, 'zero-width'],
    [{ ...POST, body: 'a‮b' }, 'bidi'],
    [{ ...POST, extra: 'x' }, 'unknown field'],
    [{ ...POST, origin: 'evil.test' }, 'origin'],
    [{ ...POST, body: 'a'.repeat(2901) }, 'over cap'],
    [null, 'not an object'],
  ] as const) {
    const r = await signComposeRequest(bad, NOW, identity, deps);
    assert.equal(r.ok, false, why);
    if (!r.ok) assert.equal(r.reason, 'refused', why);
  }
  assert.equal(calls, 0, 'no refused request reached the signer');
});

test('NEVER SIGN LATE: a card valid when shown is refused at approval time once expires_at has passed (fresh clock, Flint #996 Q6)', async () => {
  let calls = 0;
  const deps: SignDeps = { sign: (async (...a: Parameters<typeof signWithEnvelope>) => (calls++, signWithEnvelope(...a))) as typeof signWithEnvelope };
  const shown = await signComposeRequest(POST, new Date('2026-10-25T03:04:59.000Z'), identity, deps); // valid then
  assert.equal(shown.ok, true);
  calls = 0;
  const late = await signComposeRequest(POST, new Date('2026-10-25T03:05:00.000Z'), identity, deps); // expires_at == now
  assert.equal(late.ok, false);
  if (!late.ok && late.reason === 'refused') assert.equal(late.refusal.code, 'expired');
  else assert.fail('expected a refused/expired result');
  assert.equal(calls, 0);
});

test('a wrong passphrase or a garbage key fails closed with no detail and no packet', async () => {
  for (const id of [{ ...identity, passphrase: 'wrong' }, { privateKeyArmored: 'not a key', passphrase: PASS }]) {
    const r = await signComposeRequest(POST, NOW, id);
    assert.deepEqual(r, { ok: false, reason: 'sign-failed' });
  }
});

test('fails closed when the signature does not cover the bytes WE rebuilt (a signer that signs the wrong domain)', async () => {
  const wrongDomain: SignDeps = { sign: ((_d: string, input: string, k: string, p: string) => signWithEnvelope(DOMAIN_LOOM_TASK, input, k, p)) as typeof signWithEnvelope };
  assert.deepEqual(await signComposeRequest(POST, NOW, identity, wrongDomain), { ok: false, reason: 'literal-mismatch' });
  const wrongInput: SignDeps = { sign: ((d: string, _i: string, k: string, p: string) => signWithEnvelope(d, '{"a":"b"}', k, p)) as typeof signWithEnvelope };
  assert.deepEqual(await signComposeRequest(POST, NOW, identity, wrongInput), { ok: false, reason: 'literal-mismatch' });
});

test('the SELF-VERIFY guard is load-bearing: when the extracted packet does not verify detached, nothing is returned', async () => {
  let asked = 0;
  const failing: SignDeps = { verifyDetached: async () => (asked++, false) };
  assert.deepEqual(await signComposeRequest(POST, NOW, identity, failing), { ok: false, reason: 'self-verify-failed' });
  assert.equal(asked, 1, 'the guard ran exactly once, over the bytes the module rebuilt');
  // Control: with the real verifier the same request succeeds, so the refusal above is the guard and not a broken fixture.
  assert.equal((await signComposeRequest(POST, NOW, identity)).ok, true);
});

test('fails closed on a malformed or foreign-signed attached message', async () => {
  const garbage: SignDeps = { sign: (async () => ({ classical: 'this is not an armored message' })) as unknown as typeof signWithEnvelope };
  assert.deepEqual(await signComposeRequest(POST, NOW, identity, garbage), { ok: false, reason: 'extract-failed' });
  // Signed by a DIFFERENT key: the literal matches but the issuer is not the key we hold.
  const other = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'other' }], passphrase: PASS, format: 'armored' });
  const foreign: SignDeps = { sign: ((d: string, i: string) => signWithEnvelope(d, i, other.privateKey, PASS)) as typeof signWithEnvelope };
  const r = await signComposeRequest(POST, NOW, identity, foreign);
  assert.equal(r.ok, false);
  if (!r.ok) assert.ok(['extract-failed', 'self-verify-failed'].includes(r.reason), r.reason);
});

test('the result carries no key material and no passphrase', async () => {
  const r = await signComposeRequest(POST, NOW, identity);
  assert.equal(r.ok, true);
  const json = JSON.stringify(r);
  assert.doesNotMatch(json, /PRIVATE KEY|BEGIN PGP/);
  assert.equal(json.includes(PASS), false);
  assert.deepEqual(Object.keys((r as { signed: object }).signed).sort(), ['kind', 'object', 'sig_packet_b64', 'suite']);
});
