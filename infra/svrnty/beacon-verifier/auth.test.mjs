// Run: cd infra/svrnty/beacon-verifier && node --test auth.test.mjs
// Poll / withdraw authentication: K = Poseidon(DS_K, pk_lo, pk_hi) from the ONE shared module, strict Ed25519, a signed message
// that names its op, and the CLI contract the satellite parses. Every refusal of a well-formed request says "auth", never which
// check failed, so the reason can't be used as an oracle.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign as edSign, verify as edVerify, createPublicKey, randomBytes } from 'node:crypto';
import { mkdtempSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildPoseidon } from 'circomlibjs';
import { verifyAuth, parseAuthRequest, decodePoint, isSmallOrder, L, SMALL_ORDER_HEX } from './auth.mjs';
import { DS_K, K_TAG, AUTH_OPS, asciiTag, be32, pkSplit, kInputs, authMessage, R } from './beacon-wire.mjs';

const AUTH = new URL('./auth.mjs', import.meta.url).pathname;
// Apollo's THROWAWAY kat.json (588_throwaway_fixtures_20261107, sha256 bd67ef7a812a503b...): public test values, no secrets.
const KAT = {
  pk_bytes_hex: 'ffa69aab8cd4c189edd09a1c087b01deb2c9e7e3c5b048087eabd47607ace03d',
  pk_lo: '237650938200873518050230347192456765501',
  pk_hi: '339818197286350188883071988108430606814',
  K: '18629810049334873507088104396865441044207083993585906873288897659141478852963',
  DS_K: '599516529259421656039233470003312177',
};
const P = await buildPoseidon();
const kOf = (pk) => P.F.toObject(P(kInputs(pk)));
const hex = (b) => Buffer.from(b).toString('hex');
const BASE_HEX = '5866666666666666666666666666666666666666666666666666666666666666';   // the Ed25519 base point B
const H_E = 123456789012345678901234567890n;
const N_A = 987654321098765432109876543210n;

function keypair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return { privateKey, pk: Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url') };
}
/** A request as a client would build it: sign authMessage(signOp ?? op, ...) with the key. Overrides for the NEGs. */
function req(kp, o = {}) {
  const nonce = o.nonce ?? randomBytes(32);
  const msg = authMessage(o.signOp ?? o.op ?? 'poll', o.signH_e ?? H_E, o.signN ?? N_A, o.signNonce ?? nonce);
  const sig = o.sig ?? edSign(null, msg, kp.privateKey);
  return { op: o.op ?? 'poll', H_e: String(o.H_e ?? H_E), N: String(o.N ?? N_A), K: String(o.K ?? kOf(kp.pk)),
    pk: o.pkHex ?? hex(kp.pk), sig: hex(sig), nonce: hex(nonce) };
}
const verdict = (r) => verifyAuth(r, { poseidon: P });

// ---- the shared module (the prover imports the same functions) ----
test('K encoding: DS_K, the numeric big-endian pk split and K reproduce the KAT vector', () => {
  assert.equal(asciiTag(K_TAG), DS_K);
  assert.equal(DS_K.toString(), KAT.DS_K);
  const pk = Buffer.from(KAT.pk_bytes_hex, 'hex');
  const { lo, hi } = pkSplit(pk);
  assert.equal(lo.toString(), KAT.pk_lo);
  assert.equal(hi.toString(), KAT.pk_hi);
  assert.deepEqual(kInputs(pk), [DS_K, lo, hi]);
  assert.equal(kOf(pk).toString(), KAT.K);
});

test('NEG: a little-endian reader of the same 32 bytes gives a DIFFERENT K (the byte-order trap)', () => {
  const pk = Buffer.from(KAT.pk_bytes_hex, 'hex');
  const le = Buffer.from(pk).reverse();
  assert.notEqual(kOf(le).toString(), KAT.K);
});

test('asciiTag / pkSplit refuse bad input', () => {
  assert.throws(() => asciiTag('x'.repeat(31)));          // must stay < 31 bytes (one field element)
  assert.throws(() => asciiTag('svrnty:588:k:vé'));        // ASCII only
  assert.throws(() => asciiTag(''));
  assert.throws(() => pkSplit(new Uint8Array(31)));
  assert.throws(() => pkSplit('ff'.repeat(32)));           // bytes, not a hex string
});

test('authMessage = op tag || H_e || N || nonce, each 32-byte big-endian; poll and withdraw never share bytes', () => {
  const nonce = Buffer.alloc(32, 7);
  const m = authMessage('poll', 1n, 2n, nonce);
  assert.equal(hex(m), hex(Buffer.from(AUTH_OPS.poll, 'ascii')) + hex(be32(1n)) + hex(be32(2n)) + hex(nonce));
  assert.equal(m.length, AUTH_OPS.poll.length + 96);
  assert.equal(hex(be32(258n)), '00'.repeat(30) + '0102');
  const w = authMessage('withdraw', 1n, 2n, nonce);
  assert.notEqual(hex(w), hex(m));
  assert.throws(() => authMessage('Poll', 1n, 2n, nonce));
  assert.throws(() => authMessage('poll', R, 2n, nonce));   // >= r
  assert.throws(() => authMessage('poll', -1n, 2n, nonce));
  assert.throws(() => authMessage('poll', 1n, 2n, Buffer.alloc(31)));
});

// ---- auth.mjs ----
test('honest poll and honest withdraw are accepted', async () => {
  const kp = keypair();
  assert.deepEqual(await verdict(req(kp)), { ok: true });
  assert.deepEqual(await verdict(req(kp, { op: 'withdraw' })), { ok: true });
});

test('NEG: a poll signature replayed as a withdraw (and the reverse) is refused', async () => {
  const kp = keypair();
  assert.deepEqual(await verdict(req(kp, { op: 'withdraw', signOp: 'poll' })), { ok: false, reason: 'auth' });
  assert.deepEqual(await verdict(req(kp, { op: 'poll', signOp: 'withdraw' })), { ok: false, reason: 'auth' });
});

test('NEG: K must be Poseidon(DS_K, pk): another key\'s K, K+1, and K from the LE split are refused', async () => {
  const kp = keypair();
  const other = keypair();
  assert.deepEqual(await verdict(req(kp, { K: kOf(other.pk) })), { ok: false, reason: 'auth' });
  assert.deepEqual(await verdict(req(kp, { K: (kOf(kp.pk) + 1n) % R })), { ok: false, reason: 'auth' });
  assert.deepEqual(await verdict(req(kp, { K: kOf(Buffer.from(kp.pk).reverse()) })), { ok: false, reason: 'auth' });
});

test('NEG: the signature binds H_e, N and the nonce', async () => {
  const kp = keypair();
  assert.deepEqual(await verdict(req(kp, { signH_e: H_E + 1n })), { ok: false, reason: 'auth' });
  assert.deepEqual(await verdict(req(kp, { signN: N_A + 1n })), { ok: false, reason: 'auth' });
  assert.deepEqual(await verdict(req(kp, { signNonce: Buffer.alloc(32, 1) })), { ok: false, reason: 'auth' });
});

test('NEG: a signature with S >= L (S + L, same point) is refused', async () => {
  const kp = keypair();
  const good = req(kp);
  const sig = Buffer.from(good.sig, 'hex');
  const S = BigInt('0x' + Buffer.from(sig.subarray(32)).reverse().toString('hex')) + L;
  assert.ok(S < 2n ** 256n);
  const sBytes = Buffer.from(S.toString(16).padStart(64, '0'), 'hex').reverse();
  const bad = { ...good, sig: hex(Buffer.concat([sig.subarray(0, 32), sBytes])) };
  assert.deepEqual(await verdict(bad), { ok: false, reason: 'auth' });
});

test('small-order list: 8 distinct canonical points, each of order dividing 8; B and real keys are not small', () => {
  assert.equal(SMALL_ORDER_HEX.length, 8);
  const pts = SMALL_ORDER_HEX.map((h) => decodePoint(Buffer.from(h, 'hex')));
  for (const [i, pt] of pts.entries()) {
    assert.ok(pt, `small-order #${i} decodes`);
    assert.equal(isSmallOrder(pt), true, `small-order #${i}`);
  }
  assert.equal(new Set(pts.map((p) => `${p[0]},${p[1]}`)).size, 8);
  assert.equal(isSmallOrder(decodePoint(Buffer.from(BASE_HEX, 'hex'))), false);
  assert.equal(isSmallOrder(decodePoint(keypair().pk)), false);
});

test('NEG (forgery): with the identity as pk, node:crypto alone ACCEPTS a message-independent signature; auth.mjs refuses', async () => {
  const idPk = Buffer.from(SMALL_ORDER_HEX[0], 'hex');           // the identity point, order 1
  const forged = Buffer.concat([Buffer.from(BASE_HEX, 'hex'), Buffer.from('01' + '00'.repeat(31), 'hex')]);   // R = B, S = 1
  const nonce = randomBytes(32);
  const msg = authMessage('poll', H_E, N_A, nonce);
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: idPk.toString('base64url') }, format: 'jwk' });
  // Why the small-order check exists: OpenSSL checks S < L but not the order of A, so this verifies for ANY message.
  assert.equal(edVerify(null, msg, key, forged), true);
  const r = { op: 'poll', H_e: String(H_E), N: String(N_A), K: String(kOf(idPk)), pk: hex(idPk), sig: hex(forged), nonce: hex(nonce) };
  assert.deepEqual(await verdict(r), { ok: false, reason: 'auth' });
});

test('NEG: non-canonical public keys are refused (y >= p; x = 0 with the sign bit set)', async () => {
  const p = 2n ** 255n - 19n;
  const yP = Buffer.from((p + 1n).toString(16).padStart(64, '0'), 'hex').reverse();   // y = p + 1 (aliases y = 1)
  assert.equal(decodePoint(yP), null);
  const negZero = Buffer.from(SMALL_ORDER_HEX[0], 'hex');
  negZero[31] |= 0x80;                                                               // y = 1, x = 0, sign bit 1
  assert.equal(decodePoint(negZero), null);
  const kp = keypair();
  for (const pk of [yP, negZero]) {
    assert.deepEqual(await verdict(req(kp, { pkHex: hex(pk), K: kOf(pk) })), { ok: false, reason: 'auth' });
  }
});

test('wire: exact keys, op spelling, canonical decimals below r, lowercase fixed-width hex; else "wire"', () => {
  const kp = keypair();
  const good = req(kp);
  assert.doesNotThrow(() => parseAuthRequest(JSON.stringify(good)));
  const bad = [
    { ...good, extra: '1' }, (({ nonce, ...r }) => r)(good), { ...good, op: 'Poll' }, { ...good, op: 'deposit' },
    { ...good, N: '007' }, { ...good, H_e: R.toString() }, { ...good, K: '-1' }, { ...good, N: 5 },
    { ...good, pk: good.pk.toUpperCase() }, { ...good, sig: good.sig.slice(2) }, { ...good, nonce: good.nonce + '00' },
  ];
  for (const b of bad) assert.throws(() => parseAuthRequest(JSON.stringify(b)), /wire/, JSON.stringify(Object.keys(b)));
  assert.throws(() => parseAuthRequest('not json'), /wire/);
  assert.throws(() => parseAuthRequest('[]'), /wire/);
});

// ---- CLI contract (what beacon_centurion.parse_auth_output accepts) ----
const run = (input, path = AUTH) => spawnSync(process.execPath, [path], { input, encoding: 'utf8', timeout: 30_000 });

test('CLI: accept = exit 0 + exactly {"ok":true}\\n; refused = exit 1 + one reason line; also via a symlinked path', () => {
  const kp = keypair();
  const ok = run(JSON.stringify(req(kp)));
  assert.equal(ok.status, 0);
  assert.equal(ok.stdout, '{"ok":true}\n');
  const no = run(JSON.stringify(req(kp, { op: 'withdraw', signOp: 'poll' })));
  assert.equal(no.status, 1);
  assert.equal(no.stdout, '{"ok":false,"reason":"auth"}\n');
  const junk = run('{"op":"poll"}');
  assert.equal(junk.status, 1);
  assert.equal(junk.stdout, '{"ok":false,"reason":"wire"}\n');
  const dir = mkdtempSync(join(tmpdir(), 'auth-link-'));
  symlinkSync(AUTH, join(dir, 'a.mjs'));
  const viaLink = run(JSON.stringify(req(kp)), join(dir, 'a.mjs'));
  assert.equal(viaLink.status, 0);
  assert.equal(viaLink.stdout, '{"ok":true}\n');
});
