// Run: cd infra/svrnty/beacon-verifier && npm test
// The centurion's verifier: epoch rule, point checks snarkjs doesn't do, the vkey pin, and the CLI contract.
// Valid-proof tests need THROWAWAY fixtures from the rehearsal ($BEACON_FIXTURES: verification_key.json + proof_*.json +
// public_*.json); without them those tests are SKIPPED with a reason, never passed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildBn128 } from 'ffjavascript';
import { epochOk, checkPoints, verifyDeposit, EPOCH_SECONDS, GRACE_SECONDS } from './verify.mjs';
import { R } from '../../../src/lib/crypto/beacon-wire.mjs';

const VERIFY = new URL('./verify.mjs', import.meta.url).pathname;
const WEEK = EPOCH_SECONDS;
const G = GRACE_SECONDS;
const START = 2900 * WEEK;                       // a fixed epoch boundary
const sha = (b) => createHash('sha256').update(b).digest('hex');

test('epoch: cur accepted; cur-1 / cur+1 only inside the grace window; anything else refused', () => {
  assert.equal(EPOCH_SECONDS, 604800);
  assert.equal(GRACE_SECONDS, 600);
  assert.equal(epochOk(2900n, START + 5), true);
  assert.equal(epochOk(2899n, START + G - 1), true);
  assert.equal(epochOk(2899n, START + G + 1), false);                 // grace edge
  assert.equal(epochOk(2901n, START + WEEK - G + 1), true);
  assert.equal(epochOk(2901n, START + WEEK - G - 1), false);          // grace edge
  assert.equal(epochOk(2898n, START + 1), false);
  assert.equal(epochOk(2902n, START + WEEK - 1), false);
});

async function pts() {
  const curve = await buildBn128(true);
  const g1 = curve.G1.toObject(curve.G1.toAffine(curve.G1.g)).slice(0, 2);
  const g2o = curve.G2.toObject(curve.G2.toAffine(curve.G2.g));
  // A point ON the twist curve but OUTSIDE the r-order subgroup (snarkjs's isValid accepts it).
  const F2 = curve.F2;
  let rogue;
  for (let i = 1n; !rogue; i += 1n) {
    const x = F2.fromObject([i, 0n]);
    const rhs = F2.add(F2.mul(F2.square(x), x), curve.G2.b);
    if (!F2.isSquare(rhs)) continue;
    const P = new Uint8Array(F2.n8 * 2);
    P.set(x);
    P.set(F2.sqrt(rhs), F2.n8);
    if (curve.G2.isValid(P) && !curve.G2.isZero(curve.G2.timesScalar(P, R))) rogue = curve.G2.toObject(P).slice(0, 2);
  }
  await curve.terminate();
  return { g1, g2: [g2o[0], g2o[1]], rogue };
}

test('points: generators pass; off-curve G1, identity and an on-curve G2 point outside the subgroup are refused', async () => {
  const { g1, g2, rogue } = await pts();
  const curve = await buildBn128(true);
  try {
    await checkPoints({ pi_a: g1, pi_b: g2, pi_c: g1 }, curve);                          // passes
    const reason = async (p) => checkPoints(p, curve).then(() => 'accepted', (e) => e.reason);
    assert.equal(await reason({ pi_a: [1n, 3n], pi_b: g2, pi_c: g1 }), 'point:pi_a:off-curve');
    assert.equal(await reason({ pi_a: g1, pi_b: g2, pi_c: [0n, 0n] }), 'point:pi_c:identity');      // (0,0) = affine identity
    assert.equal(await reason({ pi_a: g1, pi_b: rogue, pi_c: g1 }), 'point:pi_b:not-in-subgroup');
  } finally {
    await curve.terminate();
  }
});

function run(body, { vkeyPath, vkeySha, now = START + 5, extraArgs = [] } = {}) {
  const r = spawnSync(process.execPath, [VERIFY, '--vkey', vkeyPath, '--vkey-sha256', vkeySha, '--now', String(now),
    ...extraArgs], { input: body, timeout: 60_000 });
  const out = r.stdout.toString().trim();
  return { code: r.status, out: out ? JSON.parse(out) : null, raw: out };
}

async function fakeSetup() {
  const { g1, g2, rogue } = await pts();
  const s = (v) => v.toString(10);
  const P1 = [s(g1[0]), s(g1[1]), '1'];
  const P2 = [g2[0].map(s), g2[1].map(s), ['1', '0']];
  // A vkey with the right SHAPE (generators everywhere), so a well-formed proof reaches the pairing and FAILS it.
  const vkey = { protocol: 'groth16', curve: 'bn128', nPublic: 4, vk_alpha_1: P1, vk_beta_2: P2, vk_gamma_2: P2,
    vk_delta_2: P2, vk_alphabeta_12: [], IC: [P1, P1, P1, P1, P1] };
  const dir = mkdtempSync(join(tmpdir(), 'beacon-verify-test-'));
  const vkeyPath = join(dir, 'vkey.json');
  writeFileSync(vkeyPath, JSON.stringify(vkey));
  const proof = { protocol: 'groth16', curve: 'bn128', pi_a: P1, pi_b: P2, pi_c: P1 };
  const signals = ['2900', '12345', '67890', '424242'];
  return { vkeyPath, vkeySha: sha(readFileSync(vkeyPath)), proof, signals, P1, P2, rogue: [rogue[0].map(s), rogue[1].map(s), ['1', '0']], dir };
}

test('CLI: refusal reasons are codes only, exit 1; the process always exits', async () => {
  const f = await fakeSetup();
  const dep = (o) => JSON.stringify({ proof: f.proof, publicSignals: f.signals, ...o });
  const cases = [
    ['wire (leading zero)', JSON.stringify({ proof: f.proof, publicSignals: ['2900', '012345', '67890', '424242'] }), 'wire'],
    ['wire (5 signals never reach snarkjs)', JSON.stringify({ proof: f.proof, publicSignals: [...f.signals, '1'] }), 'wire'],
    ['wire (slot on the wire)', dep({ slot: '12345' }), 'wire'],
    ['wire (N + r alias)', JSON.stringify({ proof: f.proof, publicSignals: ['2900', '12345', (67890n + R).toString(), '424242'] }), 'wire'],
    ['epoch (old)', JSON.stringify({ proof: f.proof, publicSignals: ['2898', '12345', '67890', '424242'] }), 'epoch'],
    ['point (identity-shaped)', JSON.stringify({ proof: { ...f.proof, pi_c: ['0', '0', '1'] }, publicSignals: f.signals }), 'wire'],
    ['point (outside the subgroup)', JSON.stringify({ proof: { ...f.proof, pi_b: f.rogue }, publicSignals: f.signals }), 'point:pi_b:not-in-subgroup'],
    ['proof (well-formed, fails the pairing)', dep({}), 'proof'],
  ];
  for (const [name, body, reason] of cases) {
    const r = run(body, f);
    assert.equal(r.code, 1, `${name}: exit code`);
    assert.deepEqual(r.out, { ok: false, reason }, name);
    assert.ok(!r.raw.includes('424242'), `${name}: no input echoed`);
  }
});

test('CLI: the vkey pin: a different sha, or a vkey changed after pinning, refuses every deposit', async () => {
  const f = await fakeSetup();
  const body = JSON.stringify({ proof: f.proof, publicSignals: f.signals });
  assert.deepEqual(run(body, { ...f, vkeySha: '0'.repeat(64) }).out, { ok: false, reason: 'vkey' });
  writeFileSync(f.vkeyPath, readFileSync(f.vkeyPath, 'utf8') + ' ');            // changed while "running"
  assert.deepEqual(run(body, f).out, { ok: false, reason: 'vkey' });
  const bad = { protocol: 'groth16', curve: 'bn128', nPublic: 5 };
  writeFileSync(f.vkeyPath, JSON.stringify(bad));
  assert.deepEqual(run(body, { ...f, vkeySha: sha(readFileSync(f.vkeyPath)) }).out, { ok: false, reason: 'vkey' });
});

test('CLI: bad arguments refused, never a default', async () => {
  const f = await fakeSetup();
  const r = spawnSync(process.execPath, [VERIFY, '--vkey', f.vkeyPath], { input: '{}', timeout: 30_000 });
  assert.equal(r.status, 1);
  assert.deepEqual(JSON.parse(r.stdout.toString()), { ok: false, reason: 'usage' });
});

const FIX = process.env.BEACON_FIXTURES;
const haveFix = FIX && existsSync(join(FIX, 'vkey.json'));
test('a VALID throwaway proof is accepted and prints the canonical tuple; its N + r twin is refused at the wire',
  { skip: haveFix ? false : 'needs the rehearsal THROWAWAY fixtures in $BEACON_FIXTURES' }, () => {
    const vkeyPath = join(FIX, 'vkey.json');
    const proof = JSON.parse(readFileSync(join(FIX, 'proof_A.json'), 'utf8'));
    const pub = JSON.parse(readFileSync(join(FIX, 'public_A.json'), 'utf8'));
    const e = Number(pub[0]);
    const now = e * WEEK + 5;
    const ok = run(JSON.stringify({ proof, publicSignals: pub }), { vkeyPath, vkeySha: sha(readFileSync(vkeyPath)), now });
    assert.equal(ok.code, 0);
    assert.deepEqual(ok.out, { ok: true, e: pub[0], H_e: pub[1], N: pub[2], K: pub[3] });
    const alias = [...pub];
    alias[2] = (BigInt(pub[2]) + R).toString();
    const bad = run(JSON.stringify({ proof, publicSignals: alias }), { vkeyPath, vkeySha: sha(readFileSync(vkeyPath)), now });
    assert.deepEqual(bad.out, { ok: false, reason: 'wire' });
  });

test('snarkjs receives exactly the parsed values; with a duplicated key, the N verified IS the N returned', async () => {
  const f = await fakeSetup();
  const seen = [];
  const fake = async (vk, pub, proof) => { seen.push({ pub, proof }); return true; };
  const body = `{"proof":${JSON.stringify(f.proof)},"publicSignals":["2900","12345","11111","424242"],` +
    `"publicSignals":["2900","12345","22222","424242"]}`;
  const out = await verifyDeposit(body, { vkeyPath: f.vkeyPath, vkeySha256: f.vkeySha, now: START + 5, groth16Verify: fake });
  assert.equal(seen.length, 1);
  assert.deepEqual(seen[0].pub, ['2900', '12345', '22222', '424242']);
  assert.equal(out.N, seen[0].pub[2]);                                     // stored N === verified N
  assert.deepEqual(seen[0].proof, f.proof);                                // re-serialized, canonical
});

test('launched through a SYMLINK, the verifier still runs main() (never exit 0 with empty stdout)', async () => {
  const f = await fakeSetup();
  const link = join(f.dir, 'verify-link.mjs');
  symlinkSync(VERIFY, link);
  const r = spawnSync(process.execPath, [link, '--vkey', f.vkeyPath], { input: '{}', timeout: 30_000 });
  assert.equal(r.status, 1);
  assert.deepEqual(JSON.parse(r.stdout.toString()), { ok: false, reason: 'usage' });
});
