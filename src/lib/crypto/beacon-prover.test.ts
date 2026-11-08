// #588 trust beacon, PROVER half: tests first (the stub throws, so everything that needs the implementation is RED).
// Run: npx tsx --test src/lib/crypto/beacon-prover.test.ts
// Vectors: beacon-prover.vectors.json = PUBLIC expected values from the throwaway KAT (fixtures v3). The secret scalars and Ed25519 seeds are
// re-derived here from the public labels, exactly as circuits/588-slotbind/kat.cjs does (x = (SHA256(label) mod (L-1)) + 1).
// The proof tests need the throwaway wasm + zkey + vkey (the phone-probe bundle); they SKIP, with the reason printed, if those files are absent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { deriveDeposit, buildDeposit, scheduleRedeposit, signAuth, newOneTimeKey, ProverRefused, type DepositKeys } from './beacon-prover';
import * as wire from './beacon-wire.mjs';   // namespace import: the epoch constants are asserted below (Athena adds them to the module)
const refusedWith = (reason: string) => (e: unknown) => e instanceof ProverRefused && e.reason === reason;
import { authMessage, parseDeposit, serializeDeposit } from './beacon-wire.mjs';

const V = JSON.parse(readFileSync(new URL('./beacon-prover.vectors.json', import.meta.url), 'utf8'));
const L = BigInt(V.babyjubSubOrder);
const sha = (s: string) => createHash('sha256').update(s).digest();
const scalar = (label: string) => (BigInt('0x' + sha(label).toString('hex')) % (L - BigInt('1'))) + BigInt('1');
const hex = (h: string) => Uint8Array.from(Buffer.from(h, 'hex'));
const pt = (p: string[]): readonly [bigint, bigint] => [BigInt(p[0]), BigInt(p[1])];
const keysFor = (side: 'A' | 'B'): DepositKeys => {
  const me = V[side], other = V[side === 'A' ? 'B' : 'A'];
  return { x: scalar(me.xLabel), counterpartY: pt(other.P), epoch: BigInt(V.epoch), oneTimePk: hex(me.edPkHex) };
};
const expected = (side: 'A' | 'B') => ({ e: BigInt(V.epoch), H_e: BigInt(V.slotH_e), N: BigInt(V[side].N), K: BigInt(V[side].K) });

// ---- derivation: the known answers ----
test('derive: side A reproduces the known answer [e, H_e, N_A, K_A]', async () => {
  assert.deepEqual((await deriveDeposit(keysFor('A'))).signals, expected('A'));
});
test('derive: side B reproduces the known answer [e, H_e, N_B, K_B]', async () => {
  assert.deepEqual((await deriveDeposit(keysFor('B'))).signals, expected('B'));
});
test('derive: the two sides meet at ONE slot with DISTINCT nullifiers and DISTINCT poll keys', async () => {
  const a = (await deriveDeposit(keysFor('A'))).signals, b = (await deriveDeposit(keysFor('B'))).signals;
  assert.equal(a.H_e, b.H_e); assert.notEqual(a.N, b.N); assert.notEqual(a.K, b.K);
});
test('derive: the circuit input is all canonical decimal strings and carries the public signals unchanged', async () => {
  const d = await deriveDeposit(keysFor('A'));
  for (const [k, v] of Object.entries(d.input)) assert.match(v, /^(0|[1-9][0-9]*)$/, `input.${k}`);
  assert.equal(d.input.e, String(d.signals.e)); assert.equal(d.input.H_e, String(d.signals.H_e));
  assert.equal(d.input.N, String(d.signals.N)); assert.equal(d.input.K, String(d.signals.K));
});

// ---- derivation: what the prover must refuse (these hold with or without the verified-contact rule) ----
const P_FIELD = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
const refuse = (name: string, reason: string, mutate: (k: DepositKeys) => DepositKeys) =>
  test(`derive REFUSES ${name} [${reason}]`, async () => { await assert.rejects(() => deriveDeposit(mutate(keysFor('A'))), refusedWith(reason)); });
refuse('a counterpart key that is the identity (0,1)', 'y-identity', (k) => ({ ...k, counterpartY: [BigInt('0'), BigInt('1')] }));
refuse('a counterpart key that is off the curve', 'y-off-curve', (k) => ({ ...k, counterpartY: [k.counterpartY[0], k.counterpartY[1] + BigInt('1')] }));
refuse('a counterpart key of small order (0,-1): no prime-order subgroup', 'y-small-order', (k) => ({ ...k, counterpartY: [BigInt('0'), P_FIELD - BigInt('1')] }));
refuse('x = 0', 'x-range', (k) => ({ ...k, x: BigInt('0') }));
refuse('x >= the subgroup order', 'x-range', (k) => ({ ...k, x: L }));
refuse('an epoch >= the field order', 'epoch-range', (k) => ({ ...k, epoch: P_FIELD }));
refuse('a negative epoch', 'epoch-range', (k) => ({ ...k, epoch: -BigInt('1') }));
refuse('a one-time key that is not 32 bytes', 'pk-length', (k) => ({ ...k, oneTimePk: new Uint8Array(31) }));

// ---- the deposit on the wire: needs the throwaway proving files ----
const PROBE = process.env.BEACON_THROWAWAY_DIR ?? '/app/shared/outbox/apollo/588_phone_probe_20261107';
const haveFiles = existsSync(join(PROBE, 'slotbind.wasm')) && existsSync(join(PROBE, 'slotbind_final.zkey')) && existsSync(join(PROBE, 'vkey.json'));
const skipWhy = haveFiles ? false : `throwaway proving files not found in ${PROBE} (set BEACON_THROWAWAY_DIR)`;
const files = () => ({ wasm: new Uint8Array(readFileSync(join(PROBE, 'slotbind.wasm'))), zkey: new Uint8Array(readFileSync(join(PROBE, 'slotbind_final.zkey'))) });

test('buildDeposit: the body is EXACTLY serializeDeposit(parseDeposit(body)) with only {proof, publicSignals}', { skip: skipWhy }, async () => {
  const body = await buildDeposit(keysFor('A'), files());
  assert.deepEqual(Object.keys(JSON.parse(body)).sort(), ['proof', 'publicSignals']);
  const parsed = parseDeposit(body);
  assert.equal(serializeDeposit(parsed), body, 'canonical round trip (R1-e)');
  assert.deepEqual(parsed.signals, expected('A'));
});
test('buildDeposit: the proof VERIFIES under the throwaway vkey (real snarkjs)', { skip: skipWhy }, async () => {
  const body = await buildDeposit(keysFor('B'), files());   // first, so the stub fails for ITS reason, not for a missing module
  const mod = 'snarkjs'; const snarkjs: any = await import(mod);   // a variable, so tsc does not try to resolve an untyped module
  const dep = JSON.parse(body);
  const vkey = JSON.parse(readFileSync(join(PROBE, 'vkey.json'), 'utf8'));
  assert.equal(await snarkjs.groth16.verify(vkey, dep.publicSignals, dep.proof), true);
});
test('buildDeposit: a counterpart key the prover must refuse never reaches the proof', { skip: skipWhy }, async () => {
  await assert.rejects(() => buildDeposit({ ...keysFor('A'), counterpartY: [BigInt('0'), BigInt('1')] }, files()), refusedWith('y-identity'));
});

// ---- re-deposit timing (Flint: random inside the epoch, never at the boundary) ----
test('scheduleRedeposit: always inside [start+grace, end-grace] and spread over the whole epoch, not boundary-aligned', () => {
  const epochSeconds = 604800, graceSeconds = 600, start = 1_700_000_000_000;
  let s = 0x9e3779b9; const rand = () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 2 ** 32; }; // xorshift32, seeded
  const lo = start + graceSeconds * 1000, hi = start + (epochSeconds - graceSeconds) * 1000;
  const bins = new Array(10).fill(0); const N = 5000;
  for (let i = 0; i < N; i++) {
    const t = scheduleRedeposit({ epochStartMs: start, epochSeconds, graceSeconds, rand });
    assert.ok(t >= lo && t <= hi, `t=${t} outside [${lo}, ${hi}]`);
    bins[Math.min(9, Math.floor(((t - lo) / (hi - lo)) * 10))]++;
  }
  for (const c of bins) assert.ok(c > N / 10 * 0.7 && c < N / 10 * 1.3, `bins not uniform: ${bins.join(',')}`);
});
test('scheduleRedeposit: refuses an epoch too short for its grace and a rand outside [0,1)', () => {
  assert.throws(() => scheduleRedeposit({ epochStartMs: 0, epochSeconds: 1000, graceSeconds: 600, rand: () => 0.5 }), refusedWith('epoch-too-short'));
  assert.throws(() => scheduleRedeposit({ epochStartMs: 0, epochSeconds: 604800, graceSeconds: 600, rand: () => 1 }), refusedWith('rand-range'));
});

// ---- poll / withdraw signing ----
test('signAuth: signs exactly authMessage(op, H_e, N, nonce); a poll message is never the withdraw message', async () => {
  const nonce = new Uint8Array(32).fill(7); const seen: Uint8Array[] = [];
  const sign = async (m: Uint8Array) => { seen.push(m); return new Uint8Array(64); };
  await signAuth('poll', BigInt('5'), BigInt('6'), nonce, sign); await signAuth('withdraw', BigInt('5'), BigInt('6'), nonce, sign);
  assert.deepEqual(seen[0], authMessage('poll', BigInt('5'), BigInt('6'), nonce));
  assert.deepEqual(seen[1], authMessage('withdraw', BigInt('5'), BigInt('6'), nonce));
  assert.notDeepEqual(seen[0], seen[1]);
});
test('signAuth: refuses a bad op and a nonce that is not 32 bytes, before signing anything', async () => {
  let called = 0; const sign = async () => { called++; return new Uint8Array(64); };
  await assert.rejects(() => signAuth('poll', BigInt('1'), BigInt('1'), new Uint8Array(31), sign), refusedWith('nonce'));
  await assert.rejects(() => signAuth('delete' as never, BigInt('1'), BigInt('1'), new Uint8Array(32), sign), refusedWith('op'));
  assert.equal(called, 0);
});

// ---- packaging guard (Archie Q3): snarkjs and circomlibjs are never statically imported ----
test('GUARD: no static import of snarkjs or circomlibjs anywhere in src/ (only dynamic import() on the flagged path)', () => {
  const bad: string[] = [];
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) { if (e.name !== 'node_modules') walk(p); continue; }
      if (!/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(e.name) || /\.test\./.test(e.name)) continue;
      const src = readFileSync(p, 'utf8');
      if (/(^|\n)\s*import\s[^;\n]*from\s+['"](snarkjs|circomlibjs)['"]/.test(src) || /require\(\s*['"](snarkjs|circomlibjs)['"]\s*\)/.test(src)) bad.push(p);
    }
  };
  walk(new URL('../../', import.meta.url).pathname);
  assert.deepEqual(bad, [], 'static import found');
});

// =====================================================================================================================
// Added after Flint's review of the first commit (task:588 #5282), items 1-5.
// =====================================================================================================================

// ---- 1. a MIXED-ORDER counterpart key and the other torsion points (up-front refusal, not a crash inside witness generation) ----
refuse('a MIXED-ORDER counterpart key (prime-order point + an order-8 torsion point): on the curve, not small-order', 'y-not-in-subgroup', (k) => ({ ...k, counterpartY: pt(V.mixedOrderY) }));
refuse('a counterpart key of order exactly 8 (a pure torsion point)', 'y-small-order', (k) => ({ ...k, counterpartY: pt(V.order8Y) }));
test('the refusal for a mixed-order key happens BEFORE any proving files are touched', async () => {
  let touched = 0;
  const trap = { get wasm(): Uint8Array { touched++; return new Uint8Array(0); }, get zkey(): Uint8Array { touched++; return new Uint8Array(0); } };
  await assert.rejects(() => buildDeposit({ ...keysFor('A'), counterpartY: pt(V.mixedOrderY) }, trap), refusedWith('y-not-in-subgroup'));
  assert.equal(touched, 0, 'the prover read the wasm/zkey before refusing');
});

// ---- 2. self-pair ----
refuse('a counterpart key equal to our OWN beacon key (self-pair)', 'y-self', (k) => ({ ...k, counterpartY: pt(V.A.P) }));

// ---- 3. secrets never leave: not in the serialized body, not in any refusal message ----
const secretStrings = (side: 'A' | 'B') => {
  const x = scalar(V[side].xLabel), seed = sha(V[side].edSeedLabel);
  const xHex = x.toString(16);
  return [x.toString(), xHex, xHex.padStart(64, '0'), seed.toString('hex')];
};
test('SECRETS: no refusal message contains x (decimal or hex) or the Ed25519 seed, for either side and every refusal', async () => {
  const cases: [string, (k: DepositKeys) => DepositKeys][] = [
    ['y-identity', (k) => ({ ...k, counterpartY: [BigInt('0'), BigInt('1')] })],
    ['y-off-curve', (k) => ({ ...k, counterpartY: [k.counterpartY[0], k.counterpartY[1] + BigInt('1')] })],
    ['y-not-in-subgroup', (k) => ({ ...k, counterpartY: pt(V.mixedOrderY) })],
    ['y-small-order', (k) => ({ ...k, counterpartY: pt(V.order8Y) })],
    ['epoch-range', (k) => ({ ...k, epoch: BigInt('-1') })],
    ['pk-length', (k) => ({ ...k, oneTimePk: new Uint8Array(3) })],
  ];
  for (const side of ['A', 'B'] as const) {
    for (const [reason, mut] of cases) {
      let msg = '';
      await assert.rejects(() => deriveDeposit(mut(keysFor(side))), (e: unknown) => { msg = String((e as Error).message); return refusedWith(reason)(e); });
      for (const s of secretStrings(side)) assert.ok(!msg.includes(s), `message for ${reason} leaks a secret value`);
    }
  }
});
test('SECRETS: the serialized body contains none of x (decimal/hex) or the one-time seed, for A and B', { skip: skipWhy }, async () => {
  for (const side of ['A', 'B'] as const) {
    const body = await buildDeposit(keysFor(side), files());
    for (const s of secretStrings(side)) assert.ok(!body.toLowerCase().includes(s.toLowerCase()), `body leaks a secret value (${s.slice(0, 6)}...)`);
  }
});

// ---- 4. a FRESH one-time key per deposit, from the CSPRNG; never Math.random ----
test('FRESH K: two default one-time keys differ, and each public key is 32 bytes', async () => {
  const a = await newOneTimeKey(), b = await newOneTimeKey();
  assert.equal(a.pk.length, 32); assert.equal(a.seed.length, 32);
  assert.notDeepEqual(a.pk, b.pk); assert.notDeepEqual(a.seed, b.seed);
});
test('FRESH K: the random source is a test seam and is used for the seed (same bytes in, same key out)', async () => {
  const fixed = (n: number) => new Uint8Array(n).fill(9);
  const a = await newOneTimeKey(fixed), b = await newOneTimeKey(fixed);
  assert.deepEqual(a.seed, new Uint8Array(32).fill(9)); assert.deepEqual(a.pk, b.pk);
});
test('FRESH K: the same pair and epoch with two fresh one-time keys give the SAME slot and nullifier but DIFFERENT poll keys', async () => {
  const base = keysFor('A');
  const d1 = await deriveDeposit({ ...base, oneTimePk: (await newOneTimeKey()).pk });
  const d2 = await deriveDeposit({ ...base, oneTimePk: (await newOneTimeKey()).pk });
  assert.equal(d1.signals.H_e, d2.signals.H_e); assert.equal(d1.signals.N, d2.signals.N); assert.notEqual(d1.signals.K, d2.signals.K);
});
test('GUARD: no Math.random in any beacon-*.ts / beacon-*.mjs source (the re-deposit sampler included)', () => {
  const dir = new URL('./', import.meta.url).pathname;
  const bad = readdirSync(dir).filter((f) => /^beacon-.*\.(ts|mjs)$/.test(f) && !/\.test\./.test(f))
    .filter((f) => /Math\.random/.test(readFileSync(join(dir, f), 'utf8').replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '')));
  assert.deepEqual(bad, []);
});

// ---- 5. ONE epoch constant: the prover imports it, it does not define its own ----
test('EPOCH: beacon-wire.mjs exports EPOCH_SECONDS = 604800 and GRACE_SECONDS = 600 (the one definition)', () => {
  assert.equal((wire as Record<string, unknown>).EPOCH_SECONDS, 604800);
  assert.equal((wire as Record<string, unknown>).GRACE_SECONDS, 600);
});
test('EPOCH: scheduleRedeposit with no epoch/grace given uses the module constants (the window is [start+600 s, start+604800-600 s])', () => {
  const start = 1_700_000_000_000; const lo = start + 600_000, hi = start + (604800 - 600) * 1000;
  for (const r of [0, 0.5, 0.999999]) { const t = scheduleRedeposit({ epochStartMs: start, rand: () => r }); assert.ok(t >= lo && t <= hi, `t=${t}`); }
});
test('GUARD: beacon-prover.ts defines no epoch or grace constant of its own and imports them from beacon-wire.mjs', () => {
  const src = readFileSync(new URL('./beacon-prover.ts', import.meta.url), 'utf8').replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
  assert.doesNotMatch(src, /\b604800\b|\b604_800\b|\bEPOCH_SECONDS\s*=|\bGRACE_SECONDS\s*=|=\s*600\b/, 'a literal epoch/grace constant');
  // the constants may be reached by a named import or through the wire module's namespace (the namespace form still LOADS before the module exports them)
  assert.match(src, /from\s*'\.\/beacon-wire\.mjs'/, 'must import from beacon-wire.mjs');
  assert.match(src, /\bwire(?: as any)?\)?\.EPOCH_SECONDS\b|import\s*\{[^}]*\bEPOCH_SECONDS\b[^}]*\}\s*from\s*'\.\/beacon-wire\.mjs'/, 'must take EPOCH_SECONDS from beacon-wire.mjs');
  assert.match(src, /\bwire(?: as any)?\)?\.GRACE_SECONDS\b|import\s*\{[^}]*\bGRACE_SECONDS\b[^}]*\}\s*from\s*'\.\/beacon-wire\.mjs'/, 'must take GRACE_SECONDS from beacon-wire.mjs');
});
