// src/lib/relay/mldsa-verify-pool.test.ts
// ML-DSA-87 verification off the event loop (mldsa-verify-pool.server.ts): it really runs in a worker, a full queue is shed with
// OwnerVerifyBusyError (→ the route's uniform 503) before any work, the main thread stays responsive under a flood of well-formed
// but WRONG signatures (the costly kind: they pass the early checks), and if the workers can't load ML-DSA it falls back inline.
//
// Run: npx tsx --test src/lib/relay/mldsa-verify-pool.test.ts

process.env.RELAY_DB_PATH = ':memory:';
import { test, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { verifyMlDsaPooled, mldsaPoolStats, resetMldsaPool } from './mldsa-verify-pool.server';
import { OwnerVerifyBusyError } from './owner-verify-budget';
import { resetDeposit429Counts } from './deposit-429-log';
import { resetMailboxStore, depositEnvelope } from './mailbox-store';
import { generateMailboxAuthKeypair, signOwnerRequestV2 } from './mailbox-auth-v2';

const KP = ml_dsa87.keygen(new Uint8Array(32).fill(5));
const MSG = new TextEncoder().encode('owner request');
const SIG = ml_dsa87.sign(MSG, KP.secretKey);
const WRONG = ml_dsa87.sign(new TextEncoder().encode('a different message'), KP.secretKey); // well-formed: costs a full verify

beforeEach(async () => {
  await resetMldsaPool();
  resetDeposit429Counts();
  resetMailboxStore();
  for (const k of ['RELAY_MLDSA_WORKERS', 'RELAY_MLDSA_QUEUE_MAX', 'RELAY_MLDSA_WORKER_MODULE_TEST', 'RELAY_OWNER_VERIFY_PER_SEC', 'RELAY_OWNER_VERIFY_BURST']) delete process.env[k];
});
after(async () => { await resetMldsaPool(); });

test('P1 verifies in a worker: a valid signature → true, a wrong one → false, both counted as pooled', async () => {
  assert.equal(await verifyMlDsaPooled(SIG, MSG, KP.publicKey), true);
  assert.equal(await verifyMlDsaPooled(WRONG, MSG, KP.publicKey), false);
  const s = mldsaPoolStats();
  assert.equal(s.pooled, 2);
  assert.equal(s.inline, 0);
  assert.equal(s.broken, false);
});

test('P2 the queue is bounded: with 1 worker and 1 queued slot, the 3rd concurrent job is shed BEFORE any work', async () => {
  process.env.RELAY_MLDSA_WORKERS = '1';
  process.env.RELAY_MLDSA_QUEUE_MAX = '1';
  const a = verifyMlDsaPooled(WRONG, MSG, KP.publicKey);
  const b = verifyMlDsaPooled(WRONG, MSG, KP.publicKey);
  assert.throws(() => verifyMlDsaPooled(WRONG, MSG, KP.publicKey), OwnerVerifyBusyError);
  assert.deepEqual(await Promise.all([a, b]), [false, false]);
  assert.equal(mldsaPoolStats().shed, 1);
});

async function maxLagWhile(work: () => Promise<unknown>): Promise<number> {
  let max = 0;
  let last = performance.now();
  const iv = setInterval(() => { const now = performance.now(); max = Math.max(max, now - last - 5); last = now; }, 5);
  await work();
  await new Promise((r) => setTimeout(r, 15)); // let the timer tick once more after the work
  clearInterval(iv);
  return max;
}

test('P3 the main thread stays responsive under a flood of costly wrong signatures (timer lag, pooled vs inline)', async () => {
  process.env.RELAY_MLDSA_QUEUE_MAX = '64';
  await verifyMlDsaPooled(SIG, MSG, KP.publicKey); // warm the workers (first import)
  const N = 24;
  const pooledLag = await maxLagWhile(() => Promise.all(Array.from({ length: N }, () => verifyMlDsaPooled(WRONG, MSG, KP.publicKey))));
  const inlineLag = await maxLagWhile(async () => { for (let i = 0; i < N; i++) { ml_dsa87.verify(WRONG, MSG, KP.publicKey); await new Promise((r) => setImmediate(r)); } }); // as a server would: one verify per request turn
  console.log(`QA pool lag: pooled max ${pooledLag.toFixed(1)} ms, inline max ${inlineLag.toFixed(1)} ms over ${N} costly verifies`);
  assert.ok(pooledLag < inlineLag / 3, `pooled ${pooledLag.toFixed(1)} ms must be far below inline ${inlineLag.toFixed(1)} ms`);
  assert.ok(pooledLag < 50, `pooled max lag ${pooledLag.toFixed(1)} ms`);
});

test('P4 if the workers cannot load ML-DSA, verification falls back to the main thread (owners are never locked out by the pool)', async () => {
  process.env.RELAY_MLDSA_WORKER_MODULE_TEST = '@noble/no-such-module/at-all.js';
  const lines: string[] = [];
  const orig = console.warn;
  console.warn = (...a: unknown[]) => { lines.push(a.map(String).join(' ')); };
  try {
    assert.equal(await verifyMlDsaPooled(SIG, MSG, KP.publicKey), true, 'still verifies (inline)');
    assert.equal(await verifyMlDsaPooled(WRONG, MSG, KP.publicKey), false);
    assert.equal(await verifyMlDsaPooled(SIG, MSG, KP.publicKey), true, 'and keeps verifying VALID signatures once marked broken');
  } finally { console.warn = orig; }
  assert.equal(mldsaPoolStats().broken, true);
  assert.ok(mldsaPoolStats().inline >= 2, 'the later calls ran on the inline path');
  assert.equal(lines.filter((l) => l.includes('mldsa pool unavailable')).length, 1, 'logged once');
});

test('P5 the queue route verifies a v2 poll through the pool (wiring)', async () => {
  const { GET } = await import('../../../app/api/relay/queue/route');
  const kp = generateMailboxAuthKeypair();
  const { mailboxId, headers } = signOwnerRequestV2({ keypair: kp, op: 'poll', now: Date.now() });
  depositEnvelope(mailboxId, 'POOLED', Date.now());
  const res = await GET(new Request(`http://r.test/api/relay/queue?mailbox_id=${mailboxId}`, { headers: { 'x-forwarded-for': '192.0.2.99', ...headers } }));
  assert.equal(res.status, 200);
  assert.ok((await res.text()).includes('POOLED'));
  assert.equal(mldsaPoolStats().pooled, 1, 'the ML-DSA step ran in the pool');
});

test('P6 an idle pool never keeps the process alive: a child that does one pooled verify exits by itself', async () => {
  const { spawnSync } = await import('node:child_process');
  const script = "import('./src/lib/relay/mldsa-verify-pool.server').then(async (m) => { const { ml_dsa87 } = await import('@noble/post-quantum/ml-dsa.js'); const kp = ml_dsa87.keygen(new Uint8Array(32).fill(9)); const msg = new Uint8Array([1]); const v = m.verifyMlDsaPooled ?? m.default.verifyMlDsaPooled; const ok = await v(ml_dsa87.sign(msg, kp.secretKey), msg, kp.publicKey); console.log('VERIFIED', ok); })";
  const t0 = Date.now();
  const r = spawnSync('npx', ['tsx', '-e', script], { cwd: process.cwd(), encoding: 'utf8', timeout: 60_000 });
  const secs = (Date.now() - t0) / 1000;
  assert.equal(r.signal, null, `the child was killed by the 60 s timeout (it hung): ${secs.toFixed(1)} s`);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /VERIFIED true/, 'the job settled before exit (a busy worker is ref\'d)');
});
