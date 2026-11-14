// Argon2 off the main thread: what the worker computes, what the page sends and what it refuses to send.
// Run: node --import tsx --test src/lib/crypto/kdf-offthread.test.ts
// The browser half (a real worker under the page's real policy, and the longest blocked time with and without it) is e2e/argon2-off-main-thread.spec.ts.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deriveKeyArgon2id, ARGON2_MAX_MEMORY_COST, ARGON2_MAX_TIME_COST } from './kdf';
import { handleArgon2Request, ARGON2_BAD_REQUEST, ARGON2_FAILED, type Argon2Response } from './argon2-worker-core';
import { deriveKeyArgon2idOffThread, type Argon2WorkerLike } from './kdf-offthread';

const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');
const PASS = 'pass-phrase-123';
const SALT = new Uint8Array(16).fill(7);
// Known answers computed straight from @noble/hashes argon2id, outside this module's code (t=1,m=1024,p=1 and t=2,m=2048,p=2).
const KAT_1 = 'e1108270e8182514c35430e5ca2634029abfb159f992afc9452aae7a8617ce76';
const KAT_2 = '8019e9572db371e94224473d5bc818b1f47fd72456781d0c8c5643275c07be3e';
const P1 = { time_cost: 1, memory_cost: 1024, parallelism: 1 };
const P2 = { time_cost: 2, memory_cost: 2048, parallelism: 2 };

const req = (pass: string, salt = SALT, params: unknown = P1) => ({
  passphrase: new TextEncoder().encode(pass).buffer as ArrayBuffer,
  salt: salt.slice().buffer as ArrayBuffer,
  params,
});

/**
 * A worker that behaves like a real one where it matters here: messages are structured-cloned, a TRANSFERRED buffer is detached in the sender, and the
 * reply comes back asynchronously. `behave` decides what it does with the request.
 */
function fakeWorker(behave: (data: unknown, reply: (res: unknown, transfer?: Transferable[]) => void, w: Argon2WorkerLike) => void, opts: { ready?: boolean } = {}) {
  const log = { posted: [] as ArrayBuffer[][], terminated: 0 };
  const sendReady = opts.ready !== false;
  const w: Argon2WorkerLike = {
    onmessage: null, onerror: null, onmessageerror: null,
    postMessage(msg, transfer = []) {
      log.posted.push(transfer as ArrayBuffer[]);
      const cloned = structuredClone(msg, { transfer });
      // a real worker says it started as soon as its script loads, before it handles the request
      if (sendReady) setImmediate(() => w.onmessage?.({ data: { ready: true } }));
      setImmediate(() => behave(cloned, (res, tr = []) => { const c = structuredClone(res, { transfer: tr }); w.onmessage?.({ data: c }); }, w));
    },
    terminate() { log.terminated++; },
  };
  return { w, log };
}
const realLogic = (data: unknown, reply: (res: unknown, t?: Transferable[]) => void) => {
  const res = handleArgon2Request(data);
  reply(res, res.ok ? [res.key] : []);
};

// ---------- the worker's logic ----------
test('K1 the worker computes the known answer, for two parameter sets, and it equals the synchronous derivation', () => {
  for (const [params, kat] of [[P1, KAT_1], [P2, KAT_2]] as const) {
    const res = handleArgon2Request(req(PASS, SALT, params));
    assert.ok(res.ok);
    assert.equal(hex(new Uint8Array((res as { key: ArrayBuffer }).key)), kat);
    assert.equal(hex(deriveKeyArgon2id(PASS, SALT, params)), kat, 'the string entry point is the same derivation');
  }
  // a different passphrase or salt gives a different key (the answer depends on its inputs)
  assert.notEqual(hex(new Uint8Array((handleArgon2Request(req('pass-phrase-124')) as { key: ArrayBuffer }).key)), KAT_1);
  assert.notEqual(hex(new Uint8Array((handleArgon2Request(req(PASS, new Uint8Array(16).fill(8))) as { key: ArrayBuffer }).key)), KAT_1);
});

test('K2 the passphrase bytes are zeroed when the worker is done, on success AND on refusal', () => {
  const ok = req(PASS);
  assert.ok(handleArgon2Request(ok).ok);
  assert.ok(new Uint8Array(ok.passphrase).every((b) => b === 0), 'zeroed after a derivation');
  const bad = req(PASS, SALT, { time_cost: 1, memory_cost: ARGON2_MAX_MEMORY_COST + 1, parallelism: 1 });
  assert.equal(handleArgon2Request(bad).ok, false);
  assert.ok(new Uint8Array(bad.passphrase).every((b) => b === 0), 'zeroed after a refusal');
});

test('K3 the worker refuses hostile parameters itself (the clamp does not depend on who calls it), and a bad request, and never echoes the passphrase', () => {
  const refuse = (p: unknown) => handleArgon2Request(req('MARKER-PASSPHRASE-123', SALT, p)) as Extract<Argon2Response, { ok: false }>;
  for (const p of [
    { time_cost: 1, memory_cost: ARGON2_MAX_MEMORY_COST + 1, parallelism: 1 },
    { time_cost: ARGON2_MAX_TIME_COST + 1, memory_cost: 1024, parallelism: 1 },
    { time_cost: 1, memory_cost: 1024, parallelism: 99 },
    { time_cost: 0, memory_cost: 1024, parallelism: 1 },
    { time_cost: 1.5, memory_cost: 1024, parallelism: 1 },
    { algorithm: 'argon2i', time_cost: 1, memory_cost: 1024, parallelism: 1 },
  ]) {
    const r = refuse(p);
    assert.equal(r.ok, false);
    assert.match(r.reason, /^(KDF |Unsupported KDF)/);
    assert.ok(!r.reason.includes('MARKER'));
  }
  // an error that is NOT a parameter limit (here: a salt the library refuses) comes back as the one fixed string, never the library's own text
  const shortSalt = handleArgon2Request(req('MARKER-PASSPHRASE-123', new Uint8Array(4)));
  assert.deepEqual(shortSalt, { ok: false, reason: ARGON2_FAILED });
  for (const junk of [undefined, null, 'x', {}, { passphrase: 1, salt: 2, params: P1 }, { passphrase: new ArrayBuffer(3), salt: new ArrayBuffer(16) }]) {
    assert.deepEqual(handleArgon2Request(junk), { ok: false, reason: ARGON2_BAD_REQUEST });
  }
});

test('K12 the worker wipes the derived key it holds once the copy has been handed over', () => {
  const made: Uint8Array[] = [];
  const spy: typeof import('./kdf').deriveKeyArgon2idBytes = (pass, salt, params) => { const k = deriveKeyArgon2id(PASS, salt, params); made.push(k); return k; };
  const res = handleArgon2Request(req(PASS), spy);
  assert.ok(res.ok);
  assert.equal(hex(new Uint8Array((res as { key: ArrayBuffer }).key)), KAT_1, 'what is handed over is the derived key');
  assert.equal(made.length, 1);
  assert.ok(made[0].every((b) => b === 0), 'the worker\'s own array is zeroed');
  // and a derivation that throws leaves nothing to hold
  const boom = () => { throw new Error('KDF memory_cost 1 KiB exceeds limit'); };
  assert.deepEqual(handleArgon2Request(req(PASS), boom as never), { ok: false, reason: 'KDF memory_cost 1 KiB exceeds limit' });
});

// ---------- the page's side ----------
test('K4 through a worker: the key is the known answer; the passphrase and salt buffers are TRANSFERRED (detached here); the worker is terminated once', async () => {
  const { w, log } = fakeWorker(realLogic);
  let made = 0;
  const key = await deriveKeyArgon2idOffThread(PASS, SALT, P1, () => { made++; return w; });
  assert.equal(hex(key), KAT_1);
  assert.equal(made, 1);
  assert.equal(log.terminated, 1);
  assert.equal(log.posted.length, 1);
  assert.equal(log.posted[0].length, 2, 'both buffers go in the transfer list');
  assert.ok(log.posted[0].every((b) => b.byteLength === 0), 'a transferred buffer is detached in the sender: the page keeps no copy');
  assert.equal(w.onmessage, null, 'handlers released');
});

test('K5 hostile parameters are refused BEFORE a worker exists', async () => {
  let made = 0;
  await assert.rejects(
    deriveKeyArgon2idOffThread(PASS, SALT, { time_cost: 1, memory_cost: ARGON2_MAX_MEMORY_COST + 1, parallelism: 1 }, () => { made++; return fakeWorker(realLogic).w; }),
    /exceeds limit/,
  );
  assert.equal(made, 0, 'the factory was never called');
});

test('K6 a worker that answers with a refusal or with garbage rejects with a fixed reason, and is still terminated', async () => {
  const refusal = fakeWorker((_d, reply) => reply({ ok: false, reason: 'KDF memory_cost 1 KiB exceeds limit' }));
  await assert.rejects(deriveKeyArgon2idOffThread(PASS, SALT, P1, () => refusal.w), /^Error: KDF memory_cost/);
  assert.equal(refusal.log.terminated, 1);
  for (const garbage of [undefined, null, 'x', { ok: true }, { ok: true, key: 'not a buffer' }, { ok: false }]) {
    const g = fakeWorker((_d, reply) => reply(garbage));
    await assert.rejects(deriveKeyArgon2idOffThread(PASS, SALT, P1, () => g.w), new RegExp(ARGON2_FAILED));
    assert.equal(g.log.terminated, 1);
  }
});

test('K7 when the worker cannot START (an error event before it said ready, a factory that throws, no factory) the SAME derivation runs on this thread: the known answer, not a failure', async () => {
  const within = <T,>(p: Promise<T>, ms = 3000) => {
    let timer: ReturnType<typeof setTimeout>;
    const clock = new Promise<never>((_, rej) => { timer = setTimeout(() => rej(new Error('timed out: the call never settled')), ms); });
    return Promise.race([p, clock]).finally(() => clearTimeout(timer));
  };
  const dead = fakeWorker((_d, _r, w) => w.onerror?.({}), { ready: false });
  assert.equal(hex(await within(deriveKeyArgon2idOffThread(PASS, SALT, P1, () => dead.w))), KAT_1, 'error event before ready');
  assert.equal(dead.log.terminated, 1);
  assert.equal(hex(await deriveKeyArgon2idOffThread(PASS, SALT, P1, () => { throw new Error('blocked by policy'); })), KAT_1, 'factory throws');
  assert.equal(hex(await deriveKeyArgon2idOffThread(PASS, SALT, P1, () => null)), KAT_1, 'no worker available');
  assert.equal(hex(await deriveKeyArgon2idOffThread(PASS, SALT, P1)), KAT_1, 'default factory in node has no Worker global');
});

test('K7b a worker that STARTED and then died (an error event after ready: out of memory, say) is a FAILURE with a fixed reason: nothing is re-run on this thread, and it is terminated', async () => {
  let derivedOnPage = false;
  const origNow = TextEncoder.prototype.encode;
  // the page-thread fallback encodes the passphrase itself (deriveKeyArgon2id); the worker path encodes it exactly once. A second encode of the passphrase = a re-run here.
  let encodes = 0;
  TextEncoder.prototype.encode = function (this: TextEncoder, input?: string) { if (input === PASS) encodes++; return origNow.call(this, input); };
  try {
    const died = fakeWorker((_d, _r, w) => w.onerror?.({}));   // ready first (the default), then the error
    await assert.rejects(deriveKeyArgon2idOffThread(PASS, SALT, P1, () => died.w), new RegExp(ARGON2_FAILED));
    assert.equal(died.log.terminated, 1);
    derivedOnPage = encodes > 1;
  } finally { TextEncoder.prototype.encode = origNow; }
  assert.equal(derivedOnPage, false, 'the derivation was not run again on this thread');
});

test('K4b the page wipes its own copy of the passphrase bytes after handing them over', async () => {
  const seen: Uint8Array[] = [];
  const orig = TextEncoder.prototype.encode;
  TextEncoder.prototype.encode = function (this: TextEncoder, input?: string) { const u = orig.call(this, input); if (input === PASS) seen.push(u); return u; };
  try {
    const { w } = fakeWorker(realLogic);
    assert.equal(hex(await deriveKeyArgon2idOffThread(PASS, SALT, P1, () => w)), KAT_1);
  } finally { TextEncoder.prototype.encode = orig; }
  assert.equal(seen.length, 1, 'the passphrase was encoded exactly once on the page');
  assert.ok(seen[0].length > 0 && seen[0].every((b) => b === 0), 'and that array was zeroed');
});

test('K8 the caller\'s salt is not modified, and a salt that is a view onto a bigger buffer is sent as exactly its bytes', async () => {
  const big = new Uint8Array(64).fill(1); big.set(SALT, 16);
  const view = big.subarray(16, 32);
  const before = hex(big);
  let seen = -1;
  const { w } = fakeWorker((d, reply) => { seen = (d as { salt: ArrayBuffer }).salt.byteLength; realLogic(d, reply); });
  assert.equal(hex(await deriveKeyArgon2idOffThread(PASS, view, P1, () => w)), KAT_1);
  assert.equal(seen, 16, 'exactly the salt bytes cross, not the 64-byte buffer behind the view');
  assert.equal(hex(big), before, 'the caller\'s buffer is untouched');
});

// ---------- the freeze cannot come back by a side door ----------
const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', '..'); // src/
const walk = (d: string): string[] => readdirSync(d).flatMap((n) => { const p = join(d, n); return statSync(p).isDirectory() ? walk(p) : [p]; });

test('K9 no application code calls the SYNCHRONOUS derivation: only kdf.ts itself, the off-thread fallback and the self-test do', () => {
  const allowed = new Set(['lib/crypto/kdf.ts', 'lib/crypto/kdf-offthread.ts', 'lib/sync/vault.selftest.ts']);
  const offenders = walk(SRC)
    .filter((f) => /\.(ts|tsx)$/.test(f) && !/\.test\.(ts|tsx)$/.test(f))
    .filter((f) => !allowed.has(relative(SRC, f)))
    .filter((f) => /\bderiveKeyArgon2id\s*\(/.test(readFileSync(f, 'utf8')));
  assert.deepEqual(offenders.map((f) => relative(SRC, f)), []);
});

test('K11 import.meta lives only in the lazily loaded factory module: nothing a CommonJS loader imports through vault.ts can hit it', () => {
  const users = walk(join(SRC, 'lib')).filter((f) => /\.(ts|tsx)$/.test(f) && !/\.test\.(ts|tsx)$/.test(f))
    .filter((f) => /import\.meta/.test(readFileSync(f, 'utf8').split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n')))
    .map((f) => relative(SRC, f));
  assert.ok(users.includes('lib/crypto/kdf-worker-factory.ts'), 'the factory names the worker');
  assert.ok(!users.includes('lib/crypto/kdf-offthread.ts') && !users.includes('lib/sync/vault.ts') && !users.includes('lib/crypto/encrypted-backup.ts'), 'but not the modules that vault.ts and the backup import: ' + users.join(', '));
  const off = readFileSync(join(SRC, 'lib/crypto/kdf-offthread.ts'), 'utf8');
  assert.match(off, /await import\('\.\/kdf-worker-factory'\)/, 'and it is reached by a dynamic import');
  assert.ok(!/^import .*kdf-worker-factory/m.test(off), 'never a static one');
});

test('K10 the two modules that derive from a passphrase use the off-thread path, and the worker file is only glue to the shared handler', () => {
  for (const f of ['lib/sync/vault.ts', 'lib/crypto/encrypted-backup.ts']) {
    const s = readFileSync(join(SRC, f), 'utf8');
    assert.match(s, /await deriveKeyArgon2idOffThread\(/, f);
  }
  const w = readFileSync(join(SRC, 'lib/crypto/argon2.worker.ts'), 'utf8');
  assert.match(w, /handleArgon2Request/);
  assert.match(w, /postMessage\(ARGON2_READY\)/, 'the worker says it started as soon as it loads');
  assert.ok(!/argon2id\s*\(/.test(w.replace(/handleArgon2Request/g, '')), 'no derivation logic in the worker entry itself');
});
