import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq.js';
import { acquireWriterLock, withWriterLock, LOCK_NAME } from './writer-lock';
import { HeadlessStore } from './headless-store';

const dir = () => mkdtempSync(join(tmpdir(), 'writer-lock-'));
const HELPER = join(__dirname, 'writer-lock.helper.ts');
const node = (args: string[]) => spawn(process.execPath, ['--import', 'tsx', HELPER, ...args], { stdio: ['ignore', 'pipe', 'pipe'] });
const done = (p: ReturnType<typeof node>) =>
  new Promise<string>((res, rej) => {
    let out = '';
    let err = '';
    p.stdout!.on('data', (b) => { out += b; });
    p.stderr!.on('data', (b) => { err += b; });
    p.on('exit', (code) => (code === 0 ? res(out) : rej(new Error(`helper exit ${code}: ${err}`))));
  });
const heldBy = (p: ReturnType<typeof node>) =>
  new Promise<void>((res) => p.stdout!.on('data', (b) => { if (String(b).includes('held')) res(); }));
const deadPid = () => spawnSync(process.execPath, ['-e', '0']).pid!;   // exited before we use it

test('acquire writes owner.json; release removes the lock; re-entrant; double release is a no-op', () => {
  const d = dir();
  const release = acquireWriterLock(d, { cmd: 'test' });
  const owner = JSON.parse(readFileSync(join(d, LOCK_NAME, 'owner.json'), 'utf8'));
  assert.equal(owner.pid, process.pid);
  assert.equal(owner.cmd, 'test');
  const inner = acquireWriterLock(d);                    // nested unit in the same process
  inner();
  assert.ok(existsSync(join(d, LOCK_NAME)), 'outer unit still holds it');
  release();
  assert.ok(!existsSync(join(d, LOCK_NAME)));
  const other = acquireWriterLock(d);
  release();                                             // stale handle from the first acquisition
  assert.ok(existsSync(join(d, LOCK_NAME)), 'a double release must not drop the next holder');
  other();
});

test('bounded wait: a live holder makes us throw, never proceed unlocked', async () => {
  const d = dir();
  const holder = node(['hold', d, '3000']);
  await heldBy(holder);
  let ran = false;
  assert.throws(() => withWriterLock(d, () => { ran = true; }, { waitMs: 300 }), /gave up waiting/);
  assert.equal(ran, false);
  await done(holder);
});

test('a holder killed with SIGKILL is taken over', async () => {
  const d = dir();
  const holder = node(['hold', d, '60000']);
  await heldBy(holder);
  holder.kill('SIGKILL');
  await new Promise((r) => holder.on('exit', r));
  const t0 = Date.now();
  withWriterLock(d, () => {}, { waitMs: 5_000 });
  assert.ok(Date.now() - t0 < 2_000, 'takeover should be prompt');
});

test('stale detection: dead pid, reused pid (start time mismatch), ownerless lock past its grace', () => {
  const plant = (d: string, owner: object | null, ageS = 0) => {
    const l = join(d, LOCK_NAME);
    mkdirSync(l);
    if (owner) writeFileSync(join(l, 'owner.json'), JSON.stringify(owner));
    if (ageS) utimesSync(l, new Date(Date.now() - ageS * 1000), new Date(Date.now() - ageS * 1000));
  };
  let d = dir();
  plant(d, { pid: deadPid(), start: '1', started: 'x', cmd: 'dead' });
  withWriterLock(d, () => {}, { waitMs: 1_000 });
  d = dir();
  plant(d, { pid: process.pid, start: 'not-our-start-time', started: 'x', cmd: 'reused' });
  withWriterLock(d, () => {}, { waitMs: 1_000 });
  d = dir();
  plant(d, null, 30);
  withWriterLock(d, () => {}, { waitMs: 1_000 });
  d = dir();
  plant(d, null, 0);                                     // mid-acquire by someone else: must wait, not steal
  assert.throws(() => withWriterLock(d, () => {}, { waitMs: 300 }), /gave up waiting/);
});

test('8 processes x 50 locked increments, starting from a planted stale lock: exactly one taker at a time', async () => {
  const d = dir();
  const counter = join(d, 'counter');
  writeFileSync(counter, '0');
  mkdirSync(join(d, LOCK_NAME));
  writeFileSync(join(d, LOCK_NAME, 'owner.json'), JSON.stringify({ pid: deadPid(), start: '1', started: 'x', cmd: 'dead' }));
  const outs = await Promise.all(Array.from({ length: 8 }, () => done(node(['count', d, counter, '50']))));
  const values = outs.join('').trim().split('\n').map(Number);
  assert.equal(readFileSync(counter, 'utf8'), '400');
  assert.equal(new Set(values).size, 400, 'every increment saw a distinct value: no lost update');
});

test('HeadlessStore with lockDir: 4 processes x 25 upserts lose nothing', async () => {
  const d = dir();
  await Promise.all(['a', 'b', 'c', 'd'].map((tag) => done(node(['store', d, tag, '25']))));
  const ids = new HeadlessStore({ path: join(d, 'store.json') }).listContacts().map((c) => c.id);
  assert.equal(new Set(ids).size, 100);
});

test('ratchet: 2 concurrent send-tr writers x 50: chain headers on the wire never repeat (and do without the lock)', async () => {
  const xs = x25519.utils.randomSecretKey();
  const k = generateKEMKeypair();
  const peerX = x25519.getPublicKey(x25519.utils.randomSecretKey());
  const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
  const fixture = {
    self: { xs: b64(xs), xp: b64(x25519.getPublicKey(xs)), ks: b64(k.secretKey), kp: b64(k.publicKey) },
    peer: { xp: b64(peerX), kp: b64(generateKEMKeypair().publicKey) },
  };
  const run = async (lock: boolean) => {
    const d = dir();
    const fx = join(d, 'fixture.json');
    const wire = join(d, 'wire.jsonl');
    writeFileSync(fx, JSON.stringify(fixture));
    writeFileSync(wire, '');
    await Promise.all([0, 1].map(() => done(node(['send', d, fx, '50', wire, ...(lock ? [] : ['nolock'])]))));
    const headers = readFileSync(wire, 'utf8').trim().split('\n');
    return { total: headers.length, distinct: new Set(headers).size };
  };
  const locked = await run(true);
  assert.equal(locked.total, 100);
  assert.equal(locked.distinct, 100, 'a repeated (dh, n) = the same message key used twice');
  const unlocked = await run(false);
  // Negative control: the race the lock closes. Timing-dependent, so report rather than fail on it.
  console.log(`  unlocked control: ${unlocked.total - unlocked.distinct} repeated chain header(s) of ${unlocked.total}`);
});
