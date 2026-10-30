import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq.js';
import { acquireWriterLock, withWriterLock, LOCK_NAME } from './writer-lock';
import { TripleRatchet } from '../crypto/message-ratchet';
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

test('stale detection: a zombie owner (dead-but-unreaped) is taken over', async (t) => {
  if (!existsSync('/proc/self/stat')) { t.skip('needs /proc'); return; }
  // bash execs a sleeper over itself: its backgrounded child dies unreaped and stays a zombie — kill(pid,0)
  // still succeeds and /proc/<pid>/stat still resolves with the real start time, the exact wedge shape from
  // writer-lock-zombie-stale-001 (a reparented-to-init zombie held .writer.lock for 3.5h on 2026-10-30).
  const zwrap = spawn('bash', ['-c', 'sleep 0.2 & echo $!; exec sleep 30']);
  const zpid = await new Promise<number>((res, rej) => {
    zwrap.stdout!.once('data', (b) => res(Number(String(b).trim())));
    zwrap.once('exit', () => rej(new Error('zombie wrapper exited early')));
  });
  try {
    await new Promise((r) => setTimeout(r, 600));                      // let the child die unreaped
    const stat = readFileSync(`/proc/${zpid}/stat`, 'utf8');
    const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    assert.equal(fields[0], 'Z', 'fixture sanity: the planted owner IS a zombie');
    const d = dir();
    mkdirSync(join(d, LOCK_NAME));
    // fields[19] = real start time: the start-time probe alone would call this dead process alive.
    writeFileSync(join(d, LOCK_NAME, 'owner.json'), JSON.stringify({ pid: zpid, start: fields[19], started: 'x', cmd: 'zombie' }));
    withWriterLock(d, () => {}, { waitMs: 2_000 });
  } finally {
    zwrap.kill('SIGKILL');
  }
});

test('stale detection: a zombie LEADER whose other threads still run is NOT taken over (it may still write)', async (t) => {
  if (!existsSync('/proc/self/stat')) { t.skip('needs /proc'); return; }
  if (spawnSync('python3', ['-c', '0']).status !== 0) { t.skip('needs python3 for the fixture'); return; }
  // The main thread pthread_exit()s while a worker sleeps on: /proc shows the leader as Z and kill(pid,0) succeeds,
  // exactly like a true zombie — but the process is alive and could still write. Only Threads: tells them apart.
  const lwrap = spawn('python3', ['-I', '-c', [
    'import ctypes, os, threading, time',
    'threading.Thread(target=time.sleep, args=(30,)).start()',
    'print(os.getpid(), flush=True)',
    'ctypes.CDLL(None).pthread_exit(None)',
  ].join('\n')]);
  const lpid = await new Promise<number>((res, rej) => {
    lwrap.stdout!.once('data', (b) => res(Number(String(b).trim())));
    lwrap.once('exit', () => rej(new Error('leader-exit wrapper exited early')));
  });
  try {
    await new Promise((r) => setTimeout(r, 400));                      // let the main thread exit
    const stat = readFileSync(`/proc/${lpid}/stat`, 'utf8');
    const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    assert.equal(fields[0], 'Z', 'fixture sanity: the leader shows Z');
    assert.match(readFileSync(`/proc/${lpid}/status`, 'utf8'), /^Threads:\s*[2-9]/m, 'fixture sanity: a thread still runs');
    const d = dir();
    mkdirSync(join(d, LOCK_NAME));
    writeFileSync(join(d, LOCK_NAME, 'owner.json'), JSON.stringify({ pid: lpid, start: fields[19], started: 'x', cmd: 'leader-exit' }));
    let ran = false;
    assert.throws(() => withWriterLock(d, () => { ran = true; }, { waitMs: 300 }), /gave up waiting/);
    assert.equal(ran, false);
  } finally {
    lwrap.kill('SIGKILL');
  }
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

test('ratchet, mixed: trOpen (receive) ∥ send-tr on one session: no lost receive state, distinct send headers', async () => {
  const ident = () => {
    const xs = x25519.utils.randomSecretKey();
    const k = generateKEMKeypair();
    return { x25519Sec: xs, x25519Pub: x25519.getPublicKey(xs), mlkem1024Sec: k.secretKey, mlkem1024Pub: k.publicKey };
  };
  const alice = ident();
  const bob = ident();
  const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
  const fixture = {
    self: { xs: b64(alice.x25519Sec), xp: b64(alice.x25519Pub), ks: b64(alice.mlkem1024Sec), kp: b64(alice.mlkem1024Pub) },
    peer: { xp: b64(bob.x25519Pub), kp: b64(bob.mlkem1024Pub) },
  };
  const run = async (lock: boolean) => {
    // Alice opens the session; Bob accepts, then queues 40 packets for Alice in one sending chain.
    const a = TripleRatchet.initiate(alice, { x25519Pub: bob.x25519Pub, mlkem1024Pub: bob.mlkem1024Pub });
    const first = await TripleRatchet.acceptFirst(bob, { x25519Pub: alice.x25519Pub, mlkem1024Pub: alice.mlkem1024Pub }, await a.send('hello'));
    assert.ok(first);
    const packets = [];
    for (let i = 0; i < 40; i++) packets.push(await first.session.send(`m${i}`));
    const d = dir();
    writeFileSync(join(d, 'ratchet-sessions.json'), JSON.stringify({ peer: a.exportState() }));
    writeFileSync(join(d, 'fixture.json'), JSON.stringify(fixture));
    writeFileSync(join(d, 'packets.json'), JSON.stringify(packets));
    writeFileSync(join(d, 'wire.jsonl'), '');
    writeFileSync(join(d, 'recv.txt'), '');
    const nolock = lock ? [] : ['nolock'];
    await Promise.all([
      done(node(['recv', d, join(d, 'packets.json'), join(d, 'recv.txt'), ...nolock])),
      done(node(['send', d, join(d, 'fixture.json'), '40', join(d, 'wire.jsonl'), ...nolock])),
    ]);
    const received = readFileSync(join(d, 'recv.txt'), 'utf8').trim().split('\n').filter((l) => l === 'ok').length;
    const headers = readFileSync(join(d, 'wire.jsonl'), 'utf8').trim().split('\n');
    // Forward secrecy: with the final state, every consumed packet must be undecryptable. A lost receive
    // update leaves an older state on disk, whose keys decrypt packets Alice already consumed.
    let replayable = 0;
    for (const p of packets) {
      const snap = JSON.parse(readFileSync(join(d, 'ratchet-sessions.json'), 'utf8')).peer;
      if ((await TripleRatchet.importState(snap)!.receive(p)) !== null) replayable++;
    }
    return { received, sends: headers.length, distinct: new Set(headers).size, replayable };
  };
  const locked = await run(true);
  assert.equal(locked.received, 40, 'every inbound packet decrypted once');
  assert.equal(locked.distinct, locked.sends, 'no repeated send header');
  assert.equal(locked.sends, 40);
  assert.equal(locked.replayable, 0, 'no consumed message key survived in the saved state');
  const u = await run(false);
  console.log(`  unlocked control: received ${u.received}/40, ${u.sends - u.distinct} repeated send header(s), ${u.replayable} replayable packet(s)`);
});
