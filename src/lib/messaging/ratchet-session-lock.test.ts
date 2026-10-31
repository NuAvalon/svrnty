// src/lib/messaging/ratchet-session-lock.test.ts
//
// B group 2, commit 4c (Flint #823/#821): R5. A ratchet session row is a read-modify-write. Two tabs, or an overlapping poll and a
// send, that both read the same state each advance it; the last write wins. For a SEND that reuses one message key for two different
// plaintexts; for a RECEIVE it loses the other's advance and skipped-key consumption (a replay window). The fix has two layers and
// each is tested ALONE so a regression in one cannot hide behind the other:
//   1. a per-(owner,peer) exclusive lock held across load -> advance -> persist (navigator.locks, in-process queue as fallback)
//   2. a version CAS on the row, so a write from a stale read throws instead of overwriting
// Real ratchet crypto throughout; the only fake is session STORAGE (ratchet-test-io.ts, same version semantics as store.ts) and, for the
// web-locks path, a minimal LockManager.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import {
  chooseWireBody, openDirectNote, openDirectNoteStaged, sealDirectNote, type RatchetIO,
} from './direct-session';
import { RatchetSessionConflictError, ratchetRowVersion } from './store';
import {
  acquirePeerSessionLock, peerSessionLockName, RatchetSessionBusyError,
} from './peer-session-lock';
import { memIO } from './ratchet-test-io';

function ratchetIdentity(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });
const ME = 'fp-me', THEM = 'fp-them';
const LOCK = peerSessionLockName(undefined, THEM);
const tick = () => new Promise<void>((r) => setTimeout(r, 15));
const noLock: Pick<RatchetIO, 'acquireLock'> = { acquireLock: async () => () => {} };

/** `me` holds a session in which `them` has already sent a frame that `me` OPENED (so me may ratchet back). */
async function observedSession() {
  const me = ratchetIdentity(), them = ratchetIdentity();
  const meIO = memIO(), themIO = memIO();
  const first = await sealDirectNote(ME, 'hello from them', them, peerOf(me), themIO.io);
  assert.equal(await openDirectNote(THEM, first!, me, peerOf(them), meIO.io), 'hello from them');
  return { me, them, meIO, themIO };
}
const send = (a: { me: RatchetIdentity; them: RatchetIdentity }, body: string, io: RatchetIO) =>
  chooseWireBody({ body, peerFingerprint: THEM, canDeposit: true, ownerRatchet: a.me, peerRatchet: peerOf(a.them) }, io);

// ── the pure version rule ────────────────────────────────────────────────────────────────────────────────────────────

test('ratchetRowVersion: no row = 0, a row from before the counter = 1, otherwise the stored counter', () => {
  assert.equal(ratchetRowVersion(undefined), 0);
  assert.equal(ratchetRowVersion({}), 1);
  assert.equal(ratchetRowVersion({ version: 7 }), 7);
});

// ── layer 1: the lock itself ─────────────────────────────────────────────────────────────────────────────────────────

test('lock (in-process queue): exclusive, FIFO, and the release is idempotent', async () => {
  const order: string[] = [];
  const a = await acquirePeerSessionLock('t:excl');
  const b = acquirePeerSessionLock('t:excl').then((rel) => { order.push('b'); return rel; });
  const c = acquirePeerSessionLock('t:excl').then((rel) => { order.push('c'); return rel; });
  await tick();
  assert.deepEqual(order, [], 'nobody gets in while a holds it');
  a(); a();
  const relB = await b;
  await tick();
  assert.deepEqual(order, ['b'], 'b enters first, c is still waiting (a double release did not let c in)');
  relB();
  (await c)();
  assert.deepEqual(order, ['b', 'c']);
});

test('lock: a bounded wait throws RatchetSessionBusyError, and the waiter that gave up does not block the one behind it', async () => {
  const holder = await acquirePeerSessionLock('t:busy');
  await assert.rejects(() => acquirePeerSessionLock('t:busy', 30), RatchetSessionBusyError);
  const behind = acquirePeerSessionLock('t:busy', 500);
  holder();
  (await behind)();
});

test('lock (web locks): requests exactly `tr:<peer>`, holds it until released, and an expired wait is a Busy error', async () => {
  const requested: string[] = [];
  const held = new Set<string>();
  const waiters = new Map<string, Array<() => void>>();
  const fake = {
    request: (name: string, opts: { signal: AbortSignal }, cb: () => Promise<void>) => new Promise<void>((resolve, reject) => {
      requested.push(name);
      const run = () => {
        held.add(name);
        cb().then(resolve, reject).finally(() => { held.delete(name); waiters.get(name)?.shift()?.(); });
      };
      if (!held.has(name)) return run();
      const q = waiters.get(name) ?? []; waiters.set(name, q);
      const entry = () => run();
      q.push(entry);
      opts.signal.addEventListener('abort', () => {
        const i = q.indexOf(entry); if (i >= 0) q.splice(i, 1);
        reject(Object.assign(new Error('aborted'), { name: 'AbortError' }));
      });
    }),
  };
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  Object.defineProperty(globalThis, 'navigator', { value: { locks: fake }, configurable: true, writable: true });
  try {
    const rel = await acquirePeerSessionLock(peerSessionLockName(undefined, 'peer-x'));
    assert.deepEqual(requested, ['tr:peer-x']);
    assert.equal(held.has('tr:peer-x'), true, 'held until we release');
    await assert.rejects(() => acquirePeerSessionLock('tr:peer-x', 30), RatchetSessionBusyError);
    rel();
    await tick();
    assert.equal(held.has('tr:peer-x'), false, 'released');
  } finally {
    if (saved) Object.defineProperty(globalThis, 'navigator', saved); else delete (globalThis as { navigator?: unknown }).navigator;
  }
});

test('the lock name is scoped by owner, so two identities talking to one peer never block each other', () => {
  assert.equal(peerSessionLockName('owner-a', 'p'), 'tr:owner-a:p');
  assert.notEqual(peerSessionLockName('owner-a', 'p'), peerSessionLockName('owner-b', 'p'));
});

// ── SEND ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

test('R5 send, with the lock: two concurrent sends from one state serialise; the peer opens BOTH', async () => {
  const s = await observedSession();
  const [r1, r2] = await Promise.all([send(s, 'first', s.meIO.io), send(s, 'second', s.meIO.io)]);
  assert.equal(r1.ratcheted && r2.ratcheted, true);
  assert.notEqual(r1.wireBody, r2.wireBody);
  assert.equal(s.meIO.log.filter((l) => l.startsWith('put-CONFLICT')).length, 0, 'no conflict: the lock kept them apart');
  assert.equal(s.meIO.rows.get(THEM)?.state === 'ok' && (s.meIO.rows.get(THEM) as { version: number }).version, 3, 'open(1) + two sends = three writes');
  const got = [await openDirectNote(ME, r1.wireBody, s.them, peerOf(s.me), s.themIO.io), await openDirectNote(ME, r2.wireBody, s.them, peerOf(s.me), s.themIO.io)];
  assert.deepEqual(got.sort(), ['first', 'second']);
});

test('R5 send, CAS ALONE (lock disabled): of two sends from one state exactly one wins, the other throws RatchetSessionConflictError and writes nothing', async () => {
  const s = await observedSession();
  const io: RatchetIO = { ...s.meIO.io, ...noLock };
  const results = await Promise.allSettled([send(s, 'first', io), send(s, 'second', io)]);
  assert.deepEqual(results.map((r) => r.status).sort(), ['fulfilled', 'rejected']);
  const lost = results.find((r) => r.status === 'rejected') as PromiseRejectedResult;
  assert.ok(lost.reason instanceof RatchetSessionConflictError);
  assert.equal((s.meIO.rows.get(THEM) as { version: number }).version, 2, 'exactly one advance was stored');
  const won = results.find((r) => r.status === 'fulfilled') as PromiseFulfilledResult<{ wireBody: string }>;
  assert.ok(await openDirectNote(ME, won.value.wireBody, s.them, peerOf(s.me), s.themIO.io), 'and the winner is readable');
});

test('R5 fixture control: with NEITHER the lock nor the CAS the original bug appears: two sends, one message key, the peer can open only one', async () => {
  const s = await observedSession();
  const blind: RatchetIO = { ...s.meIO.io, ...noLock, put: async (fp, snap) => { await s.meIO.io.put(fp, snap, (s.meIO.rows.get(fp) as { version: number }).version); } };
  const [r1, r2] = await Promise.all([send(s, 'first', blind), send(s, 'second', blind)]);
  const opened = [
    await openDirectNote(ME, r1.wireBody, s.them, peerOf(s.me), s.themIO.io),
    await openDirectNote(ME, r2.wireBody, s.them, peerOf(s.me), s.themIO.io),
  ];
  assert.equal(opened.filter((x) => x !== null).length, 1, 'one of the two messages is permanently unreadable: this is what R5 prevents');
});

test('R5 send: a lock that cannot be had in time fails closed, BEFORE any session read or write', async () => {
  const s = await observedSession();
  const held = await acquirePeerSessionLock(LOCK);
  try {
    const logBefore = s.meIO.log.length;
    const io: RatchetIO = { ...s.meIO.io, acquireLock: (fp) => acquirePeerSessionLock(peerSessionLockName(undefined, fp), 30) };
    await assert.rejects(() => send(s, 'x', io), RatchetSessionBusyError);
    assert.equal(s.meIO.log.length, logBefore, 'the session was not touched');
  } finally {
    held(); // a failed assertion above must not leave the lock held for every later test
  }
});

// ── RECEIVE ──────────────────────────────────────────────────────────────────────────────────────────────────────────

/** `them` sends two frames to `me` (me has NO session yet, so the first open is acceptFirst). */
async function twoFrames() {
  const me = ratchetIdentity(), them = ratchetIdentity();
  const meIO = memIO(), themIO = memIO();
  const f1 = (await sealDirectNote(ME, 'one', them, peerOf(me), themIO.io))!;
  const f2 = (await sealDirectNote(ME, 'two', them, peerOf(me), themIO.io))!;
  return { me, them, meIO, f1, f2 };
}

test('R5 receive, with the lock: a second open WAITS for the first to commit, then opens from the advanced state', async () => {
  const t = await twoFrames();
  const a = await openDirectNoteStaged(THEM, t.f1, t.me, peerOf(t.them), t.meIO.io);
  assert.equal(a?.plaintext, 'one');
  let bDone = false;
  const bP = openDirectNoteStaged(THEM, t.f2, t.me, peerOf(t.them), t.meIO.io).then((x) => { bDone = true; return x; });
  await tick();
  assert.equal(bDone, false, 'b is blocked while a holds the session');
  await a!.commit();
  const b = await bP;
  assert.equal(b?.plaintext, 'two', 'b read the state AFTER a committed, so it opened');
  await b!.commit();
  assert.equal(t.meIO.log.filter((l) => l.startsWith('put-CONFLICT')).length, 0);
  assert.equal((t.meIO.rows.get(THEM) as { version: number }).version, 2);
});

test('R5 receive, CAS ALONE (lock disabled): two staged opens on the same S0, the second commit fails CAS, and the RETRY opens', async () => {
  const t = await twoFrames();
  const io: RatchetIO = { ...t.meIO.io, ...noLock };
  const a = await openDirectNoteStaged(THEM, t.f1, t.me, peerOf(t.them), io);
  const b = await openDirectNoteStaged(THEM, t.f2, t.me, peerOf(t.them), io);   // both read S0 (no session yet)
  assert.equal(a?.plaintext, 'one');
  assert.equal(b !== null, true);
  await a!.commit();
  await assert.rejects(() => b!.commit(), RatchetSessionConflictError);
  assert.equal((t.meIO.rows.get(THEM) as { version: number }).version, 1, "b's stale write did not overwrite a's advance");
  const retry = await openDirectNoteStaged(THEM, t.f2, t.me, peerOf(t.them), io);
  assert.equal(retry?.plaintext, 'two', 'the retry reads the current state and opens');
  await retry!.commit();
});

test('R5 receive: the lock is freed on EVERY exit: a null open, release(), a throwing commit, and a second commit/release', async () => {
  const t = await twoFrames();
  const free = async () => { (await acquirePeerSessionLock(LOCK, 50))(); };

  // A body that does not even decode returns before the lock is taken, so it proves nothing. These return null WHILE the lock is held:
  const unreadable = memIO();
  unreadable.rows.set(THEM, { state: 'unreadable' });
  assert.equal(await openDirectNoteStaged(THEM, t.f1, t.me, peerOf(t.them), unreadable.io), null, 'unreadable row: null');
  await free();
  const replay = await openDirectNoteStaged(THEM, t.f1, t.me, peerOf(t.them), t.meIO.io);
  await replay!.commit();
  assert.equal(await openDirectNoteStaged(THEM, t.f1, t.me, peerOf(t.them), t.meIO.io), null, 'replay of a committed frame: null');
  await free();
  t.meIO.rows.clear(); // back to "no session" for the cases below

  const putsBefore = t.meIO.puts();
  const a = await openDirectNoteStaged(THEM, t.f1, t.me, peerOf(t.them), t.meIO.io);
  a!.release(); a!.release();
  await free();
  assert.equal(t.meIO.puts(), putsBefore, 'release() commits nothing');

  const failing = memIO({ failPuts: 1 });
  const c = await openDirectNoteStaged(THEM, t.f1, t.me, peerOf(t.them), failing.io);
  await assert.rejects(() => c!.commit(), /session store write failed/);
  await free();

  const d = await openDirectNoteStaged(THEM, t.f1, t.me, peerOf(t.them), t.meIO.io);
  await d!.commit();
  await assert.rejects(() => d!.commit(), /already ended/);
  await free();
});
