// src/lib/messaging/ratchet-reset-720.test.ts
//
// #720 RESET, Flint reset-semantics v1 (shared/outbox/flint/ratchet_reset_semantics_v1.md), the SESSION half: R1 (what the reset drops) and R3 (the next
// outbound note starts the new session). Real ratchet crypto (TripleRatchet, real X25519 + ML-KEM-1024); the only fake is session STORAGE (memIO).
//   N-R1  the reset deletes ONLY that contact's row: other contacts' rows are byte-identical, and nothing else is touched.
//   N-R1b it takes the per-peer lock (so it cannot race an open or a seal) and releases it, even if the delete throws.
//   N-R1c an UNREADABLE row is cleared too (that is exactly when a user resets), and an absent row is a no-op that says so.
//   N-R1d a store that is locked or open for another identity cannot be reset by this owner (the owner-bound wrapper throws before deleting).
//   N-R3  after a reset the next seal is a FIRST frame: a peer with no session opens it, and it did not continue the dropped session.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq';
import type { RatchetIdentity, RatchetPeer } from '../crypto/message-ratchet';
import { openDirectNote, ownerBoundRatchetIO, resetRatchetSession, sealDirectNote, type RatchetIO } from './direct-session';
import { memIO } from './ratchet-test-io';

function ratchetIdentity(): RatchetIdentity {
  const x25519Sec = x25519.utils.randomSecretKey();
  const kem = generateKEMKeypair();
  return { x25519Sec, x25519Pub: x25519.getPublicKey(x25519Sec), mlkem1024Sec: kem.secretKey, mlkem1024Pub: kem.publicKey };
}
const peerOf = (id: RatchetIdentity): RatchetPeer => ({ x25519Pub: id.x25519Pub, mlkem1024Pub: id.mlkem1024Pub });

const ME = 'fp-me', A = 'fp-alice', B = 'fp-bob';

/** `me` holds a session with both Alice and Bob (each opened a first frame from `me`'s peer side is not needed: me initiates). */
async function twoSessions() {
  const me = ratchetIdentity(), alice = ratchetIdentity(), bob = ratchetIdentity();
  const meIO = memIO();
  assert.ok(await sealDirectNote(A, 'to alice', me, peerOf(alice), meIO.io));
  assert.ok(await sealDirectNote(B, 'to bob', me, peerOf(bob), meIO.io));
  return { me, alice, bob, meIO };
}

test('N-R1 reset deletes ONLY that contact\'s session row: the other contact\'s row is byte-identical, and only one remove happened', async () => {
  const { meIO } = await twoSessions();
  const bobBefore = JSON.stringify(meIO.rows.get(B));
  const logBefore = meIO.log.length;
  assert.equal(await resetRatchetSession(ME, A, meIO.io), true);
  assert.equal(meIO.rows.has(A), false, 'alice\'s row is gone');
  assert.equal(JSON.stringify(meIO.rows.get(B)), bobBefore, 'bob\'s row is untouched');
  assert.deepEqual(meIO.log.slice(logBefore), [`remove:${A}`], 'the reset did exactly one thing: remove alice (no reads or writes of anyone else)');
});

test('N-R1b the reset runs under the per-peer lock for THAT peer, and releases it even when the delete throws', async () => {
  const { meIO } = await twoSessions();
  const order: string[] = [];
  const io: RatchetIO = {
    ...meIO.io,
    remove: async (fp) => { order.push(`remove:${fp}`); return meIO.io.remove(fp); },
    acquireLock: async (fp) => { order.push(`lock:${fp}`); return () => { order.push(`unlock:${fp}`); }; },
  };
  await resetRatchetSession(ME, A, io);
  assert.deepEqual(order, [`lock:${A}`, `remove:${A}`, `unlock:${A}`], 'lock, delete, unlock: in that order, for alice only');

  order.length = 0;
  const boom: RatchetIO = { ...io, remove: async (fp) => { order.push(`remove:${fp}`); throw new Error('store write failed'); } };
  await assert.rejects(resetRatchetSession(ME, B, boom), /store write failed/);
  assert.deepEqual(order, [`lock:${B}`, `remove:${B}`, `unlock:${B}`], 'the lock is released on the failure path');
  assert.equal(meIO.rows.has(B), true, 'a failed reset leaves the row');
});

test('N-R1c an UNREADABLE row is cleared (the case a user resets for); an absent row is a no-op that reports false', async () => {
  const meIO = memIO();
  meIO.rows.set(A, { state: 'unreadable' });
  assert.equal(await resetRatchetSession(ME, A, meIO.io), true);
  assert.deepEqual(await meIO.io.read(A), { state: 'absent' });
  assert.equal(await resetRatchetSession(ME, A, meIO.io), false, 'nothing left to delete');
});

test('N-R1d a session store that is locked or open for ANOTHER identity cannot be reset by this owner: it throws before deleting anything', async () => {
  const { meIO } = await twoSessions();
  const wrong = ownerBoundRatchetIO(ME, () => 'fp-someone-else', meIO.io);
  const logBefore = meIO.log.length;
  await assert.rejects(resetRatchetSession(ME, A, wrong));
  assert.equal(meIO.rows.has(A), true);
  assert.equal(meIO.log.slice(logBefore).some((l) => l.startsWith('remove:')), false, 'the inner store was never asked to delete');
  const locked = ownerBoundRatchetIO(ME, () => null, meIO.io);
  await assert.rejects(resetRatchetSession(ME, A, locked));
  assert.equal(meIO.rows.has(A), true);
  const right = ownerBoundRatchetIO(ME, () => ME, meIO.io);
  assert.equal(await resetRatchetSession(ME, A, right), true, 'control: the right owner can');
});

test('N-R3 after a reset the next seal is a FIRST frame: a peer with NO session opens it, and the dropped session is not continued', async () => {
  const me = ratchetIdentity(), alice = ratchetIdentity();
  const meIO = memIO(), aliceIO = memIO();
  const before = await sealDirectNote(A, 'old session', me, peerOf(alice), meIO.io);
  assert.ok(before);
  assert.equal(await openDirectNote(ME, before!, alice, peerOf(me), aliceIO.io), 'old session', 'control: the old session works');
  await resetRatchetSession(ME, A, meIO.io);
  const after = await sealDirectNote(A, 'new session', me, peerOf(alice), meIO.io);
  assert.ok(after);
  assert.notEqual(after, before);
  const freshAlice = memIO(); // a receiver with no row for me at all
  assert.equal(await openDirectNote(ME, after!, alice, peerOf(me), freshAlice.io), 'new session', 'a first frame opens on a peer with no session');
  const cont = await openDirectNote(ME, after!, alice, peerOf(me), aliceIO.io);
  assert.equal(cont, null, 'a peer that still holds the OLD session cannot open it yet: that is why the receiving side needs R5');
});

// ── STATIC GUARDS for the IndexedDB-bound half (this repo has no fake-indexeddb runtime harness for store.ts; the real-browser proof is the
// reset UI's Playwright e2e). These pin the shape the runtime tests above rely on.
const src = (f: string) => readFileSync(new URL(f, import.meta.url), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/[^\n]*/g, '$1');

test('W2 static: the reset defaults to the OWNER-BOUND store and the real store maps remove -> deleteRatchetSession', () => {
  const ds = src('./direct-session.ts');
  assert.match(ds, /export async function resetRatchetSession\(ownerFingerprint: string, peerFingerprint: string, io: RatchetIO = ownerBoundRatchetIO\(ownerFingerprint\)\)/, 'a caller who passes no io must get the owner check');
  assert.match(ds, /realRatchetIO: RatchetIO = \{[^}]*remove: deleteRatchetSession/);
  assert.match(ds, /remove: async \(peerFp\) => \{ assertNotesStoreOpenFor\(openOwner\(\), ownerFingerprint\); return inner\.remove\(peerFp\); \}/);
  const body = ds.slice(ds.indexOf('export async function resetRatchetSession'));
  assert.match(body.slice(0, 400), /lockSession\(io, peerFingerprint\)[\s\S]*try \{[\s\S]*io\.remove\(peerFingerprint\)[\s\S]*finally \{\s*release\(\)/);
});

test('W3 static: deleteRatchetSession touches ONLY the ratchet_sessions store, deletes by the one peer key, in a single readwrite transaction', () => {
  const st = src('./store.ts');
  const fn = st.slice(st.indexOf('export async function deleteRatchetSession'), st.indexOf('export async function getRatchetSession'));
  assert.match(fn, /db\.transaction\('ratchet_sessions', 'readwrite'\)/);
  assert.match(fn, /os\.delete\(peerFingerprint\)/);
  assert.doesNotMatch(fn, /\.clear\(|deleteDatabase|transaction\(\[|'notes'|'threads'|'contacts'|dead_letter/, 'never a clear(), another store, or a bulk delete');
  assert.equal((fn.match(/os\.delete\(/g) ?? []).length, 1);
});

test('W4 static: resetMessageSession deletes the SESSION first and marks the held frames second (marking first could release frames for a reset that failed); the store reads/writes the right rows', () => {
  const sr = src('./session-reset.ts');
  const body = sr.slice(sr.indexOf('export async function resetMessageSession'));
  assert.ok(body.indexOf('resetRatchetSession(') > -1 && body.indexOf('resetRatchetSession(') < body.indexOf('markSessionReset('), 'session delete BEFORE marking');
  assert.match(body, /markSessionReset\(peerFingerprint\.toLowerCase\(\)\)/);
  const ds = src('./dead-letter-store.ts');
  assert.match(ds, /resetMarksFor\(await listDeadLetters\(\), peerFp\)[\s\S]*putDeadLetter\(m\)/);
  assert.match(ds, /r\.reason === 'session-reset' && r\.fp\) out\.set\(r\.envelope_id, r\.fp\)/);
  assert.match(src('../sync/live-book-poll.ts'), /releasedByReset: async \(\) => \{\s*assertNotesStoreOpenFor\(openOwner\(\), owner\.fingerprint\);\s*return releasedByReset\(\);/, 'the sink method is owner-checked');
});
