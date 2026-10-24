// src/lib/crypto/unlock-cycle.test.ts
// N10 — per-poll-cycle unlock context lifetime. Run: npx tsx --test src/lib/crypto/unlock-cycle.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from 'openpgp';
import { makeUnlockCycle, UnlockCycleEnded } from './unlock-cycle';
import { lockSession, setActiveFingerprint } from '@/lib/identity/client-store';

async function armoredKey(passphrase: string): Promise<string> {
  const { privateKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 't' }], passphrase, format: 'armored' });
  return privateKey;
}

test('one unlock per cycle: repeated and concurrent key() calls share the same unlocked key', async () => {
  const armored = await armoredKey('pw');
  const c = makeUnlockCycle(armored, 'pw');
  const [a, b] = await Promise.all([c.key(), c.key()]);
  assert.equal(a, b);
  assert.equal(await c.key(), a);
  c.drop();
});

test('drop() ends the cycle: key() rejects afterwards and the reference is released', async () => {
  const armored = await armoredKey('pw');
  const c = makeUnlockCycle(armored, 'pw');
  await c.key();
  c.drop();
  await assert.rejects(c.key(), /unlock cycle ended/);
  c.drop(); // idempotent
});

test('lockSession() kills a live cycle (setActiveFingerprint fires the same hook; not separately tested here)', async () => {
  const armored = await armoredKey('pw');
  const c = makeUnlockCycle(armored, 'pw');
  await c.key();
  lockSession();
  await assert.rejects(c.key(), /unlock cycle ended/);
});

test('a cycle created AFTER a lock is a fresh, working cycle (no cross-cycle reuse of the old key)', async () => {
  const armored = await armoredKey('pw');
  const c1 = makeUnlockCycle(armored, 'pw');
  const k1 = await c1.key();
  lockSession();
  const c2 = makeUnlockCycle(armored, 'pw');
  const k2 = await c2.key();
  assert.notEqual(k1, k2);
  c2.drop();
});

test('wrong passphrase rejects (decrypt failure surfaces, never a silent success)', async () => {
  const armored = await armoredKey('right');
  const c = makeUnlockCycle(armored, 'wrong');
  await assert.rejects(c.key());
  await assert.rejects(c.key());
  c.drop();
});

test('N10 (a): lockSession() DURING an in-flight key() — the awaiting caller is refused the key, not handed it', async () => {
  const armored = await armoredKey('pw');
  const c = makeUnlockCycle(armored, 'pw');
  const inflight = c.key(); // unlock started, not yet resolved
  lockSession(); // lock lands while a decryptor is awaiting
  await assert.rejects(inflight, UnlockCycleEnded);
  assert.equal(c.ended, true);
});

test('N10 (b): setActiveFingerprint() mid-cycle kills the cycle (hook fires synchronously, before its IDB write)', async () => {
  const armored = await armoredKey('pw');
  const c = makeUnlockCycle(armored, 'pw');
  await c.key();
  // The identity switch chokepoint. Its IDB write may reject in a bare-node test env; only the hook matters here.
  void setActiveFingerprint('0'.repeat(40)).catch(() => {});
  assert.equal(c.ended, true);
  await assert.rejects(c.key(), UnlockCycleEnded);
});

test('N10 (b): a normal cycle with 3 concurrent consumers (2 decryptors + signer) unlocks EXACTLY once', async () => {
  const armored = await armoredKey('pw');
  let unlocks = 0;
  const c = makeUnlockCycle(armored, 'pw', { onUnlock: () => { unlocks += 1; } });
  const ks = await Promise.all([c.key(), c.key(), c.key()]);
  await c.key();
  assert.equal(unlocks, 1);
  assert.ok(ks.every((k) => k === ks[0]));
  c.drop();
});

test('N10 (c): two cycles for the same key never share an unlocked key (each tick owns its cycle)', async () => {
  const armored = await armoredKey('pw');
  const c1 = makeUnlockCycle(armored, 'pw');
  const c2 = makeUnlockCycle(armored, 'pw');
  const [k1, k2] = await Promise.all([c1.key(), c2.key()]);
  assert.notEqual(k1, k2);
  c1.drop();
  assert.equal(c2.ended, false, 'dropping one tick\'s cycle does not end another');
  assert.equal(await c2.key(), k2);
  c2.drop();
});
