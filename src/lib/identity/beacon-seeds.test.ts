// src/lib/identity/beacon-seeds.test.ts
// #588 piece B: the ONE-TIME deposit seeds the client must keep so it can sign a later poll/withdraw. This file tests the PURE half (map ops, validation,
// expiry) and STATIC GUARDS on the IndexedDB-bound half (client-store has no fake-indexeddb runtime harness; the real-browser proof comes with the wiring).
// Run: npx tsx --test src/lib/identity/beacon-seeds.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  seedKey, isBeaconSeeds, addSeed, removeSeed, sweepExpired, MAX_SEEDS, type BeaconSeedEntry, type BeaconSeeds,
} from './beacon-seeds';
import { expiryForEpoch } from './beacon-seed-expiry';

const b64 = (n: number) => Buffer.from(new Uint8Array(32).fill(n)).toString('base64');
const entry = (over: Partial<BeaconSeedEntry> = {}): BeaconSeedEntry => ({ epoch: '2900', H_e: '12345', N: '67890', seed: b64(7), expiresAtMs: 2_000_000_000_000, ...over });

test('BS1 seedKey is H_e:N for canonical decimals and refuses anything else (no leading zeros, no signs, no hex, no length abuse)', () => {
  assert.equal(seedKey('12345', '67890'), '12345:67890');
  assert.equal(seedKey('0', '0'), '0:0');
  for (const bad of ['', '01', '-1', '1.5', '0x10', ' 1', '1 ', '1e3', 'abc', '9'.repeat(78), 5 as any, null as any]) {
    assert.throws(() => seedKey(bad, '1'), /canonical/i, String(bad));
    assert.throws(() => seedKey('1', bad), /canonical/i, String(bad));
  }
});

test('BS2 addSeed returns a NEW map (the input is never mutated) and is idempotent for the same seed', () => {
  const m0: BeaconSeeds = {};
  const m1 = addSeed(m0, entry());
  assert.deepEqual(m0, {}, 'input untouched');
  assert.deepEqual(Object.keys(m1), ['12345:67890']);
  const m2 = addSeed(m1, entry());
  assert.deepEqual(m2, m1);
});

test('BS3 the SAME (H_e, N) with a DIFFERENT seed is refused: an existing seed is never overwritten (that would strand a live deposit)', () => {
  const m1 = addSeed({}, entry());
  assert.throws(() => addSeed(m1, entry({ seed: b64(9) })), /conflict/i);
});

test('BS4 an entry must carry a 32-byte seed, a canonical epoch, and a finite expiry', () => {
  const bad: Array<Partial<BeaconSeedEntry>> = [
    { seed: Buffer.from(new Uint8Array(31)).toString('base64') },
    { seed: Buffer.from(new Uint8Array(33)).toString('base64') },
    { seed: 'not base64!' },
    { seed: '' },
    { epoch: '01' },
    { epoch: 'x' },
    { expiresAtMs: Number.NaN },
    { expiresAtMs: Infinity },
    { expiresAtMs: -1 },
    { expiresAtMs: '5' as any },
  ];
  for (const b of bad) assert.throws(() => addSeed({}, entry(b)), /invalid/i, JSON.stringify(b).slice(0, 60));
});

test('BS5 removeSeed drops exactly one entry and tolerates a missing one', () => {
  const m = addSeed(addSeed({}, entry()), entry({ H_e: '1', N: '2' }));
  const r = removeSeed(m, '12345', '67890');
  assert.deepEqual(Object.keys(r), ['1:2']);
  assert.deepEqual(removeSeed(r, '9', '9'), r);
});

test('BS6 sweepExpired removes entries whose expiry has PASSED (strictly), keeps the rest, and counts only what it removed', () => {
  let m: BeaconSeeds = {};
  m = addSeed(m, entry({ H_e: '1', N: '1', expiresAtMs: 1000 }));
  m = addSeed(m, entry({ H_e: '2', N: '2', expiresAtMs: 2000 }));
  m = addSeed(m, entry({ H_e: '3', N: '3', expiresAtMs: 3000 }));
  const { kept, removed } = sweepExpired(m, 2000);
  assert.equal(removed, 1, 'expiry == now is NOT yet expired');
  assert.deepEqual(Object.keys(kept).sort(), ['2:2', '3:3']);
  assert.equal(sweepExpired(kept, 2000).removed, 0);
});

test('BS7 expiryForEpoch = the end of the epoch plus one grace window, from the ONE definition in beacon-wire', async () => {
  const wire: any = await import('../crypto/beacon-wire.mjs');
  const e = 2900;
  assert.equal(expiryForEpoch(BigInt(e)), (e + 1) * wire.EPOCH_SECONDS * 1000 + wire.GRACE_SECONDS * 1000);
});

test('BS8 the map is bounded: the (MAX_SEEDS+1)th distinct entry is refused, an existing one is still idempotent', () => {
  let m: BeaconSeeds = {};
  for (let i = 0; i < MAX_SEEDS; i++) m = addSeed(m, entry({ H_e: String(i), N: String(i) }));
  assert.throws(() => addSeed(m, entry({ H_e: '999999', N: '1' })), /full/i);
  assert.deepEqual(addSeed(m, entry({ H_e: '0', N: '0' })), m);
});

test('BS9 isBeaconSeeds accepts exactly what addSeed produces and refuses a tampered shape (extra keys, wrong key format, key not matching its entry)', () => {
  const m = addSeed({}, entry());
  assert.equal(isBeaconSeeds(m), true);
  assert.equal(isBeaconSeeds({}), true);
  const wrongKey = { '1:2': entry() }; // key says 1:2, entry says 12345:67890
  const extra = { '12345:67890': { ...entry(), plaintextNote: 'hi' } };
  const badKey = { 'not-a-key': entry() };
  for (const x of [wrongKey, extra, badKey, null, undefined, [], 'x', 5, { '12345:67890': null }]) assert.equal(isBeaconSeeds(x), false, JSON.stringify(x)?.slice(0, 50));
});

// ── STATIC GUARDS on client-store (the IndexedDB-bound half) ─────────────────────────────────────────────────────────
const store = () => readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');

test('BS10 [static] client-store holds the seeds under a RESERVED AAD id, distinct from the other reserved ids', () => {
  const s = store();
  const m = s.match(/const BEACON_SEEDS_RECORD_ID = '([^']+)'/);
  assert.ok(m, 'BEACON_SEEDS_RECORD_ID is declared');
  assert.ok(!['piece2:suppression', 'piece2:held-affirms'].includes(m![1]));
  assert.ok(s.includes('beacon_seeds:${ownerFingerprint}') || s.includes('`beacon_seeds:${'), 'the settings key is per owner');
});

test('BS11 [static] setBeaconSeeds throws when locked and encrypts BEFORE it writes; getBeaconSeeds returns null when locked, absent, or malformed', () => {
  const s = store();
  const set = s.slice(s.indexOf('export async function setBeaconSeeds'), s.indexOf('export async function setBeaconSeeds') + 700);
  assert.match(set, /if \(!_sessionKey\) throw new Error\(/);
  const encAt = set.indexOf('encryptContactRecord(_sessionKey, BEACON_SEEDS_RECORD_ID');
  const putAt = set.indexOf("txPut('settings'");
  assert.ok(encAt > -1 && putAt > encAt, 'encrypt, then put');
  assert.ok(!/txPut\('settings', \{ key: beaconSeedsSettingKey\(ownerFingerprint\), value: map/.test(s), 'the plain map is never the stored value');
  const get = s.slice(s.indexOf('export async function getBeaconSeeds'), s.indexOf('export async function getBeaconSeeds') + 900);
  assert.match(get, /if \(!_sessionKey\) return null/);
  assert.match(get, /isBeaconSeeds\(/);
  assert.match(get, /catch \{\s*return null/);
});

test('BS12 [static] the seeds are NOT part of the .svrnty backup (packVault takes an explicit VaultContents, which has no seed field): per-deposit and short-lived, so a restore re-deposits', () => {
  const vault = readFileSync(new URL('../sync/vault.ts', import.meta.url), 'utf8');
  assert.ok(!/beacon_seed|BeaconSeed/i.test(vault), 'vault.ts never mentions the seeds');
  assert.ok(/export async function packVault\(contents: VaultContents/.test(vault), 'packVault still takes an explicit contents object (if it ever dumps whole stores, this guard must be revisited)');
});

test('BS13 [static] beacon-seeds.ts (imported by client-store, so in the main bundle) does not import beacon-wire, snarkjs or circomlibjs', () => {
  const src = readFileSync(new URL('./beacon-seeds.ts', import.meta.url), 'utf8');
  assert.ok(!/^import .*(beacon-wire|snarkjs|circomlibjs)/m.test(src));
});
