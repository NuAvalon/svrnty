// src/lib/identity/beacon-key-record.test.ts
// #588 D1/D2 (Flint 11-09): the beacon secret x + its generation + the re-deposit jitter secret are ONE identity-state record: created lazily, stored
// encrypted beside the seeds, carried in the backup (keys.beacon), and STRICTLY validated on restore. This file: the pure half + static guards on the
// IndexedDB-bound half (client-store has no fake-indexeddb here). Run: npx tsx --test src/lib/identity/beacon-key-record.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { isBeaconKeyRecord, newBeaconKeyRecord, secretOf, publicKeyOf, jitterSeedOf, type BeaconKeyRecord } from './beacon-key-record';
import { beaconPublicKey, BEACON_ORDER } from '../crypto/beacon-key';
import { GENERATION_FLOOR } from '../crypto/beacon-generation';

const NOW = (GENERATION_FLOOR + 40 * 86400) * 1000;
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
const le = (x: bigint) => { const o = new Uint8Array(32); let v = x; for (let i = 0; i < 32; i++) { o[i] = Number(v & BigInt(0xff)); v >>= BigInt(8); } return o; };

test('BR1 a new record is valid, its generation is clock-seeded, and secret and jitter come from two separate random draws', async () => {
  const calls: number[] = [];
  const rec = await newBeaconKeyRecord(NOW, undefined, (n) => { calls.push(n); return crypto.getRandomValues(new Uint8Array(n)); });
  assert.equal(isBeaconKeyRecord(rec), true);
  assert.equal(rec.key_generation, GENERATION_FLOOR + 40 * 86400);
  assert.ok(calls.length >= 2, 'at least two draws (secret, jitter)');
  assert.notEqual(rec.secret, rec.jitter_secret);
});

test('BR2 regenerating with a previous record never goes backward and gives a DIFFERENT secret (D3)', async () => {
  const a = await newBeaconKeyRecord(NOW);
  const b = await newBeaconKeyRecord(NOW, a); // same clock second: must still be higher
  assert.equal(b.key_generation, a.key_generation + 1);
  assert.notEqual(b.secret, a.secret);
  assert.notEqual(b.jitter_secret, a.jitter_secret);
});

test('BR3 JSON round trip (what a backup does) keeps the record valid and reproduces the SAME public key (restore reproduces Y)', async () => {
  const a = await newBeaconKeyRecord(NOW);
  const back = JSON.parse(JSON.stringify(a)) as BeaconKeyRecord;
  assert.equal(isBeaconKeyRecord(back), true);
  assert.equal(await publicKeyOf(back), await publicKeyOf(a));
  assert.equal(await publicKeyOf(a), await beaconPublicKey(secretOf(a)));
  assert.deepEqual(jitterSeedOf(back), jitterSeedOf(a));
});

test('BR4 STRICT validation on restore: x = 0, x >= l, wrong length, non-canonical base64, extra or missing fields, bad generation, bad jitter are all refused', async () => {
  const good = await newBeaconKeyRecord(NOW);
  const bad: Array<[string, unknown]> = [
    ['x = 0', { ...good, secret: b64(le(BigInt(0))) }],
    ['x = l', { ...good, secret: b64(le(BEACON_ORDER)) }],
    ['x = l + 1', { ...good, secret: b64(le(BEACON_ORDER + BigInt(1))) }],
    ['x = 2^251 - 1', { ...good, secret: b64(le(BigInt(2) ** BigInt(251) - BigInt(1))) }],
    ['31 bytes', { ...good, secret: b64(new Uint8Array(31).fill(1)) }],
    ['33 bytes', { ...good, secret: b64(new Uint8Array(33).fill(1)) }],
    ['no padding', { ...good, secret: good.secret.replace(/=+$/, '') }],
    ['not base64', { ...good, secret: '!'.repeat(44) }],
    ['jitter 31 bytes', { ...good, jitter_secret: b64(new Uint8Array(31).fill(2)) }],
    ['generation 0', { ...good, key_generation: 0 }],
    ['generation float', { ...good, key_generation: 1.5 }],
    ['generation string', { ...good, key_generation: String(good.key_generation) }],
    ['generation above cap', { ...good, key_generation: 2 ** 31 }],
    ['extra field', { ...good, note: 'x' }],
    ['missing jitter', { secret: good.secret, key_generation: good.key_generation }],
    ['null', null], ['array', []], ['string', 'x'], ['number', 5],
  ];
  for (const [label, v] of bad) assert.equal(isBeaconKeyRecord(v), false, label);
});

test('BR5 the restore range check accepts a PAST generation (no floor/future test at restore: those apply at mint and receive), but still requires an integer in [1, 2^31-1]', async () => {
  const good = await newBeaconKeyRecord(NOW);
  assert.equal(isBeaconKeyRecord({ ...good, key_generation: 1 }), true);
  assert.equal(isBeaconKeyRecord({ ...good, key_generation: 2 ** 31 - 1 }), true);
});

// ── STATIC GUARDS on client-store / vault / the export dialog ───────────────────────────────────────────────────────
const store = () => readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');

test('BR6 [static] the record lives under its own reserved AAD id, distinct from the other reserved ids, per owner', () => {
  const s = store();
  const m = s.match(/const BEACON_KEY_RECORD_ID = '([^']+)'/);
  assert.ok(m);
  assert.ok(!['piece2:suppression', 'piece2:held-affirms', 'piece588:beacon-seeds'].includes(m![1]));
  assert.ok(s.includes('beacon_key:${ownerFingerprint}'));
});

test('BR7 [static] getBeaconKeyRecord returns null on any doubt; ensureBeaconKeyRecord creates with an ATOMIC add (not get-then-put) and adopts the winner on a conflict; nothing is stored unencrypted', () => {
  const s = store();
  const get = s.slice(s.indexOf('export async function getBeaconKeyRecord'), s.indexOf('export async function ensureBeaconKeyRecord'));
  assert.match(get, /if \(!_sessionKey\) return null/);
  assert.match(get, /isBeaconKeyRecord\(/);
  assert.match(get, /catch \{\s*return null/);
  const ens = s.slice(s.indexOf('export async function ensureBeaconKeyRecord'), s.indexOf('export async function importBeaconKeyRecord'));
  assert.match(ens, /if \(!_sessionKey\) throw new Error\(/);
  assert.match(ens, /encryptContactRecord\(_sessionKey, BEACON_KEY_RECORD_ID/);
  assert.match(ens, /txAdd\('settings'/);
  assert.ok(!/txPut\('settings'/.test(ens), 'creation must not be a blind put (two tabs would overwrite each other)');
  assert.match(ens, /getBeaconKeyRecord\(ownerFingerprint\)/, 'after a lost race it re-reads and adopts the stored record');
});

test('BR8 [static] importBeaconKeyRecord (the restore path) validates strictly, creates ONLY if absent (never overwrites a held record), and the vault restore calls it best-effort after the PQ keys', () => {
  const s = store();
  const imp = s.slice(s.indexOf('export async function importBeaconKeyRecord'), s.indexOf('export async function listIdentities'));
  assert.match(imp, /isBeaconKeyRecord\(/);
  assert.match(imp, /txAdd\('settings'/);
  assert.ok(!/txPut\('settings'/.test(imp));
  assert.match(s, /contents\.keys\?\.beacon/);
  const at = s.indexOf('contents.keys?.beacon');
  assert.ok(at > s.indexOf('await storePQKeys(fp, contents.keys.pq)'), 'after the PQ keys');
  assert.match(s.slice(at - 120, at + 260), /try \{[\s\S]*importBeaconKeyRecord[\s\S]*\} catch/, 'a bad or failing beacon record must never fail the restore');
});

test('BR9 [static] the backup carries it: VaultKeys has an OPTIONAL beacon field and the export dialog adds it only when a record exists', () => {
  const vault = readFileSync(new URL('../sync/vault.ts', import.meta.url), 'utf8');
  assert.match(vault, /beacon\?: BeaconKeyRecord/);
  const dlg = readFileSync(new URL('../../components/export/VaultExportDialog.tsx', import.meta.url), 'utf8');
  assert.match(dlg, /getBeaconKeyRecord\(/);
  const keysAt = dlg.indexOf('const vaultKeys = {');
  const createAt = dlg.indexOf('createVaultContents(\n');
  const keysBlock = dlg.slice(keysAt, dlg.indexOf('};', keysAt));
  assert.ok(keysAt > -1 && createAt > keysAt, 'vaultKeys is built before the contents');
  assert.match(keysBlock, /\.\.\.\(beaconKey \? \{ beacon: beaconKey \} : \{\}\)/, 'the beacon record is spread into vaultKeys ONLY when one exists');
});
