// A restore must never write an owner's records under a different passphrase than that owner's existing records.
// The decision is pure and tested here over its whole truth table. The IndexedDB wiring has no runtime harness in this repo, so it is
// pinned by static guards in the same style as blocker-c-failclosed.test.ts; the browser proof with a no-change control is separate.
//   npx tsx --test src/lib/identity/restore-domain.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  restoreDomainDecision, RestoreDomainRefused, isRestoreDomainRefusal, RESTORE_DOMAIN_CODE, keyRecordOpens, type RestoreDomainFacts,
} from './restore-domain';

const read = (p: string) => readFileSync(new URL(p, import.meta.url), 'utf8');
const facts = (held: boolean, unlocked: boolean, sessionOpens: boolean, passphraseOpens: boolean): RestoreDomainFacts =>
  ({ held, unlocked, sessionOpens, passphraseOpens });
const B = [false, true];

test('an owner this device has never held always proceeds, on every path (a new owner gets a new domain)', () => {
  for (const unlocked of B) for (const sessionOpens of B) for (const passphraseOpens of B) {
    assert.equal(restoreDomainDecision('keeps-open-session', facts(false, unlocked, sessionOpens, passphraseOpens)), 'proceed');
    assert.equal(restoreDomainDecision('always-derives', facts(false, unlocked, sessionOpens, passphraseOpens)), 'proceed');
  }
});

test('keeps-open-session, session open: only the owner\'s own domain may write', () => {
  for (const passphraseOpens of B) {
    assert.equal(restoreDomainDecision('keeps-open-session', facts(true, true, true, passphraseOpens)), 'proceed');
    // The passphrase opening X is no use here: this path writes under the OPEN session, which is someone else's.
    assert.equal(restoreDomainDecision('keeps-open-session', facts(true, true, false, passphraseOpens)), 'refuse');
  }
});

test('keeps-open-session, locked: the incoming passphrase must open the existing rows', () => {
  for (const sessionOpens of B) {
    assert.equal(restoreDomainDecision('keeps-open-session', facts(true, false, sessionOpens, true)), 'proceed');
    assert.equal(restoreDomainDecision('keeps-open-session', facts(true, false, sessionOpens, false)), 'refuse');
  }
});

test('always-derives: this path re-keys the session from the typed passphrase, so only that passphrase counts', () => {
  for (const unlocked of B) for (const sessionOpens of B) {
    assert.equal(restoreDomainDecision('always-derives', facts(true, unlocked, sessionOpens, true)), 'proceed');
    assert.equal(restoreDomainDecision('always-derives', facts(true, unlocked, sessionOpens, false)), 'refuse');
  }
});

test('the refusal is recognisable without instanceof, and says nothing was changed', () => {
  for (const use of ['keeps-open-session', 'always-derives'] as const) {
    const e = new RestoreDomainRefused(use);
    assert.equal(e.code, 'restore-domain');
    assert.equal(RESTORE_DOMAIN_CODE, 'restore-domain');
    assert.ok(isRestoreDomainRefusal(e));
    assert.match(e.message, /nothing was changed/i);
    assert.match(e.message, /new browser profile/i);
  }
  assert.ok(!isRestoreDomainRefusal(new Error('Incorrect passphrase')));
  assert.ok(!isRestoreDomainRefusal(null));
  assert.ok(!isRestoreDomainRefusal({ code: 'other' }));
});

test('the wording a user is given differs where the way forward differs', () => {
  const open = new RestoreDomainRefused('keeps-open-session').message;
  const derive = new RestoreDomainRefused('always-derives').message;
  assert.notEqual(open, derive);
  assert.match(open, /unlock/i);
  assert.match(derive, /current passphrase/i);
});

// ---- the key check, with real WebCrypto ----------------------------------------------------------------------------------------------
const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');
async function aes() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function record(key: CryptoKey, enc_version: unknown = 1) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode('{"k":1}')));
  return { enc_version, iv: b64(iv), ciphertext: b64(ct) };
}

test('keyRecordOpens: true only for the key that wrote the record', async () => {
  const [a, other] = [await aes(), await aes()];
  const r = await record(a);
  assert.equal(await keyRecordOpens(r, a, 1), true);
  assert.equal(await keyRecordOpens(r, other, 1), false, 'a wrong key is a GCM failure, and must read as false');
});

test('keyRecordOpens: every malformed or absent record is false and nothing throws', async () => {
  const a = await aes();
  const good = await record(a);
  for (const bad of [null, undefined, 'x', 7, {}, { ...good, enc_version: 2 }, { ...good, enc_version: undefined }, { ...good, iv: 5 },
    { ...good, ciphertext: null }, { ...good, iv: '!!not base64!!' }, { ...good, ciphertext: '' }, { ...good, iv: '' }]) {
    assert.equal(await keyRecordOpens(bad, a, 1), false, JSON.stringify(bad));
  }
});

test('a tampered ciphertext does not open', async () => {
  const a = await aes();
  const r = await record(a);
  const raw = Buffer.from(r.ciphertext, 'base64');
  raw[0] ^= 1;
  assert.equal(await keyRecordOpens({ ...r, ciphertext: raw.toString('base64') }, a, 1), false);
});

// ---- wiring pins: the guard runs BEFORE any key derivation or write ----------------------------------------------------------------
function before(src: string, a: string, b: string, why: string) {
  const i = src.indexOf(a), j = src.indexOf(b);
  assert.ok(i >= 0, `${a} not found`);
  assert.ok(j >= 0, `${b} not found`);
  assert.ok(i < j, why);
}
const GUARD = 'assertRestoreKeepsOwnerDomain(';

function fnBody(src: string, signature: string): string {
  const start = src.indexOf(signature);
  assert.ok(start >= 0, `${signature} not found`);
  const ends = ['\nexport ', '\n/**'].map((m) => src.indexOf(m, start + 1)).filter((i) => i !== -1);
  return src.slice(start, ends.length ? Math.min(...ends) : src.length);
}

test('vault restore: guard after the fingerprint is derived, before initSessionKey and the import', () => {
  const s = fnBody(read('../../components/recovery/vaultPassphraseRestore.ts'), 'export async function restoreIdentityFromVaultReport');
  before(s, 'reconstructCanonicalIdentityForRestore(', GUARD, 'the guard must use the DERIVED fingerprint, not a claimed one');
  before(s, GUARD, 'initSessionKey(vaultPassphrase)', 'the guard must run before the session key is derived');
  before(s, GUARD, 'importVaultContentsReport(', 'the guard must run before anything is written');
  assert.match(s, /assertRestoreKeepsOwnerDomain\(derivedFp, vaultPassphrase, 'keeps-open-session'\)/);
});

test('seed restore: guard before the unconditional initSessionKey and every write, using the derive-always rule', () => {
  const s = fnBody(read('../../components/recovery/seedVaultRestore.ts'), 'export async function restoreIdentityFromSeedVault');
  before(s, 'reconstructCanonicalIdentityForRestore(', GUARD, 'guard after the fingerprint is derived');
  before(s, GUARD, 'initSessionKey(newPassphrase)', 'guard before the session key is derived');
  before(s, GUARD, 'storeKey(', 'guard before anything is written');
  assert.match(s, /assertRestoreKeepsOwnerDomain\(fingerprint, newPassphrase, 'always-derives'\)/);
});

test('encrypted key-file import: guard before initSessionKey and storeKey', () => {
  const src = read('../../components/SoverentityFrontend.tsx');
  const i = src.indexOf("data.type === 'svrnty-keys'");
  assert.ok(i >= 0);
  const s = src.slice(i, src.indexOf('Raw identity object', i));
  before(s, GUARD, 'initSessionKey(vaultPassphrase)', 'guard before the session key is derived');
  before(s, GUARD, 'storeKey(fp', 'guard before anything is written');
  assert.match(s, /assertRestoreKeepsOwnerDomain\(fp, vaultPassphrase, 'keeps-open-session'\)/);
});

test('plain-backup import: guard right after the identity binds, before the first write', () => {
  const s = fnBody(read('./client-store.ts'), 'export async function importAll');
  before(s, 'assertPlaintextBackupIdentityBinds(backup)', GUARD, 'guard uses the bound fingerprint');
  before(s, GUARD, 'storeIdentity(', 'guard before the first write');
  assert.match(s, /assertRestoreKeepsOwnerDomain\(fingerprint, '', 'keeps-open-session'\)/);
});

test('the gate shows the refusal as itself, never as a wrong passphrase', () => {
  const src = read('../../components/SoverentityFrontend.tsx');
  const handler = src.slice(src.indexOf('const looksLikeDecryptFail') - 400, src.indexOf('const looksLikeDecryptFail'));
  assert.match(handler, /isRestoreDomainRefusal\(err\)/, 'the wrong-passphrase regex matches the word "passphrase": the refusal must be handled first');
});

test('the seed-restore handler also shows the refusal as itself', () => {
  const src = read('../../components/SoverentityFrontend.tsx');
  const i = src.indexOf('restoreIdentityFromSeedVault(arrayBuffer');
  assert.ok(i >= 0);
  const s = src.slice(i, src.indexOf('finally', i));
  assert.match(s, /isRestoreDomainRefusal\(/);
});

test('the store helper computes facts without writing and fails closed', () => {
  const s = read('./client-store.ts');
  const held = fnBody(s, 'export async function deviceHoldsOwner');
  for (const store of ['keys', 'pq_keys', 'vaults', 'shards', 'device_mailbox']) {
    assert.ok(held.includes(`'${store}'`), `deviceHoldsOwner must look in ${store}`);
  }
  assert.match(held, /txGetByIndex[^\n]*'contacts', 'owner'/, 'contact rows count as holding the owner, with no decryption');
  assert.doesNotMatch(held, /txPut|txDelete|decrypt/);
  const opens = fnBody(s, 'export async function sessionOpensOwner');
  assert.match(opens, /if \(!_sessionKey\) return false;/, 'a locked session opens nothing');
  assert.match(opens, /keyRecordOpens\(await txGet<unknown>\('keys', fingerprint\), _sessionKey, ENC_VERSION\)/);
  assert.doesNotMatch(opens, /txPut|txDelete|initSessionKey/);
  const guard = fnBody(s, 'export async function assertRestoreKeepsOwnerDomain');
  assert.match(guard, /restoreDomainDecision\(/);
  assert.match(guard, /throw new RestoreDomainRefused\(/);
  assert.doesNotMatch(guard, /txPut|txDelete|initSessionKey\(/);
});

test('initSessionKey itself is not the guard: a second identity under another passphrase stays legitimate', () => {
  const s = fnBody(read('./client-store.ts'), 'export async function initSessionKey');
  assert.ok(!s.includes(GUARD));
});
