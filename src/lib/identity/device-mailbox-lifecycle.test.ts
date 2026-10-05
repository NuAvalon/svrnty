// src/lib/identity/device-mailbox-lifecycle.test.ts
// piece-2 device-mailbox — STATIC SOURCE GUARDS for the storage/genesis/unlock wiring that has no
// fake-indexeddb runtime harness. Same style as blocker-c-failclosed.test.ts: the behavior is enforced
// at runtime, these pins stop a future edit from silently regressing the fail-closed / lifecycle invariants.
//   npx tsx --test src/lib/identity/device-mailbox-lifecycle.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const clientStore = () => readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
const browserIdentity = () => readFileSync(new URL('./browser-identity.ts', import.meta.url), 'utf8');
const genesisHooks = () => readFileSync(new URL('./identity-genesis-hooks.ts', import.meta.url), 'utf8');

function fnBody(src: string, signature: string): string {
  const start = src.indexOf(signature);
  assert.ok(start >= 0, `${signature} not found`);
  const next = src.indexOf('\nexport ', start + 1);
  const nextPriv = src.indexOf('\nasync function ', start + 1);
  const end = Math.min(next === -1 ? src.length : next, nextPriv === -1 ? src.length : nextPriv);
  return src.slice(start, end);
}

test('client-store: DB_VERSION bumped to 4 and the device_mailbox store is created on upgrade', () => {
  const src = clientStore();
  assert.match(src, /const DB_VERSION = 4;/, 'DB_VERSION must be 4 (device_mailbox store added)');
  assert.match(src, /createObjectStore\('device_mailbox', \{ keyPath: 'fingerprint' \}\)/, 'device_mailbox store must be created keyed by fingerprint');
  // created inside onupgradeneeded (guarded by a contains() check like the other stores)
  assert.match(src, /objectStoreNames\.contains\('device_mailbox'\)/, 'device_mailbox creation must be idempotent-guarded');
});

test('client-store: storeDeviceMailbox fails closed when locked (no plaintext else-fallback)', () => {
  const body = fnBody(clientStore(), 'export async function storeDeviceMailbox(');
  assert.match(body, /if \(!_sessionKey\)/, 'must guard on a missing session key');
  assert.match(body, /throw new Error\(/, 'must throw when locked (Blocker-C fail-closed)');
  assert.doesNotMatch(body, /}\s*else\s*{/, 'must not keep a plaintext else-fallback');
  assert.match(body, /encryptKeyData\(/, 'must encrypt the serialized keypair at rest');
});

test('client-store: loadDeviceMailbox returns null ONLY on absence; THROWS on present-but-unreadable', () => {
  const body = fnBody(clientStore(), 'export async function loadDeviceMailbox(');
  assert.match(body, /if \(!record\) return null;/, 'genuine absence → null (safe to lazy-init)');
  // a present record that is not enc_version is corrupt → throw, NEVER silently null (which would
  // regenerate-overwrite possibly-recoverable key material / churn mailbox_fp on a transient fault).
  assert.match(body, /enc_version !== ENC_VERSION/, 'must detect a non-encrypted (corrupt) record');
  assert.match(body, /throw new Error\(/, 'present-but-malformed must throw, not collapse to null');
  assert.doesNotMatch(body, /catch\s*\{[^}]*return null/, 'must not swallow a decrypt-fail into null');
});

test('client-store: initSessionKey ensures device mailboxes on unlock (after the eager key-store migrate)', () => {
  const body = fnBody(clientStore(), 'export async function initSessionKey(');
  const eagerAt = body.indexOf('eagerMigrateIdentityStoresOnUnlock()');
  const ensureAt = body.indexOf('ensureDeviceMailboxesOnUnlock()');
  assert.ok(eagerAt >= 0, 'initSessionKey must still run the eager key-store migrate');
  assert.ok(ensureAt > eagerAt, 'ensureDeviceMailboxesOnUnlock must run on unlock, after the eager migrate');
});

test('client-store: ensureDeviceMailboxesOnUnlock regenerates ONLY on absence and never overwrites an unreadable record', () => {
  const body = fnBody(clientStore(), 'async function ensureDeviceMailboxesOnUnlock(');
  assert.match(body, /if \(existing\) continue;/, 'a readable mailbox is left untouched');
  assert.match(body, /initDeviceMailboxAtGenesis\(fp\)/, 'absent → lazy-init a fresh mailbox');
  // the outer catch (present-but-unreadable) must NOT call a store/init — it warns and skips.
  const catchAt = body.lastIndexOf('} catch (e) {');
  assert.ok(catchAt >= 0, 'must catch the present-but-unreadable throw');
  const tail = body.slice(catchAt);
  assert.doesNotMatch(tail, /initDeviceMailboxAtGenesis|storeDeviceMailbox/, 'the unreadable path must never overwrite');
  assert.match(tail, /not overwriting/, 'the unreadable path documents that it does not overwrite');
});

test('client-store: getMyDeviceMailbox returns secrets+publicKeys+fp for the active identity', () => {
  const body = fnBody(clientStore(), 'export async function getMyDeviceMailbox(');
  assert.match(body, /getActiveFingerprint\(\)/, 'defaults to the active identity');
  assert.match(body, /loadDeviceMailbox\(fp\)/, 'reads through the fail-closed loader');
  assert.match(body, /secrets:/, 'returns the receive secrets');
  assert.match(body, /publicKeys:/, 'returns the publishable public keys');
});

test('browser-identity: genesis generates the mailbox BEFORE storeIdentity and fires genesis hooks AFTER', () => {
  const src = browserIdentity();
  const genAt = src.indexOf('initDeviceMailboxAtGenesis(fingerprint)');
  const storeAt = src.indexOf('storeIdentity(fingerprint, identity)');
  const hooksAt = src.indexOf('runGenesisHooks(fingerprint)');
  assert.ok(genAt >= 0, 'genesis must generate the device mailbox');
  assert.ok(storeAt >= 0, 'genesis must store the identity');
  assert.ok(hooksAt >= 0, 'genesis must fire the run-once hooks');
  assert.ok(genAt < storeAt, 'the public block must be stamped on the identity BEFORE it is persisted');
  assert.ok(hooksAt > storeAt, 'hooks fire AFTER the identity is committed (keyed to a persisted fp)');
  assert.match(src, /identity\.device_mailbox = await initDeviceMailboxAtGenesis/, 'the public block is cached on the identity wrapper');
});

test('genesis-hooks: runGenesisHooks is best-effort (swallows a throwing hook — fail-closed consumer contract)', () => {
  const body = fnBody(genesisHooks(), 'export async function runGenesisHooks(');
  assert.match(body, /try \{/, 'each hook runs in a try');
  assert.match(body, /catch \(e\)/, 'a throwing hook is caught');
  assert.match(body, /console\.warn/, 'a failed hook is surfaced, not silent');
  assert.doesNotMatch(body, /throw /, 'runGenesisHooks must never throw into the mint flow');
});

test('client-store: SovereignBackup carries device_mailbox; import validates the shape before persisting', () => {
  const src = clientStore();
  assert.match(src, /device_mailbox\?: ReturnType<typeof serializeMailboxKeypair>;/, 'backup type carries the serialized keypair');
  const importBody = fnBody(src, 'export async function importAll(');
  assert.match(importBody, /deserializeMailboxKeypair\(backup\.device_mailbox\)/, 'import validates the untrusted shape BEFORE storing (no soft-lock)');
  assert.match(importBody, /storeDeviceMailbox\(fingerprint, backup\.device_mailbox\)/, 'a valid backup mailbox is restored (continuity)');
});
