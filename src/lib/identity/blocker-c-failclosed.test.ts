// Blocker-C invariant (Archie #133842): NO plaintext key material at rest, ever — not even
// transiently. The four client-store key-material stores must FAIL CLOSED (throw) when no session
// key is present rather than fall back to a plaintext txPut, and the passphrase-free recovery path
// (restoreIdentityFromSeedVault) must establish the session key BEFORE it writes any key material.
//
// Static source guard (same style as plaintext-import.test.ts): the runtime already enforces this
// via the throw, but this test stops a future change from silently re-introducing an else-plaintext
// fallback or reordering the recovery write ahead of initSessionKey().

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('client-store: the 4 key-material stores fail closed (no plaintext else-fallback)', () => {
  const src = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
  for (const fn of ['storeKey', 'storePQKeys', 'storeVault', 'storeShards']) {
    const start = src.indexOf(`export async function ${fn}(`);
    assert.ok(start >= 0, `${fn} not found`);
    const body = src.slice(start, src.indexOf('\nexport ', start + 1));
    assert.match(body, /if \(!_sessionKey\)/, `${fn} must guard on a missing session key`);
    assert.match(body, /throw new Error\(/, `${fn} must throw when locked (fail-closed)`);
    // No else-branch that would write the value in the clear.
    assert.doesNotMatch(body, /}\s*else\s*{/, `${fn} must not keep a plaintext else-fallback`);
  }
});

test('importAll: blocks a plaintext-backup import unless a session is established (3a/block)', () => {
  const src = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
  const start = src.indexOf('export async function importAll(');
  const body = src.slice(start, src.indexOf('\nexport ', start + 1));
  const guardAt = body.indexOf('isSessionUnlocked()');
  const firstStoreAt = body.indexOf('storeIdentity(');
  assert.ok(guardAt >= 0, 'importAll must guard on isSessionUnlocked()');
  assert.ok(firstStoreAt > guardAt, 'the session guard must run before any write');
});

test('seedVaultRestore: establishes the session key BEFORE writing key material', () => {
  const src = readFileSync(
    new URL('../../components/recovery/seedVaultRestore.ts', import.meta.url),
    'utf8',
  );
  const initAt = src.indexOf('initSessionKey(');
  const storeAt = src.indexOf('storeKey(');
  assert.ok(initAt >= 0, 'must call initSessionKey()');
  assert.ok(storeAt >= 0, 'must call storeKey()');
  assert.ok(initAt < storeAt, 'initSessionKey() must run before storeKey() (encrypt-before-write)');
  // 3a-pure: the recovery function requires a device passphrase to derive the at-rest key.
  assert.match(src, /newPassphrase: string/, 'restoreIdentityFromSeedVault must require a device passphrase');
});
