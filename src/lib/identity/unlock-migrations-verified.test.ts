// Unlock-time writes run only for owners whose existing encrypted records open under the session key. The behaviour is proven in a real
// browser (e2e/unlock-migrations-verified.spec.ts); these pins stop a later edit from dropping a gate. Same style as blocker-c-failclosed.
//   npx tsx --test src/lib/identity/unlock-migrations-verified.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('./client-store.ts', import.meta.url), 'utf8');
function fnBody(signature: string): string {
  const start = src.indexOf(signature);
  assert.ok(start >= 0, `${signature} not found`);
  const ends = ['\nexport ', '\nasync function ', '\n/**', '\nfunction '].map((m) => src.indexOf(m, start + 1)).filter((i) => i !== -1);
  return src.slice(start, Math.min(...ends));
}
const GATE = '_unlockVerifiedOwners.has(';

test('initSessionKey decides who is verified before the first migration runs', () => {
  const s = fnBody('export async function initSessionKey');
  const decided = s.indexOf('_unlockVerifiedOwners = await ownersVerifiedBySession()');
  const first = s.indexOf('await migrateAndVerifyContactsOnUnlock()');
  assert.ok(decided > 0 && first > decided);
  assert.ok(s.indexOf('_sessionKey = await deriveSessionKey') < decided, 'it needs the session key');
  const cleared = s.indexOf('_unlockVerifiedOwners = new Set()');
  assert.ok(cleared > 0 && cleared < s.indexOf('_sessionKey = await deriveSessionKey'), 'the old verified set must be gone before the key changes');
  assert.ok(cleared < s.indexOf('await txGet'), 'it is the first thing the function changes');
});

test('locking forgets who was verified', () => {
  assert.match(fnBody('export function lockSession'), /_unlockVerifiedOwners = new Set\(\)/);
});

for (const fn of ['migratePerContactPrivacyOnUnlock', 'purgeAffirmWireMutualTaintOnUnlock', 'eagerMigrateIdentityStoresOnUnlock', 'ensureDeviceMailboxesOnUnlock']) {
  test(`${fn} skips an owner the session did not verify`, () => {
    assert.ok(fnBody(`async function ${fn}(`).includes(GATE));
  });
}

test('the contact heal and the manifest step are each gated', () => {
  const s = fnBody('async function migrateAndVerifyContactsOnUnlock(');
  assert.equal(s.split(GATE).length - 1, 2);
  assert.ok(s.indexOf(GATE) < s.indexOf('buildStoredContact('), 'gate before the heal write');
});

for (const [fn, field] of [['loadKey', 'privateKey'], ['loadPQKeys', 'bundle'], ['loadVault', 'vault'], ['loadShards', 'shards_data']]) {
  test(`${fn}'s lazy heal needs a verified owner`, () => {
    assert.ok(fnBody(`export async function ${fn}(`).includes(`if (_sessionKey && _unlockVerifiedOwners.has(fingerprint) && record.${field})`));
  });
}

test('verification fails closed and reads only', () => {
  const owners = fnBody('async function ownersVerifiedBySession(');
  assert.match(owners, /catch \{\s*verified\.clear\(\);/);
  assert.doesNotMatch(owners, /txPut|txDelete|store[A-Z]/);
  const one = fnBody('async function sessionVerifiesOwner(');
  assert.match(one, /keyRecordOpens\(/);
  assert.doesNotMatch(one, /txPut|txDelete/);
  assert.match(one, /r\.enc_version && typeof r\.ciphertext === 'string'/,
    'a row without real ciphertext proves nothing: decryptContactIfNeeded would return it unchanged');
});
