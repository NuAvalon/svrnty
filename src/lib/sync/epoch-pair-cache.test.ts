// The real cache instance is emptied by the store's own lock event. Run: npx tsx --test src/lib/sync/epoch-pair-cache.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { lockSession } from '@/lib/identity/client-store';
import { epochPairSecretCache } from './epoch-pair-cache';

const K = Uint8Array.from({ length: 32 }, (_, i) => i);
const S = Uint8Array.from({ length: 32 }, (_, i) => 100 + i);

test('NEG: after the session locks (the store\'s real lockSession), the real cache instance is empty', () => {
  epochPairSecretCache.set('c1', K, S);
  epochPairSecretCache.set('c2', K, S);
  assert.equal(epochPairSecretCache.size(), 2);
  lockSession();
  assert.equal(epochPairSecretCache.size(), 0);
  assert.equal(epochPairSecretCache.get('c1', K), undefined);
});

test('the store fires that same hook from setActiveFingerprint (the identity switch), so an identity change empties it too (source pin: that path needs the real database)', () => {
  const cs = readFileSync(new URL('../identity/client-store.ts', import.meta.url), 'utf8');
  const at = cs.indexOf('export async function setActiveFingerprint(');
  assert.ok(at > 0);
  const body = cs.slice(at, cs.indexOf('\nexport ', at + 1));
  assert.match(body, /fireSessionLockHooks\(\)/);
  const hook = readFileSync(new URL('./epoch-pair-cache.ts', import.meta.url), 'utf8');
  assert.match(hook, /createPairSecretCache\(onSessionLock\)/);
});
