import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fingerprintMatchesKey } from '../identity/fingerprint';
import { SAMPLE_SVRNTY_PEERS, SAMPLE_SVRNTY_FPS } from './sample-svrnty-keys';

test('demo SVRNTY peers: fingerprint ≡ H(public_key) (Invariant-1)', async () => {
  assert.equal(SAMPLE_SVRNTY_PEERS.length, 10);
  for (const p of SAMPLE_SVRNTY_PEERS) {
    assert.ok(p.public_key.includes('BEGIN PGP PUBLIC KEY BLOCK'));
    assert.equal(await fingerprintMatchesKey(p.fingerprint, p.public_key), true);
    assert.ok(SAMPLE_SVRNTY_FPS.has(p.fingerprint));
  }
});

test('demo SVRNTY peers include the open-visibility clique', () => {
  const clique = SAMPLE_SVRNTY_PEERS.filter((p) => p.clique).map((p) => p.id).sort();
  assert.deepEqual(clique, [
    'ada',
    'barbara',
    'grace',
    'jean',
    'joan',
    'margaret',
    'radia',
    'sophie',
  ]);
});
