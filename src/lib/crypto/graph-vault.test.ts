// Graph vault — contacts/trust sealed under the master secret so seed-phrase AND
// Shamir recovery restore the graph too (not just the keys). Additive: a backup
// without a graph_vault behaves exactly as before.
// Run: npx tsx --test src/lib/crypto/graph-vault.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  encryptGraphVault,
  decryptGraphVault,
  generateMasterSecret,
  masterSecretToSeedPhrase,
  seedPhraseToMasterSecret,
  createShards,
  reconstructFromShards,
} from './recovery';

const SAMPLE_GRAPH = {
  contacts: [
    { fingerprint: 'a1b2c3', name: 'Alice', trusted: true, mutual: { reciprocal: true } },
    { fingerprint: 'd4e5f6', name: 'Bob', trusted: false, notes: 'met at the conf' },
  ],
};

test('round-trip: encrypt then decrypt returns the same graph', async () => {
  const ms = generateMasterSecret();
  const vault = await encryptGraphVault(SAMPLE_GRAPH, ms);
  const out = await decryptGraphVault(vault, ms);
  assert.deepEqual(out, SAMPLE_GRAPH);
});

test('vault shape: version + base64 fields + sha256 master_secret_hash', async () => {
  const ms = generateMasterSecret();
  const vault = await encryptGraphVault(SAMPLE_GRAPH, ms);
  assert.equal(vault.version, '1.0.0');
  assert.ok(vault.encrypted_graph.length > 0);
  assert.ok(vault.auth_tag.length > 0);
  assert.ok(vault.iv.length > 0);
  assert.equal(vault.master_secret_hash.length, 64); // sha256 hex
});

test('actually encrypted: ciphertext does not embed the plaintext', async () => {
  const ms = generateMasterSecret();
  const vault = await encryptGraphVault({ secret: 'PLAINTEXT-MARKER-42' }, ms);
  const raw = Buffer.from(vault.encrypted_graph, 'base64').toString('latin1');
  assert.ok(!raw.includes('PLAINTEXT-MARKER-42'));
});

test('fail-closed: wrong master secret ⇒ throws (hash mismatch)', async () => {
  const ms = generateMasterSecret();
  const vault = await encryptGraphVault(SAMPLE_GRAPH, ms);
  const wrong = generateMasterSecret();
  await assert.rejects(() => decryptGraphVault(vault, wrong), /hash mismatch/);
});

test('tamper: mutated ciphertext with the right secret ⇒ GCM auth failure', async () => {
  const ms = generateMasterSecret();
  const vault = await encryptGraphVault(SAMPLE_GRAPH, ms);
  const raw = Buffer.from(vault.encrypted_graph, 'base64');
  raw[0] ^= 0xff; // flip a byte — passes the hash gate, GCM must reject
  const tampered = { ...vault, encrypted_graph: raw.toString('base64') };
  await assert.rejects(() => decryptGraphVault(tampered, ms));
});

test('empty graph round-trips', async () => {
  const ms = generateMasterSecret();
  const vault = await encryptGraphVault({ contacts: [] }, ms);
  assert.deepEqual(await decryptGraphVault(vault, ms), { contacts: [] });
});

// The two paths that matter: the graph inherits BOTH of the key vault's recovery routes.

test('seed-phrase recovery: graph recovers from the seed phrase alone', async () => {
  const ms = generateMasterSecret();
  const phrase = masterSecretToSeedPhrase(ms);
  const vault = await encryptGraphVault(SAMPLE_GRAPH, ms);
  // On a new device only the phrase is known:
  const recovered = seedPhraseToMasterSecret(phrase);
  const out = await decryptGraphVault(vault, recovered);
  assert.deepEqual(out, SAMPLE_GRAPH);
});

test('Shamir recovery: graph recovers from a threshold of guardian shards', async () => {
  const ms = generateMasterSecret();
  const vault = await encryptGraphVault(SAMPLE_GRAPH, ms);
  const shards = await createShards(ms, 3, 5, 'fp-test');
  const recovered = await reconstructFromShards(shards.slice(0, 3)); // 3-of-5
  const out = await decryptGraphVault(vault, recovered);
  assert.deepEqual(out, SAMPLE_GRAPH);
});
