// .svrnty format — graph_vault tier (§1 of the graph-vault recovery wiring).
// Verifies the Do-No-Harm line: a file WITH a graph_vault round-trips; a file
// WITHOUT one — or an old v3 file, or a corrupted section — yields null, NEVER
// throws, and keys/passphrase-unlock still work. Additive + backward-compatible.
// Run: npx tsx --test src/lib/sync/vault.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createVaultContents,
  packVault,
  unpackVault,
  extractRecoveryVault,
  extractGraphVault,
  type VaultIdentity,
  type VaultKeys,
} from './vault';
import {
  createKeyVault,
  encryptGraphVault,
  decryptGraphVault,
  type PrivateKeyBundle,
} from '../crypto/recovery';
import type { TrustGraph } from '../trust/types';

const PASSPHRASE = 'Tr0ub4dour-Horse-Battery-Staple!';
const BUNDLE: PrivateKeyBundle = {
  classical_private_key: 'PGP-PRIVATE',
  classical_passphrase: 'pgp-pass',
  pq_signing_secret_key: 'sig-sk',
  pq_kem_secret_key: 'kem-sk',
};
const IDENTITY = {
  version: '1',
  created_at: '2026-01-01T00:00:00Z',
  identity: { name: 'Alice', email: 'a@x', fingerprint: 'abc123', public_key: 'PUB' },
  verification: { status: 'unverified', method: null, verified_at: null },
  metadata: { client_version: 'test', key_type: 'ed25519', key_usage: [] },
} as unknown as VaultIdentity;
const KEYS = { classical: { privateKey: 'p', passphrase: 'pp' }, pq: null } as VaultKeys;
const TRUST = {} as unknown as TrustGraph;
const GRAPH = {
  contacts: [{ fingerprint: 'a1', name: 'Alice', trusted: true }],
  trust: {},
  profile: { display_name: 'Ally', slug: 'alice' },
};

async function contentsWithRecovery() {
  const { vault, masterSecret } = await createKeyVault(BUNDLE, 3, 5, 'abc123');
  const contents = createVaultContents(IDENTITY, KEYS, TRUST, {}, vault);
  return { contents, masterSecret };
}

// ── The happy path: the graph survives export/restore via the master secret ──
test('§1 round-trip: pack WITH graph_vault → extractGraphVault (no passphrase) → decrypt returns the graph', async () => {
  const { contents, masterSecret } = await contentsWithRecovery();
  const gv = await encryptGraphVault(GRAPH, masterSecret);
  const file = await packVault(contents, PASSPHRASE, gv);

  const extracted = extractGraphVault(file); // NO passphrase — the whole point
  assert.ok(extracted, 'graph_vault must be extractable at the passphrase-free tier');
  const graph = await decryptGraphVault(extracted!, masterSecret);
  assert.deepEqual(graph, GRAPH);
});

// ── The Do-No-Harm line: no graph_vault ⇒ null, never a throw ──
test('§4 do-no-harm: pack WITHOUT graph_vault → extractGraphVault === null (no throw)', async () => {
  const { contents } = await contentsWithRecovery();
  const file = await packVault(contents, PASSPHRASE); // no graphVault arg
  assert.equal(extractGraphVault(file), null);
});

test('§4 do-no-harm: a graph_vault does NOT break extractRecoveryVault (old reader still finds the KeyVault)', async () => {
  const { contents, masterSecret } = await contentsWithRecovery();
  const gv = await encryptGraphVault(GRAPH, masterSecret);
  const file = await packVault(contents, PASSPHRASE, gv);
  const kv = extractRecoveryVault(file);
  assert.equal(typeof kv.encrypted_keys, 'string');
  assert.equal(typeof kv.master_secret_hash, 'string');
});

test('§4 do-no-harm: daily passphrase unlock still works with a graph_vault present', async () => {
  const { contents, masterSecret } = await contentsWithRecovery();
  const gv = await encryptGraphVault(GRAPH, masterSecret);
  const file = await packVault(contents, PASSPHRASE, gv);
  const { contents: opened } = await unpackVault(file, PASSPHRASE);
  assert.equal(opened.identity.identity.name, 'Alice');
});

test('§4 do-no-harm: extractGraphVault on truncated / empty / non-v4 buffers returns null, never throws', () => {
  assert.equal(extractGraphVault(new Uint8Array([1, 2, 3]).buffer), null);
  assert.equal(extractGraphVault(new ArrayBuffer(0)), null);
  // A v3-magic file (SVRNTY\0\3) carries no passphrase-free graph tier → null.
  const v3 = new Uint8Array([0x53, 0x56, 0x52, 0x4e, 0x54, 0x59, 0x00, 0x03, 0, 0, 0, 2, 0x7b, 0x7d]);
  assert.equal(extractGraphVault(v3.buffer), null);
});

test('§1: no recovery vault ⇒ graph_vault does not ride (no master secret to recover it)', async () => {
  // recovery === null → no passphrase-free envelope → a graph_vault would be
  // unrecoverable (no seed/Shamir KeyVault to reconstruct its master secret), so it
  // is correctly NOT written. extractGraphVault → null.
  const contents = createVaultContents(IDENTITY, KEYS, TRUST, {}, null);
  const { masterSecret } = await createKeyVault(BUNDLE, 3, 5, 'abc123');
  const gv = await encryptGraphVault(GRAPH, masterSecret);
  const file = await packVault(contents, PASSPHRASE, gv);
  assert.equal(extractGraphVault(file), null);
});

test('§4 do-no-harm: wrong master secret fails closed on the graph (keys unaffected)', async () => {
  const { contents, masterSecret } = await contentsWithRecovery();
  const gv = await encryptGraphVault(GRAPH, masterSecret);
  const file = await packVault(contents, PASSPHRASE, gv);
  const extracted = extractGraphVault(file);
  assert.ok(extracted);
  // A different master secret must not open the graph (GCM + hash fail-closed).
  const wrong = (await createKeyVault(BUNDLE, 3, 5, 'abc123')).masterSecret;
  await assert.rejects(() => decryptGraphVault(extracted!, wrong));
});
