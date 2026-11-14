// #532 C1: a restore carries the identity's durable epoch + id, never a hard-coded genesis.
//   npx tsx --test src/lib/identity/restore-durable.test.ts
// The seed-restore and mint wiring touch IndexedDB, which has no runtime harness in this repo, so they are pinned by static guards
// (the restore-domain.test.ts style); the carrying itself is proven with the REAL vault crypto (createKeyVault / recoverFromSeedPhrase,
// packVault / unpackVault), which runs in node.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { durableFromSeedBundle, RestoreDurableRefused } from './restore-durable';
import { createKeyVault, recoverFromSeedPhrase, seedPhraseToMasterSecret, type PrivateKeyBundle } from '../crypto/recovery';
import { deriveNextAuthorityCommitment } from './fingerprint';
import { createVaultContents, packVault, unpackVault, type VaultIdentity } from '../sync/vault';

const read = (p: string) => readFileSync(new URL(p, import.meta.url), 'utf8');
const FP = 'a'.repeat(64);
const DURABLE = 'b'.repeat(64);
const refuses = (fn: () => unknown, reason: string) =>
  assert.throws(fn, (e: unknown) => e instanceof RestoreDurableRefused && e.reason === reason);

test('D1 absent fields = a genesis bundle: epoch 0, the current fp is the durable id, the next pin is epoch 1', () => {
  assert.deepEqual(durableFromSeedBundle({}, FP), { fingerprint: FP, epoch: 0, nextCommitmentEpoch: 1 });
  assert.deepEqual(durableFromSeedBundle({ durable_epoch: 0, durable_fingerprint: FP }, FP), { fingerprint: FP, epoch: 0, nextCommitmentEpoch: 1 });
});

test('D2 a rotated identity keeps its epoch AND its durable id (not the current fp), and pins epoch + 1', () => {
  assert.deepEqual(durableFromSeedBundle({ durable_epoch: 3, durable_fingerprint: DURABLE }, FP), { fingerprint: DURABLE, epoch: 3, nextCommitmentEpoch: 4 });
});

test('D3 fail-closed: a bad epoch, a missing durable id past genesis, a bad id, a genesis id that is not the current fp', () => {
  for (const e of [-1, 1.5, NaN, Infinity, '3', null, Number.MAX_SAFE_INTEGER]) refuses(() => durableFromSeedBundle({ durable_epoch: e, durable_fingerprint: DURABLE }, FP), 'bad-epoch');
  refuses(() => durableFromSeedBundle({ durable_epoch: 2 }, FP), 'missing-durable-id');
  for (const id of ['', 7, null, {}]) refuses(() => durableFromSeedBundle({ durable_epoch: 2, durable_fingerprint: id }, FP), 'bad-durable-id');
  refuses(() => durableFromSeedBundle({ durable_epoch: 0, durable_fingerprint: DURABLE }, FP), 'genesis-id-mismatch');
  refuses(() => durableFromSeedBundle({ durable_fingerprint: DURABLE }, FP), 'genesis-id-mismatch');
});

test('D4 the refusal echoes no bundle bytes and says nothing was restored', () => {
  try { durableFromSeedBundle({ durable_epoch: 2, durable_fingerprint: '' }, FP); assert.fail('no throw'); } catch (e) {
    assert.ok(e instanceof RestoreDurableRefused);
    assert.match((e as Error).message, /Nothing was restored/);
    assert.ok(!(e as Error).message.includes(FP));
  }
});

const bundle = (extra: Partial<PrivateKeyBundle>): PrivateKeyBundle => ({
  classical_private_key: 'k', classical_passphrase: 'p', pq_signing_secret_key: 's', pq_kem_secret_key: 'm', identity_fingerprint: FP, ...extra,
});

test('S1 REAL seed vault: durable_epoch 3 + durable id survive seal -> seed open, and restore derives the epoch-4 pin from the seed', async () => {
  const { vault, seedPhrase } = await createKeyVault(bundle({ durable_epoch: 3, durable_fingerprint: DURABLE }), 2, 3, FP);
  const back = await recoverFromSeedPhrase(vault, seedPhrase);
  assert.equal(back.durable_epoch, 3);
  assert.equal(back.durable_fingerprint, DURABLE);
  const d = durableFromSeedBundle(back, FP);
  const ms = seedPhraseToMasterSecret(seedPhrase);
  const pin = deriveNextAuthorityCommitment(ms, d.nextCommitmentEpoch);
  assert.equal(pin, deriveNextAuthorityCommitment(ms, 4));
  assert.notEqual(pin, deriveNextAuthorityCommitment(ms, 1)); // the old hard-coded genesis pin is a DIFFERENT value
});

test('S2 a tampered sealed bundle does not open (the fields live inside the authenticated body)', async () => {
  const { vault, seedPhrase } = await createKeyVault(bundle({ durable_epoch: 3, durable_fingerprint: DURABLE }), 2, 3, FP);
  const raw = Buffer.from(vault.encrypted_keys, 'base64');
  raw[raw.length >> 1] ^= 0x01;
  await assert.rejects(recoverFromSeedPhrase({ ...vault, encrypted_keys: raw.toString('base64') }, seedPhrase));
});

test('P1 REAL passphrase vault: identity.durable (epoch 3) and next_authority_commitment round-trip through pack/unpack', async () => {
  const durable = { fingerprint: DURABLE, epoch: 3, next_authority_commitment: 'c'.repeat(64) };
  const identity = {
    version: '1.0', created_at: '2026-11-14T00:00:00Z',
    identity: { name: 'n', email: '', fingerprint: FP, public_key: 'pk' },
    verification: { status: 'unverified', method: null, verified_at: null },
    metadata: { client_version: 't', key_type: 't', key_usage: [] },
    next_authority_commitment: durable.next_authority_commitment,
    durable,
  } as VaultIdentity;
  const packed = await packVault(createVaultContents(identity, { classical: { privateKey: '', passphrase: '' }, pq: null } as never, { edges: [], contacts: [] } as never), 'correct horse battery staple');
  const back = await unpackVault(packed, 'correct horse battery staple');
  assert.deepEqual(back.contents.identity.durable, durable);
  assert.equal(back.contents.identity.next_authority_commitment, durable.next_authority_commitment);
});

// ── static guards on the IndexedDB wiring ──
function fnBody(src: string, signature: string): string {
  const start = src.indexOf(signature);
  assert.ok(start >= 0, `${signature} not found`);
  const ends = ['\nexport ', '\n/**'].map((m) => src.indexOf(m, start + 1)).filter((i) => i !== -1);
  return src.slice(start, ends.length ? Math.min(...ends) : src.length);
}
const code = (s: string) => s.split('\n').filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n');
const before = (s: string, a: string, b: string, why: string) => {
  const i = s.indexOf(a), j = s.indexOf(b);
  assert.ok(i >= 0 && j >= 0 && i < j, why);
};

test('G1 seed restore reads the durable record from the bundle, after the fp is derived and before anything is written', () => {
  const s = code(fnBody(read('../../components/recovery/seedVaultRestore.ts'), 'export async function restoreIdentityFromSeedVault'));
  before(s, 'reconstructCanonicalIdentityForRestore(', 'durableFromSeedBundle(bundle, fingerprint)', 'needs the derived fp');
  before(s, 'durableFromSeedBundle(bundle, fingerprint)', 'initSessionKey(', 'refuse before the session key');
  before(s, 'durableFromSeedBundle(bundle, fingerprint)', 'storeKey(', 'refuse before any write');
  assert.match(s, /deriveNextAuthorityCommitment\(_ms, durable\.nextCommitmentEpoch\)/);
  assert.match(s, /durable: \{ fingerprint: durable\.fingerprint, epoch: durable\.epoch, next_authority_commitment \}/);
  assert.doesNotMatch(s, /deriveNextAuthorityCommitment\(_ms, 1\)/, 'no hard-coded genesis pin');
  assert.doesNotMatch(s, /epoch: 0/, 'no hard-coded genesis epoch');
});

test('G2 seed restore still pins the claimed fp from INSIDE the bundle (omit/tamper -> the recompute check refuses)', () => {
  const s = code(fnBody(read('../../components/recovery/seedVaultRestore.ts'), 'export async function restoreIdentityFromSeedVault'));
  assert.match(s, /claimedFingerprint: bundle\.identity_fingerprint \?\? ''/);
  const f = code(fnBody(read('./fingerprint.ts'), 'export async function reconstructCanonicalIdentityForRestore'));
  assert.match(f, /if \(fingerprint !== normalizeFingerprintHex\(args\.claimedFingerprint\)\) \{\s*throw/);
});

test('G3 both mint paths seal a genesis durable record into the seed bundle', () => {
  for (const p of ['./browser-identity.ts', './core.ts']) {
    const s = code(read(p));
    const i = s.indexOf('const keyBundle: PrivateKeyBundle = {');
    assert.ok(i >= 0, p);
    const lit = s.slice(i, s.indexOf('};', i));
    assert.match(lit, /durable_epoch: 0,/, p);
    assert.match(lit, /durable_fingerprint: fingerprint,/, p);
  }
});
