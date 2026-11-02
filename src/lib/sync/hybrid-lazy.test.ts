// S14 #275 — Flint R1/R2: the FE hybrid open-material is derived LAZILY, from the poll cycle's ONE unlock.
//   R2: no second identity-key unlock per tick; an empty/classical mailbox derives nothing (zero cost); the secrets
//       exist only once a hybrid-shaped blob arrives.
//   R1: nothing secret exists before deps are returned; if anything after cycle creation throws the cycle is ended;
//       a derivation that is overtaken by a lock/drop zeroes its own bytes and returns nothing.
// Run: npx tsx --test src/lib/sync/hybrid-lazy.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeUnlockCycle, type UnlockCycle } from '@/lib/crypto/unlock-cycle';
import { deriveOwnerHybridSecretsFromKey } from '@/lib/crypto/living-book-receive';
import { sealLivingBookHybrid, type LivingBookHybridSecrets } from '@/lib/crypto/living-book-sleeve';
import type { IssuedCodeMap } from '@/lib/identity/client-store';
import { consumeInboundContactUpdates, type ConsumeDeps } from './consume-mailbox';
import { asMailboxEnvelopePackage } from './hybrid-dual-read';
import { buildJoinerSeam, cycleDroppingHybrid, dropCycleOnThrow, lazyCycleHybrid, openHybridForCycle, type LazyCycleHybrid } from './live-book-poll';
import { mintHybridRecipient, type HybridRecipient } from './hybrid-test-fixture';

const nonZero = (a: Uint8Array) => a.some((b) => b !== 0);

/** A cycle wired exactly like buildConsumeDeps wires it: dropping it zeroes what the lazy provider derived. */
function wired(r: HybridRecipient, opts: { kemPub?: string | null; kemSec?: string | undefined } = {}) {
  const counts = { unlocks: 0, kemLoads: 0 };
  const keysSeen: unknown[] = []; // every identity key the provider derived from
  const base = makeUnlockCycle(r.privateKeyArmored, r.passphrase, { onUnlock: () => { counts.unlocks += 1; } });
  const cycle = cycleDroppingHybrid(base, () => lazy.current());
  const lazy: LazyCycleHybrid = lazyCycleHybrid(
    cycle,
    opts.kemPub === null ? undefined : (opts.kemPub ?? r.pqKemPublicKey),
    async () => { counts.kemLoads += 1; return 'kemSec' in opts ? opts.kemSec : r.kemSecretKeyB64; },
    async (key, pub, sec) => { keysSeen.push(key); return deriveOwnerHybridSecretsFromKey(key, pub, sec); },
  );
  return { cycle, lazy, counts, keysSeen };
}

test('R2: before any hybrid blob arrives NOTHING is unlocked or read (empty/classical mailbox costs zero)', async () => {
  const r = await mintHybridRecipient();
  const { cycle, lazy, counts } = wired(r);
  assert.equal(counts.unlocks, 0);
  assert.equal(counts.kemLoads, 0);
  assert.equal(lazy.current(), undefined, 'no secret exists yet');
  cycle.drop();
  assert.equal(counts.unlocks, 0, 'a tick that never sees a hybrid blob never pays an unlock for the hybrid leg');
});

test('R2: the first hybrid blob derives ONCE from the cycle\'s single unlock (shared with the classical decryptors), then reuses it', async () => {
  const r = await mintHybridRecipient();
  const { cycle, lazy, counts, keysSeen } = wired(r);
  const payload = new TextEncoder().encode('hello hybrid');
  const blob = await sealLivingBookHybrid(payload, r.publicKeyArmored, r.pqKemPublicKey);
  const open = openHybridForCycle({ cycle }, lazy.source);

  const inner = await open(asMailboxEnvelopePackage(blob)!);
  assert.deepEqual(inner && Array.from(inner), Array.from(payload), 'opens and returns the plaintext');
  await cycle.key(); // what the classical decryptors do in the same tick
  await open(asMailboxEnvelopePackage(blob)!); // a second hybrid blob in the same tick
  assert.equal(counts.unlocks, 1, 'ONE identity-key unlock for the whole tick (no second decryptKey) — Flint R2');
  assert.equal(keysSeen.length, 1, 'derived once per tick');
  assert.equal(keysSeen[0], await cycle.key(), 'derived from the CYCLE\'s own unlocked key object, not a second unlock of the armored key');
  assert.equal(counts.kemLoads, 1, 'the vault PQ bundle is read once per tick');
  cycle.drop();
});

test('R2: a classical identity (no kem pub) derives nothing and touches no key', async () => {
  const r = await mintHybridRecipient();
  const { cycle, lazy, counts } = wired(r, { kemPub: null });
  assert.equal(await lazy.source(), undefined);
  assert.deepEqual(counts, { unlocks: 0, kemLoads: 0 });
  cycle.drop();
});

test('an unreadable PQ bundle (no kem secret) -> undefined (fail-soft to classical), not a throw', async () => {
  const r = await mintHybridRecipient();
  const { cycle, lazy } = wired(r, { kemSec: undefined });
  assert.equal(await lazy.source(), undefined);
  cycle.drop();
});

test('cycle drop() zeroes what was derived (tick lifetime) — the bytes the provider created', async () => {
  const r = await mintHybridRecipient();
  const { cycle, lazy } = wired(r);
  const h = (await lazy.source())!;
  assert.ok(nonZero(h.secrets.x25519Sec) && nonZero(h.secrets.mlkem1024Sec), 'control: real secrets before drop');
  cycle.drop();
  assert.equal(nonZero(h.secrets.x25519Sec), false);
  assert.equal(nonZero(h.secrets.mlkem1024Sec), false);
  assert.equal(await lazy.source(), undefined, 'a dead cycle derives nothing further');
});

test('R1: a lock/drop that lands WHILE deriving: the freshly derived bytes are zeroed and never returned', async () => {
  const r = await mintHybridRecipient();
  const known: LivingBookHybridSecrets = { secrets: { x25519Sec: new Uint8Array(32).fill(7), mlkem1024Sec: new Uint8Array(3168).fill(9) }, myFp: 'f'.repeat(64) };
  const base = makeUnlockCycle(r.privateKeyArmored, r.passphrase);
  const cycle = cycleDroppingHybrid(base, () => lazy.current());
  const lazy: LazyCycleHybrid = lazyCycleHybrid(cycle, r.pqKemPublicKey, async () => r.kemSecretKeyB64, async () => { cycle.drop(); return known; }); // lock lands inside derive
  assert.equal(await lazy.source(), undefined, 'overtaken derivation returns nothing');
  assert.equal(lazy.current(), undefined);
  assert.equal(nonZero(known.secrets.x25519Sec) || nonZero(known.secrets.mlkem1024Sec), false, 'and zeroes the bytes it made');
});

test('R1: if building deps throws AFTER the secrets exist, the cycle is ended and the secrets are zeroed (error still propagates)', async () => {
  const r = await mintHybridRecipient();
  const { cycle, lazy } = wired(r);
  const h = (await lazy.source())!; // worst case: already derived when the later step (e.g. loadIssuedCodeMap) throws
  const boom = new Error('loadIssuedCodeMap failed');
  await assert.rejects(dropCycleOnThrow(cycle, async () => { throw boom; }), (e) => e === boom);
  assert.equal(cycle.ended, true);
  assert.equal(nonZero(h.secrets.x25519Sec) || nonZero(h.secrets.mlkem1024Sec), false, 'secrets zeroed on the error path');
});

test('R1 control: a successful build is returned untouched and the cycle stays live', async () => {
  const r = await mintHybridRecipient();
  const { cycle } = wired(r);
  assert.equal(await dropCycleOnThrow(cycle, async () => 42), 42);
  assert.equal(cycle.ended, false);
  cycle.drop();
});

// ── consume level: the lazy hybridSecretMissing check runs ONLY for hybrid-shaped blobs ──
const HYBRID_SHAPED = JSON.stringify({ v: 1, mailbox_fp: 'x', epk: 'a', kem_ct: 'b', nonce: 'c', ct: 'd' });

function consumeDeps(blob: string, ackLog: string[][], cycle: UnlockCycle, r: HybridRecipient, hybridSecretMissing: ConsumeDeps['hybridSecretMissing']): ConsumeDeps {
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (String(url).includes('/queue')) return new Response(JSON.stringify([{ envelope_id: 'e1', blob }]), { status: 200, headers: { 'content-type': 'application/json' } });
    if (String(url).includes('/ack')) { ackLog.push(JSON.parse(String(init?.body ?? '{}')).envelope_ids); return new Response(JSON.stringify({ deleted: 1 }), { status: 200 }); }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  return {
    owner: { fingerprint: r.fingerprint, publicKeyArmored: r.publicKeyArmored, privateKeyArmored: r.privateKeyArmored, passphrase: r.passphrase, cycle },
    decrypt: async () => null,
    store: { lookup: async () => null, persist: async () => undefined },
    relayBase: 'http://relay.test/api/relay',
    now: () => '2026-08-19T00:00:00.000Z',
    fetchImpl,
    hybridSecretMissing,
  };
}

test('consume: a CLASSICAL blob never evaluates the lazy hybridSecretMissing check', async () => {
  const r = await mintHybridRecipient();
  const cycle = makeUnlockCycle(r.privateKeyArmored, r.passphrase);
  let calls = 0;
  await consumeInboundContactUpdates(consumeDeps('-----BEGIN PGP MESSAGE-----\nxx\n-----END PGP MESSAGE-----', [], cycle, r, async () => { calls += 1; return true; }));
  assert.equal(calls, 0);
  cycle.drop();
});

test('consume: a hybrid blob + secret missing -> RETRYABLE, never acked (loud, not silent-loss)', async () => {
  const r = await mintHybridRecipient();
  const cycle = makeUnlockCycle(r.privateKeyArmored, r.passphrase);
  const ackLog: string[][] = [];
  let calls = 0;
  const summary = await consumeInboundContactUpdates(consumeDeps(HYBRID_SHAPED, ackLog, cycle, r, async () => { calls += 1; return true; }));
  assert.equal(calls, 1, 'evaluated once, for the hybrid-shaped blob');
  assert.deepEqual(ackLog, [], 'left in the mailbox for retry');
  assert.equal(summary.acked, 0);
  cycle.drop();
});

test('consume control: the same hybrid-shaped blob with the secret NOT missing falls to the normal path (terminal drop -> acked)', async () => {
  const r = await mintHybridRecipient();
  const cycle = makeUnlockCycle(r.privateKeyArmored, r.passphrase);
  const ackLog: string[][] = [];
  await consumeInboundContactUpdates(consumeDeps(HYBRID_SHAPED, ackLog, cycle, r, async () => false));
  assert.deepEqual(ackLog, [['e1']], 'proves the retryable case above is caused by the missing-secret check, not by the blob');
  cycle.drop();
});

// ── joiner path: the lazy source is resolved only for hybrid-shaped blobs ──
test('joiner seam: a classical blob never resolves the lazy hybrid source; a hybrid-shaped one resolves it once', async () => {
  const r = await mintHybridRecipient();
  const cycle = makeUnlockCycle(r.privateKeyArmored, r.passphrase);
  let calls = 0;
  const source = async () => { calls += 1; return undefined; };
  const seam = buildJoinerSeam(
    { fingerprint: r.fingerprint, publicKeyArmored: r.publicKeyArmored, privateKeyArmored: r.privateKeyArmored, passphrase: r.passphrase, cycle },
    {} as IssuedCodeMap,
    source,
  );
  assert.equal(await seam.verify('-----BEGIN PGP MESSAGE-----\nxx\n-----END PGP MESSAGE-----'), null);
  assert.equal(calls, 0, 'classical blob: no derivation');
  assert.equal(await seam.verify(HYBRID_SHAPED), null);
  assert.equal(calls, 1, 'hybrid-shaped blob: resolved exactly once');
  cycle.drop();
});
