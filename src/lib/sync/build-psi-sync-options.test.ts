// buildPsiSyncOptions + /bind ceremony — injected loadKey + fetch, no IndexedDB.
// Run: npx tsx --test src/lib/sync/build-psi-sync-options.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from 'openpgp';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { extractRawSign, psiAuthPreimage } from '@/lib/identity/raw-sign';
import { decryptKey, readPrivateKey } from 'openpgp';
import { buildPsiSyncOptions, runBindCeremony } from './know-layer-sync';

const passphrase = 'psi-options-test-pass';
const fingerprint = 'ab'.repeat(32);

let privateKey: string;
let seed: Uint8Array;
let signPub: Uint8Array;

before(async () => {
  const generated = await generateKey({
    type: 'ecc',
    curve: 'ed25519',
    userIDs: [{ name: 'Psi', email: 'psi@example.test' }],
    passphrase,
    format: 'armored',
  });
  privateKey = generated.privateKey;
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted()
    ? locked
    : await decryptKey({ privateKey: locked, passphrase });
  ({ seed, signPub } = extractRawSign(unlocked));
});

test('buildPsiSyncOptions is null when bind fails (fail-closed)', async () => {
  const options = await buildPsiSyncOptions(
    { identity: { fingerprint } },
    {
      loadKey: async () => ({ privateKey, passphrase }),
      satelliteUrl: 'https://satellite.test',
      fetchImpl: (async () => new Response('nope', { status: 404 })) as typeof fetch,
    },
  );
  assert.equal(options, null);
});

test('buildPsiSyncOptions signFn prefixes svrnty-psi-auth: onto {fp}:{unix}', async () => {
  const options = await buildPsiSyncOptions(
    { identity: { fingerprint } },
    {
      loadKey: async () => ({ privateKey, passphrase }),
      satelliteUrl: 'https://satellite.test',
      skipBind: true,
    },
  );
  assert.ok(options);
  assert.equal(options!.myFingerprint, fingerprint);
  assert.equal(options!.satelliteUrl, 'https://satellite.test');
  const unix = 1_700_000_001;
  const wrapped = new TextEncoder().encode(`${fingerprint}:${unix}`);
  const sig = options!.signFn(wrapped);
  const preimage = psiAuthPreimage(fingerprint, unix);
  assert.equal(ed25519.verify(sig, preimage, signPub), true);
});

test('runBindCeremony GET challenge → POST signed bind body', async () => {
  const calls: Array<{ url: string; method: string; body?: unknown }> = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method || 'GET';
    let body: unknown;
    if (init?.body && typeof init.body === 'string') body = JSON.parse(init.body);
    calls.push({ url, method, body });
    if (method === 'GET') {
      return new Response(JSON.stringify({ nonce: 'n1', epoch: 3 }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  }) as typeof fetch;

  const ok = await runBindCeremony({
    satelliteUrl: 'https://satellite.test',
    fingerprint,
    seed,
    signPub,
    fetchImpl,
  });
  assert.equal(ok, true);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].method, 'GET');
  assert.match(calls[0].url, /\/bind\?fingerprint=/);
  assert.equal(calls[1].method, 'POST');
  const posted = calls[1].body as Record<string, unknown>;
  assert.equal(posted.fingerprint, fingerprint);
  assert.equal(posted.sign_pubkey, bytesToHex(signPub));
  assert.equal(posted.nonce, 'n1');
  assert.equal(posted.epoch, 3);
  assert.equal(typeof posted.signature, 'string');
});
