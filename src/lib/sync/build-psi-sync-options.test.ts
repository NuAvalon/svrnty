// buildPsiSyncOptions + /bind ceremony — injected loadKey + fetch, no IndexedDB.
// Run: npx tsx --test src/lib/sync/build-psi-sync-options.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from 'openpgp';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { extractRawSign, psiAuthPreimage, bindPreimage } from '@/lib/identity/raw-sign';
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

// Canonical client bind (Flint #134651): GET registration /identity/{fp} for epoch + bound-status,
// then (if unbound) client-CSPRNG nonce + signBind → POST registration /bind with tag#2 field names.
test('runBindCeremony: GET /identity (registered, unbound) → POST /bind with canonical tag#2 fields + valid sig', async () => {
  const calls: Array<{ url: string; method: string; body?: unknown }> = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method || 'GET';
    let body: unknown;
    if (init?.body && typeof init.body === 'string') body = JSON.parse(init.body);
    calls.push({ url, method, body });
    if (method === 'GET') {
      return new Response(JSON.stringify({ epoch: 0, has_sig_pubkey: false }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
  }) as typeof fetch;

  const ok = await runBindCeremony({
    registrationBase: 'https://reg.test',
    fingerprint,
    seed,
    signPub,
    fetchImpl,
  });
  assert.equal(ok, true);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].method, 'GET');
  assert.match(calls[0].url, new RegExp(`/identity/${fingerprint}$`));
  assert.equal(calls[1].method, 'POST');
  assert.match(calls[1].url, /\/bind$/);
  const posted = calls[1].body as Record<string, unknown>;
  assert.equal(posted.fingerprint, fingerprint);
  assert.equal(posted.sig_pubkey, bytesToHex(signPub)); // renamed sign_pubkey → sig_pubkey
  assert.equal(posted.epoch, 0); // int, from /identity (fresh mint)
  assert.equal(typeof posted.nonce, 'string');
  assert.equal((posted.nonce as string).length, 64); // client CSPRNG hex(32B)
  // binding_sig (renamed from signature) MUST verify against the canonical tag#2 preimage.
  const sig = Uint8Array.from(atob(posted.binding_sig as string), (c) => c.charCodeAt(0));
  const preimage = bindPreimage(bytesToHex(signPub), posted.nonce as string, 0);
  assert.equal(ed25519.verify(sig, preimage, signPub), true);
});

test('runBindCeremony: already bound (has_sig_pubkey) short-circuits — no POST', async () => {
  const calls: string[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push((init?.method || 'GET') + ' ' + String(input));
    return new Response(JSON.stringify({ epoch: 2, has_sig_pubkey: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as typeof fetch;
  const ok = await runBindCeremony({ registrationBase: 'https://reg.test', fingerprint, seed, signPub, fetchImpl });
  assert.equal(ok, true);
  assert.equal(calls.length, 1); // GET /identity only; no POST /bind
  assert.match(calls[0], /^GET .*\/identity\//);
});

test('runBindCeremony: /identity 404 (not registered yet) → false (fail-closed, retry next tick)', async () => {
  const fetchImpl = (async () => new Response('nope', { status: 404 })) as typeof fetch;
  const ok = await runBindCeremony({ registrationBase: 'https://reg.test', fingerprint, seed, signPub, fetchImpl });
  assert.equal(ok, false);
});
