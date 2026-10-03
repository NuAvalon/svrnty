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

test('runBindCeremony POST-direct: new fields {sig_pubkey,nonce,epoch=0,binding_sig}, binds on 200, NO GET', async () => {
  const calls: Array<{ url: string; method: string; body: Record<string, unknown> }> = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method || 'GET',
      body: init?.body && typeof init.body === 'string' ? JSON.parse(init.body) : {},
    });
    return new Response(JSON.stringify({ status: 'bound' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as typeof fetch;

  const ok = await runBindCeremony({ satelliteUrl: 'https://satellite.test', fingerprint, seed, signPub, fetchImpl });
  assert.equal(ok, true);
  assert.equal(calls.length, 1); // POST-direct — the vestigial GET challenge is gone
  assert.equal(calls[0].method, 'POST');
  assert.match(calls[0].url, /\/bind$/);
  const b = calls[0].body;
  assert.equal(b.fingerprint, fingerprint);
  assert.equal(b.sig_pubkey, bytesToHex(signPub)); // NEW satellite field name
  assert.equal(b.epoch, 0); // client-local init 0
  assert.match(String(b.nonce), /^[0-9a-f]+$/); // fresh lowercase-hex
  assert.equal(String(b.nonce).length % 2, 0); // even length (satellite nonce guard)
  assert.equal('sign_pubkey' in b, false); // old field gone
  assert.equal('signature' in b, false); // old field gone
  // binding_sig = identity seed signing its OWN pubkey over the tag#2 preimage (self-bind)
  const preimage = new TextEncoder().encode(`svrnty-bind:${b.sig_pubkey}:${b.nonce}:${b.epoch}`);
  assert.equal(ed25519.verify(Buffer.from(String(b.binding_sig), 'base64'), preimage, signPub), true);
});

test('runBindCeremony adopts satellite epoch on 409 "stale epoch (current=N)" + retries ONCE (fresh nonce)', async () => {
  const bodies: Array<Record<string, unknown>> = [];
  const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = init?.body && typeof init.body === 'string' ? JSON.parse(init.body) : {};
    bodies.push(body);
    if (body.epoch === 0) {
      return new Response(JSON.stringify({ detail: 'stale epoch (current=7)' }), {
        status: 409,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({ status: 'bound' }), { status: 200 });
  }) as typeof fetch;

  const ok = await runBindCeremony({ satelliteUrl: 'https://satellite.test', fingerprint, seed, signPub, fetchImpl });
  assert.equal(ok, true);
  assert.equal(bodies.length, 2);
  assert.equal(bodies[0].epoch, 0);
  assert.equal(bodies[1].epoch, 7); // adopted from the satellite's 409 detail (never registration)
  assert.notEqual(bodies[0].nonce, bodies[1].nonce); // fresh nonce on the retry
  const preimage = new TextEncoder().encode(`svrnty-bind:${bodies[1].sig_pubkey}:${bodies[1].nonce}:7`);
  assert.equal(ed25519.verify(Buffer.from(String(bodies[1].binding_sig), 'base64'), preimage, signPub), true);
});

test('runBindCeremony fails CLOSED on a 409 that is not a parseable stale-epoch (e.g. nonce-reuse) — no blind retry', async () => {
  let n = 0;
  const fetchImpl = (async () => {
    n++;
    return new Response(JSON.stringify({ detail: 'nonce already used' }), { status: 409 });
  }) as typeof fetch;
  const ok = await runBindCeremony({ satelliteUrl: 'https://satellite.test', fingerprint, seed, signPub, fetchImpl });
  assert.equal(ok, false); // no adoptable epoch ⇒ fail-closed, no PSI
  assert.equal(n, 1); // did not blindly retry
});
