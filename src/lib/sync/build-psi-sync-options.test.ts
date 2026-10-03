// buildPsiSyncOptions + /bind ceremony — injected loadKey + fetch, no IndexedDB.
// Run: npx tsx --test src/lib/sync/build-psi-sync-options.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey } from 'openpgp';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { extractRawSign, psiAuthPreimage } from '@/lib/identity/raw-sign';
import { decryptKey, readPrivateKey } from 'openpgp';
import { deriveMailboxFp } from '@/lib/crypto/mailbox-envelope';
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

// ── FE-WIRING (b): buildPsiSyncOptions fetches + anti-swap-verifies the satellite key → populates pqWrap ──

// A fetchImpl that answers BOTH the bind ceremony (bind succeeds) AND the satellite-key fetch. Robust
// to either bind flow (this branch's GET-challenge or the merged POST-direct) — bind just needs to pass.
function wiringFetch(keyRec: Record<string, string> | null): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.includes('/trust/psi/satellite-key')) {
      return keyRec
        ? new Response(JSON.stringify(keyRec), { status: 200, headers: { 'Content-Type': 'application/json' } })
        : new Response('not found', { status: 404 });
    }
    if ((init?.method || 'GET') === 'GET') {
      // GET /bind challenge (old flow) — harmless if the merged POST-direct flow never calls it
      return new Response(JSON.stringify({ nonce: 'n1', epoch: 0 }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }
    return new Response(JSON.stringify({ status: 'bound' }), { status: 200 });
  }) as typeof fetch;
}

// A satellite mailbox keypair of the right byte-shape + its derived fp (the anti-swap pin).
function fakeSatelliteKey() {
  const x25519 = crypto.getRandomValues(new Uint8Array(32));
  const mlkem = crypto.getRandomValues(new Uint8Array(1568));
  const fp = deriveMailboxFp(x25519, mlkem);
  return { x25519, mlkem, fp, rec: { x25519_pk: bytesToHex(x25519), mlkem1024_pk: bytesToHex(mlkem), mailbox_fp: fp } };
}

test('buildPsiSyncOptions populates pqWrap from the verified satellite key (FE-wiring-b)', async () => {
  const sat = fakeSatelliteKey();
  const options = await buildPsiSyncOptions(
    { identity: { fingerprint } },
    {
      loadKey: async () => ({ privateKey, passphrase }),
      satelliteUrl: 'https://satellite.test',
      fetchImpl: wiringFetch(sat.rec),
      pinnedFp: sat.fp,
    },
  );
  assert.ok(options);
  assert.ok(options!.pqWrap, 'pqWrap populated so the KNOW-sync seals (satellite enforces sealed PSI)');
  assert.deepEqual([...options!.pqWrap!.satelliteKeys.x25519Pub], [...sat.x25519]);
  assert.deepEqual([...options!.pqWrap!.satelliteKeys.mlkem1024Pub], [...sat.mlkem]);
});

test('buildPsiSyncOptions fail-closes (null) when the satellite key is unreachable (404)', async () => {
  const options = await buildPsiSyncOptions(
    { identity: { fingerprint } },
    {
      loadKey: async () => ({ privateKey, passphrase }),
      satelliteUrl: 'https://satellite.test',
      fetchImpl: wiringFetch(null),
    },
  );
  assert.equal(options, null); // no key ⇒ can't seal ⇒ no PSI (unsealed body would be 400'd + leak the set)
});

test('buildPsiSyncOptions fail-closes (null) when the fetched key fails the anti-swap pin (swapped key)', async () => {
  const sat = fakeSatelliteKey();
  const other = fakeSatelliteKey(); // a DIFFERENT key — derived fp ≠ sat.fp (the pin)
  const options = await buildPsiSyncOptions(
    { identity: { fingerprint } },
    {
      loadKey: async () => ({ privateKey, passphrase }),
      satelliteUrl: 'https://satellite.test',
      fetchImpl: wiringFetch(other.rec),
      pinnedFp: sat.fp,
    },
  );
  assert.equal(options, null); // swapped key REJECTED by verifySatelliteKey ⇒ fail-closed
});
