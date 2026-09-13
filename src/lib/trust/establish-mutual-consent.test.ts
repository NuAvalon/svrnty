// establishMutualConsent — best-effort owner→peer PSI-discovery consent write.
// Injected loadKey + fetch, no IndexedDB. Run: npx tsx --test src/lib/trust/establish-mutual-consent.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, decryptKey, readPrivateKey } from 'openpgp';
import { ed25519 } from '@noble/curves/ed25519.js';
import { extractRawSign, allowedAddPreimage } from '@/lib/identity/raw-sign';
import { establishMutualConsent } from './establish-mutual-consent';

const passphrase = 'consent-test-pass';
const ownerFp = 'ab'.repeat(32);
const peerFp = 'cd'.repeat(32);

let privateKey: string;
let signPub: Uint8Array;

before(async () => {
  // openpgp's GenerateKeyOptions type omits 'ed25519' from EllipticCurveName in this version even
  // though the runtime supports it (same quirk as build-psi-sync-options.test.ts); cast to satisfy tsc.
  const g = await generateKey({
    type: 'ecc',
    curve: 'ed25519',
    userIDs: [{ name: 'Consent', email: 'consent@example.test' }],
    passphrase,
    format: 'armored',
  } as any);
  privateKey = g.privateKey;
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  ({ signPub } = extractRawSign(unlocked));
});

function captureFetch(status = 200, payload: unknown = { status: 'added' }) {
  const calls: Array<{ url: string; method: string; body: any }> = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method || 'GET',
      body: init?.body ? JSON.parse(init.body as string) : undefined,
    });
    return new Response(JSON.stringify(payload), { status });
  }) as typeof fetch;
  return { calls, fetchImpl };
}

const okKey = () => ({ loadKey: async () => ({ privateKey, passphrase }) });

test('POSTs owner→peer consent to /api/satellite/allowed/{owner} with a verifiable sender-bound sig', async () => {
  const { calls, fetchImpl } = captureFetch();
  const ok = await establishMutualConsent(ownerFp, peerFp, { ...okKey(), fetchImpl });
  assert.equal(ok, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, 'POST');
  assert.equal(calls[0].url, `/api/satellite/allowed/${ownerFp}`);
  assert.equal(calls[0].body.sender_fingerprint, peerFp);

  // wire = "{unix}:{b64sig}"
  const [unixStr, b64sig] = String(calls[0].body.signature).split(':');
  const unix = Number(unixStr);
  assert.ok(Number.isInteger(unix) && unix > 1_600_000_000, 'unix seconds in the wire');

  // The sig verifies against OUR sign pubkey over the owner→peer preimage. This proves the KEY AXIS
  // (Athena #138544): signAllowedAdd signs with the sig keypair the satellite checks, no psi-auth wrap.
  const sig = Uint8Array.from(atob(b64sig), (c) => c.charCodeAt(0));
  assert.equal(ed25519.verify(sig, allowedAddPreimage(ownerFp, peerFp, unix), signPub), true);
});

test('never writes the reverse: the sig does NOT verify as peer→owner', async () => {
  const { calls, fetchImpl } = captureFetch();
  await establishMutualConsent(ownerFp, peerFp, { ...okKey(), fetchImpl });
  const [unixStr, b64sig] = String(calls[0].body.signature).split(':');
  const sig = Uint8Array.from(atob(b64sig), (c) => c.charCodeAt(0));
  assert.equal(ed25519.verify(sig, allowedAddPreimage(peerFp, ownerFp, Number(unixStr)), signPub), false);
});

test('fail-soft guards: keyless peer, self-edge, and locked session → no fetch, returns false', async () => {
  const { calls, fetchImpl } = captureFetch();
  assert.equal(await establishMutualConsent(ownerFp, '', { ...okKey(), fetchImpl }), false, 'keyless peer');
  assert.equal(await establishMutualConsent(ownerFp, ownerFp, { ...okKey(), fetchImpl }), false, 'self-edge');
  assert.equal(await establishMutualConsent(ownerFp, peerFp, { loadKey: async () => null, fetchImpl }), false, 'locked');
  assert.equal(calls.length, 0, 'no consent write on any guard');
});

test('fail-soft: a non-ok satellite response resolves false without throwing', async () => {
  const { fetchImpl } = captureFetch(403, { detail: 'nope' });
  const ok = await establishMutualConsent(ownerFp, peerFp, { ...okKey(), fetchImpl });
  assert.equal(ok, false);
});
