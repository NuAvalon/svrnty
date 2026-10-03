// allowed-sync — client /allowed ADD/DELETE signing + reconcile-by-invariant (AND-gate b, #572).
// Run: node --import tsx --test src/lib/sync/allowed-sync.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  addAllowedSender,
  removeAllowedSender,
  reconcileAllowedForPeer,
  allowedRowShouldExist,
  type PeerConsent,
} from './allowed-sync';

const OWNER = 'aa'.repeat(32); // 64 lowercase-hex
const SENDER = 'bb'.repeat(32);
const SEED = ed25519.utils.randomSecretKey(); // 32B bound sig seed (self-bind)
const PUB = ed25519.getPublicKey(SEED);
const FIXED_UNIX = 1_700_000_000;

function b64ToBytes(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

interface Captured {
  url: string;
  method: string;
  body: Record<string, unknown>;
  xsig: string | null;
}
function capturingFetch(status = 200): { fetchImpl: typeof fetch; calls: Captured[] } {
  const calls: Captured[] = [];
  const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    calls.push({
      url: String(input),
      method: init?.method || 'GET',
      body: init?.body && typeof init.body === 'string' ? JSON.parse(init.body) : {},
      xsig: headers.get('X-Signature'),
    });
    return new Response('{}', { status });
  }) as typeof fetch;
  return { fetchImpl, calls };
}

test('addAllowedSender POSTs /{owner} with a signed svrnty-allowed-add wire that verifies', async () => {
  const { fetchImpl, calls } = capturingFetch(200);
  const ok = await addAllowedSender({
    ownerFp: OWNER,
    senderFp: SENDER,
    seed: SEED,
    fetchImpl,
    nowUnixSeconds: FIXED_UNIX,
  });
  assert.equal(ok, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, 'POST');
  assert.equal(calls[0].url, `/api/satellite/allowed/${OWNER}`);
  assert.equal(calls[0].body.sender_fingerprint, SENDER);
  const [unixStr, b64sig] = String(calls[0].body.signature).split(':');
  assert.equal(unixStr, String(FIXED_UNIX)); // wire = {unix}:{b64sig}
  const preimage = new TextEncoder().encode(`svrnty-allowed-add:${OWNER}:${SENDER}:${FIXED_UNIX}`);
  assert.equal(ed25519.verify(b64ToBytes(b64sig), preimage, PUB), true); // bound-sig-key signed the exact preimage
});

test('removeAllowedSender DELETEs /{owner}/{sender} with X-Signature svrnty-allowed-remove that verifies', async () => {
  const { fetchImpl, calls } = capturingFetch(200);
  const ok = await removeAllowedSender({
    ownerFp: OWNER,
    senderFp: SENDER,
    seed: SEED,
    fetchImpl,
    nowUnixSeconds: FIXED_UNIX,
  });
  assert.equal(ok, true);
  assert.equal(calls[0].method, 'DELETE');
  assert.equal(calls[0].url, `/api/satellite/allowed/${OWNER}/${SENDER}`);
  const [unixStr, b64sig] = String(calls[0].xsig).split(':');
  assert.equal(unixStr, String(FIXED_UNIX));
  const preimage = new TextEncoder().encode(`svrnty-allowed-remove:${OWNER}:${SENDER}:${FIXED_UNIX}`);
  assert.equal(ed25519.verify(b64ToBytes(b64sig), preimage, PUB), true);
  // domain-separation: the remove sig must NOT verify as an add
  const addPre = new TextEncoder().encode(`svrnty-allowed-add:${OWNER}:${SENDER}:${FIXED_UNIX}`);
  assert.equal(ed25519.verify(b64ToBytes(b64sig), addPre, PUB), false);
});

test('reconcileAllowedForPeer: ADD iff trusted∩open_vis∩!blocked, else DELETE (all 3 exits)', async () => {
  const cases: Array<{ consent: PeerConsent; action: 'add' | 'delete'; method: string }> = [
    { consent: { trusted: true, openVisibility: true, blocked: false }, action: 'add', method: 'POST' }, // full invariant → ADD
    { consent: { trusted: false, openVisibility: true, blocked: false }, action: 'delete', method: 'DELETE' }, // untrust exit
    { consent: { trusted: true, openVisibility: false, blocked: false }, action: 'delete', method: 'DELETE' }, // go-private exit
    { consent: { trusted: true, openVisibility: true, blocked: true }, action: 'delete', method: 'DELETE' }, // block exit
  ];
  for (const c of cases) {
    const { fetchImpl, calls } = capturingFetch(200);
    const r = await reconcileAllowedForPeer({
      ownerFp: OWNER,
      senderFp: SENDER,
      seed: SEED,
      consent: c.consent,
      fetchImpl,
      nowUnixSeconds: FIXED_UNIX,
    });
    assert.equal(r.action, c.action, JSON.stringify(c.consent));
    assert.equal(r.ok, true);
    assert.equal(calls[0].method, c.method, JSON.stringify(c.consent));
  }
});

test('fail-closed: non-2xx → false, network throw → false', async () => {
  const { fetchImpl: f403 } = capturingFetch(403);
  assert.equal(
    await addAllowedSender({ ownerFp: OWNER, senderFp: SENDER, seed: SEED, fetchImpl: f403, nowUnixSeconds: FIXED_UNIX }),
    false,
  );
  const throwing = (async () => {
    throw new Error('network down');
  }) as unknown as typeof fetch;
  assert.equal(
    await removeAllowedSender({ ownerFp: OWNER, senderFp: SENDER, seed: SEED, fetchImpl: throwing, nowUnixSeconds: FIXED_UNIX }),
    false,
  );
});

test('allowedRowShouldExist = the full consent invariant', () => {
  assert.equal(allowedRowShouldExist({ trusted: true, openVisibility: true, blocked: false }), true);
  assert.equal(allowedRowShouldExist({ trusted: false, openVisibility: true, blocked: false }), false);
  assert.equal(allowedRowShouldExist({ trusted: true, openVisibility: false, blocked: false }), false);
  assert.equal(allowedRowShouldExist({ trusted: true, openVisibility: true, blocked: true }), false);
});
