// src/lib/trust/trust-rendezvous.test.ts
// Sovereign trust-rendezvous (Track C) — client crypto core, mock relay.
// Run: npx tsx --test src/lib/trust/trust-rendezvous.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { generateKEMKeypair } from '../crypto/pq.js';
import { deriveMailboxFp, type MailboxPublicKeys, type MailboxSecretKeys } from '../crypto/mailbox-envelope.js';
import {
  deriveRendezvousTag,
  rendezvousTagFor,
  buildSignedBeacon,
  verifyBeacon,
  beaconSigPreimage,
  depositTrustBeacon,
  pollForPeerTrust,
  rehydrateTrustBeacons,
  httpTrustRelay,
  type TrustRelay,
  type TrustBeacon,
} from './trust-rendezvous.js';
import { deriveSharedSecret } from '../crypto/mutual-trust.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const signFn = (msg: Uint8Array, sk: Uint8Array) => ed25519.sign(msg, sk);
const verifyFn = (sig: Uint8Array, msg: Uint8Array, pk: Uint8Array) => {
  try {
    return ed25519.verify(sig, msg, pk);
  } catch {
    return false;
  }
};

interface Peer {
  edPriv: Uint8Array;
  edPub: Uint8Array;
  did: string;
  mbPub: MailboxPublicKeys;
  mbSec: MailboxSecretKeys;
  mbFp: string;
}

function mkPeer(didTag: string): Peer {
  const edPriv = ed25519.utils.randomSecretKey();
  const edPub = ed25519.getPublicKey(edPriv);
  const xSk = x25519.utils.randomSecretKey();
  const xPub = x25519.getPublicKey(xSk);
  const kem = generateKEMKeypair();
  const mbFp = deriveMailboxFp(xPub, kem.publicKey);
  return {
    edPriv,
    edPub,
    did: `did:${didTag}:${bytesToHex(edPub).slice(0, 24)}`,
    mbPub: { x25519Pub: xPub, mlkem1024Pub: kem.publicKey },
    mbSec: { x25519Sec: xSk, mlkem1024Sec: kem.secretKey },
    mbFp,
  };
}

/** In-memory relay: list of blobs per rendezvous tag — mirrors the deposit/poll namespace Athena builds. */
function mockRelay(): TrustRelay & { store: Map<string, string[]> } {
  const store = new Map<string, string[]>();
  return {
    store,
    async deposit(rTagB64, blob) {
      const arr = store.get(rTagB64) ?? [];
      arr.push(blob);
      store.set(rTagB64, arr);
      return true;
    },
    async poll(rTagB64) {
      return store.get(rTagB64) ?? [];
    },
  };
}

const EPOCH = 2876; // fixed test epoch

test('R is symmetric: both peers derive the same rendezvous tag', () => {
  const a = mkPeer('a');
  const b = mkPeer('b');
  const rFromA = rendezvousTagFor(a.edPriv, b.edPub, a.did, b.did, EPOCH);
  const rFromB = rendezvousTagFor(b.edPriv, a.edPub, b.did, a.did, EPOCH);
  assert.equal(bytesToHex(rFromA), bytesToHex(rFromB));
  assert.equal(rFromA.length, 32);
});

test('R is relay-blind: differs per epoch and per pair', () => {
  const a = mkPeer('a');
  const b = mkPeer('b');
  const c = mkPeer('c');
  const sAB = deriveSharedSecret(a.edPriv, b.edPub);
  const sAC = deriveSharedSecret(a.edPriv, c.edPub);
  assert.notEqual(bytesToHex(deriveRendezvousTag(sAB, a.did, b.did, EPOCH)), bytesToHex(deriveRendezvousTag(sAB, a.did, b.did, EPOCH + 1)));
  assert.notEqual(bytesToHex(deriveRendezvousTag(sAB, a.did, b.did, EPOCH)), bytesToHex(deriveRendezvousTag(sAC, a.did, c.did, EPOCH)));
});

test('mutual: A deposits → B polls sees "A trusts B"; C (uninvolved) sees nothing', async () => {
  const relay = mockRelay();
  const a = mkPeer('a');
  const b = mkPeer('b');
  // A trusts B → deposit
  const { deposited } = await depositTrustBeacon({
    relay, myEdPriv: a.edPriv, myDid: a.did, peerEdPub: b.edPub, peerDid: b.did,
    peerMailbox: b.mbPub, peerMailboxFp: b.mbFp, signFn, epoch: EPOCH,
  });
  assert.ok(deposited);
  // B polls (B's trust decision) → sees A trusts B
  const bSees = await pollForPeerTrust({
    relay, myEdPriv: b.edPriv, myDid: b.did, myMailbox: b.mbSec, myMailboxFp: b.mbFp,
    peerEdPub: a.edPub, peerDid: a.did, verifyFn, now: EPOCH,
  });
  assert.equal(bSees, true);
  // A polls before B deposits → A does NOT yet see mutual (B hasn't reciprocated)
  const aSees = await pollForPeerTrust({
    relay, myEdPriv: a.edPriv, myDid: a.did, myMailbox: a.mbSec, myMailboxFp: a.mbFp,
    peerEdPub: b.edPub, peerDid: b.did, verifyFn, now: EPOCH,
  });
  assert.equal(aSees, false);
});

test('full mutual bond: both deposit → both poll true', async () => {
  const relay = mockRelay();
  const a = mkPeer('a');
  const b = mkPeer('b');
  await depositTrustBeacon({ relay, myEdPriv: a.edPriv, myDid: a.did, peerEdPub: b.edPub, peerDid: b.did, peerMailbox: b.mbPub, peerMailboxFp: b.mbFp, signFn, epoch: EPOCH });
  await depositTrustBeacon({ relay, myEdPriv: b.edPriv, myDid: b.did, peerEdPub: a.edPub, peerDid: a.did, peerMailbox: a.mbPub, peerMailboxFp: a.mbFp, signFn, epoch: EPOCH });
  const aSees = await pollForPeerTrust({ relay, myEdPriv: a.edPriv, myDid: a.did, myMailbox: a.mbSec, myMailboxFp: a.mbFp, peerEdPub: b.edPub, peerDid: b.did, verifyFn, now: EPOCH });
  const bSees = await pollForPeerTrust({ relay, myEdPriv: b.edPriv, myDid: b.did, myMailbox: b.mbSec, myMailboxFp: b.mbFp, peerEdPub: a.edPub, peerDid: a.did, verifyFn, now: EPOCH });
  assert.ok(aSees && bSees, 'both sides bond');
  // Both beacons collide at the SAME symmetric R; the envelope wrong-recipient filter keeps them apart.
  const rAB = bytesToHex(rendezvousTagFor(a.edPriv, b.edPub, a.did, b.did, EPOCH));
  const rBA = bytesToHex(rendezvousTagFor(b.edPriv, a.edPub, b.did, a.did, EPOCH));
  assert.equal(rAB, rBA);
});

test('★ ANTI-FORGERY (Flint #136666): B cannot forge "A trusts B" — self-signed beacon fails verify', () => {
  const a = mkPeer('a');
  const b = mkPeer('b');
  // B crafts a beacon CLAIMING from_did=A, but can only sign with B's own key (lacks A's private key).
  const forged: TrustBeacon = buildSignedBeacon(a.did, b.did, EPOCH, b.edPriv, signFn); // signed by B, claims A
  // B (or anyone) verifies against A's identity pubkey → MUST reject (B's sig ≠ A's sig).
  assert.equal(verifyBeacon(forged, a.did, b.did, a.edPub, verifyFn, EPOCH), false);
  // Sanity: a genuine A-signed beacon DOES verify vs A's pubkey.
  const genuine = buildSignedBeacon(a.did, b.did, EPOCH, a.edPriv, signFn);
  assert.equal(verifyBeacon(genuine, a.did, b.did, a.edPub, verifyFn, EPOCH), true);
});

test('epoch window: current-1 accepted, current-2 rejected, wrong from/to rejected', () => {
  const a = mkPeer('a');
  const b = mkPeer('b');
  const prev = buildSignedBeacon(a.did, b.did, EPOCH - 1, a.edPriv, signFn);
  assert.equal(verifyBeacon(prev, a.did, b.did, a.edPub, verifyFn, EPOCH), true, 'current-1 within skew window');
  const old = buildSignedBeacon(a.did, b.did, EPOCH - 2, a.edPriv, signFn);
  assert.equal(verifyBeacon(old, a.did, b.did, a.edPub, verifyFn, EPOCH), false, 'current-2 outside window');
  const genuine = buildSignedBeacon(a.did, b.did, EPOCH, a.edPriv, signFn);
  assert.equal(verifyBeacon(genuine, 'did:wrong:xx', b.did, a.edPub, verifyFn, EPOCH), false, 'from mismatch');
  assert.equal(verifyBeacon(genuine, a.did, 'did:wrong:yy', a.edPub, verifyFn, EPOCH), false, 'to mismatch');
});

test('beacon sig preimage is domain-separated + injective on fields', () => {
  const p1 = new TextDecoder().decode(beaconSigPreimage('did:a', 'did:b', 7));
  assert.ok(p1.startsWith('svrnty-trust-beacon-v1:'));
  // swapping from/to changes the preimage (no field-merge ambiguity)
  assert.notEqual(p1, new TextDecoder().decode(beaconSigPreimage('did:b', 'did:a', 7)));
});

test('rehydrate: idempotent re-deposit to a fresh relay still bonds (migrate/rehydrate §46)', async () => {
  const a = mkPeer('a');
  const b = mkPeer('b');
  // B already trusts A (so A polling will bond once A's beacon is on the new relay).
  const newRelay = mockRelay();
  await depositTrustBeacon({ relay: newRelay, myEdPriv: b.edPriv, myDid: b.did, peerEdPub: a.edPub, peerDid: a.did, peerMailbox: a.mbPub, peerMailboxFp: a.mbFp, signFn, epoch: EPOCH });
  // A migrates → rehydrates its trust beacons to the new relay from the book (peer list).
  const res = await rehydrateTrustBeacons({
    relay: newRelay, myEdPriv: a.edPriv, myDid: a.did, signFn,
    peers: [{ edPub: b.edPub, did: b.did, mailbox: b.mbPub, mailboxFp: b.mbFp }],
    epoch: EPOCH,
  });
  assert.deepEqual(res, [{ peerDid: b.did, deposited: true }]);
  // Re-run rehydrate (idempotent) — still fine, and both sides bond on the new relay.
  await rehydrateTrustBeacons({ relay: newRelay, myEdPriv: a.edPriv, myDid: a.did, signFn, peers: [{ edPub: b.edPub, did: b.did, mailbox: b.mbPub, mailboxFp: b.mbFp }], epoch: EPOCH });
  const aSees = await pollForPeerTrust({ relay: newRelay, myEdPriv: a.edPriv, myDid: a.did, myMailbox: a.mbSec, myMailboxFp: a.mbFp, peerEdPub: b.edPub, peerDid: b.did, verifyFn, now: EPOCH });
  assert.equal(aSees, true, 'bond survives migration to a new relay via rehydrate');
});

// ── Track C relay-wire: httpTrustRelay adapter to the satellite /trust/rendezvous/* endpoints (Athena #137166) ──
/** Mock fetch faithfully simulating the deployed endpoints: an in-memory store keyed by r. */
function satelliteMockFetch() {
  const store = new Map<string, string[]>();
  const seen: Array<{ path: string; body: Record<string, unknown> }> = [];
  const fetchImpl = (async (url: string, init?: { body?: string }) => {
    const path = new URL(url).pathname;
    const body = JSON.parse(init?.body ?? '{}') as Record<string, unknown>;
    seen.push({ path, body });
    if (path === '/trust/rendezvous/deposit') {
      const r = body.r as string;
      const arr = store.get(r) ?? [];
      arr.push(body.blob as string);
      store.set(r, arr);
      return { ok: true, json: async () => ({ deposited: true }) } as Response;
    }
    if (path === '/trust/rendezvous/poll') {
      return { ok: true, json: async () => ({ blobs: store.get(body.r as string) ?? [] }) } as Response;
    }
    return { ok: false, json: async () => ({}) } as Response;
  }) as unknown as typeof fetch;
  return { fetchImpl, store, seen };
}

test('httpTrustRelay: wire shape matches Athena #137166 (POST {r,blob}→{deposited}; POST {r}→{blobs})', async () => {
  const { fetchImpl, seen } = satelliteMockFetch();
  const relay = httpTrustRelay('http://sat:8100/', fetchImpl); // trailing slash normalized
  assert.equal(await relay.deposit('R_b64', 'blob1'), true);
  assert.deepEqual(await relay.poll('R_b64'), ['blob1']);
  assert.deepEqual(seen[0], { path: '/trust/rendezvous/deposit', body: { r: 'R_b64', blob: 'blob1' } });
  assert.deepEqual(seen[1], { path: '/trust/rendezvous/poll', body: { r: 'R_b64' } });
});

test('httpTrustRelay: full mutual bond through the HTTP adapter (mock-fetch-backed satellite)', async () => {
  const { fetchImpl } = satelliteMockFetch();
  const relay = httpTrustRelay('http://sat:8100', fetchImpl);
  const a = mkPeer('a');
  const b = mkPeer('b');
  await depositTrustBeacon({ relay, myEdPriv: a.edPriv, myDid: a.did, peerEdPub: b.edPub, peerDid: b.did, peerMailbox: b.mbPub, peerMailboxFp: b.mbFp, signFn, epoch: EPOCH });
  await depositTrustBeacon({ relay, myEdPriv: b.edPriv, myDid: b.did, peerEdPub: a.edPub, peerDid: a.did, peerMailbox: a.mbPub, peerMailboxFp: a.mbFp, signFn, epoch: EPOCH });
  const aSees = await pollForPeerTrust({ relay, myEdPriv: a.edPriv, myDid: a.did, myMailbox: a.mbSec, myMailboxFp: a.mbFp, peerEdPub: b.edPub, peerDid: b.did, verifyFn, now: EPOCH });
  const bSees = await pollForPeerTrust({ relay, myEdPriv: b.edPriv, myDid: b.did, myMailbox: b.mbSec, myMailboxFp: b.mbFp, peerEdPub: a.edPub, peerDid: a.did, verifyFn, now: EPOCH });
  assert.ok(aSees && bSees, 'both bond through the HTTP adapter');
});

test('httpTrustRelay: fail-soft — non-2xx deposit→false, failed poll→[]', async () => {
  const fetchImpl = (async () => ({ ok: false, json: async () => ({}) }) as Response) as unknown as typeof fetch;
  const relay = httpTrustRelay('http://sat:8100', fetchImpl);
  assert.equal(await relay.deposit('R', 'b'), false);
  assert.deepEqual(await relay.poll('R'), []);
});
