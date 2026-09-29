// src/lib/trust/mailbox-pointer-transport.test.ts
// Increment-2 pins: publish/resolve a mailbox pointer over the blind rendezvous (KB#90104/#90108).
//   node --import tsx --test src/lib/trust/mailbox-pointer-transport.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { deriveSharedSecret } from '../crypto/mutual-trust.js';
import { deriveRendezvousTag, type TrustRelay } from './trust-rendezvous.js';
import { deriveMailboxFp, sealToMailbox, openMailboxEnvelope } from '../crypto/mailbox-envelope.js';
import { generateMailboxKeypair, mailboxFpOf, toPublicKeys, toSecretKeys } from '../crypto/mailbox-keys.js';
import { buildSignedMailboxPointer } from '../crypto/mailbox-pointer.js';
import { uint8ToBase64 } from '../crypto/pq.js';
import { publishMailboxPointer, resolveMailboxPointer, type PointerOpenCandidate } from './mailbox-pointer-transport.js';

// in-memory rendezvous relay (blobs keyed by R tag)
function memRelay(): TrustRelay {
  const store = new Map<string, string[]>();
  return {
    async deposit(r, blob) {
      const a = store.get(r) ?? [];
      a.push(blob);
      store.set(r, a);
      return true;
    },
    async poll(r) {
      return store.get(r) ?? [];
    },
  };
}

// fixed identities (deterministic R_e)
const seedA = new Uint8Array(32).fill(0x41);
const seedB = new Uint8Array(32).fill(0x42);
const pubA = ed25519.getPublicKey(seedA);
const pubB = ed25519.getPublicKey(seedB);
const DID_A = 'did:svrnty:aaaa';
const DID_B = 'did:svrnty:bbbb';
const EPOCH_WK = 2900; // fixed rendezvous week epoch (avoid Date.now nondeterminism)

// A's mailbox (what A advertises); B's identity-enc keys (bootstrap target) + B's mailbox (rotation target)
const aMailbox = generateMailboxKeypair();
const aMailboxFp = deriveMailboxFp(aMailbox.x25519Pub, aMailbox.mlkem1024Pub);
const bIdentityEnc = generateMailboxKeypair(); // stand-in: same {x25519,mlkem1024} shape as identity enc keys
const bIdentityEncFp = mailboxFpOf(bIdentityEnc);
const bMailbox = generateMailboxKeypair();
const bMailboxFp = mailboxFpOf(bMailbox);

// what B holds to open with: its identity-enc secrets (bootstrap) + its mailbox secrets (rotation)
const bCandidates: PointerOpenCandidate[] = [
  { secrets: toSecretKeys(bIdentityEnc), fp: bIdentityEncFp },
  { secrets: toSecretKeys(bMailbox), fp: bMailboxFp },
];

const publishArgs = (sealTarget: ReturnType<typeof toPublicKeys>, sealTargetFp: string, pointerEpoch: number) => ({
  myEdPriv: seedA,
  myDid: DID_A,
  peerEdPub: pubB,
  peerDid: DID_B,
  sealTarget,
  sealTargetFp,
  myMailboxX25519Pub: aMailbox.x25519Pub,
  myMailboxMlkemEk: aMailbox.mlkem1024Pub,
  pointerEpoch,
  rendezvousEpoch: EPOCH_WK,
});

const resolveArgs = (openWith: PointerOpenCandidate[]) => ({
  myEdPriv: seedB,
  myDid: DID_B,
  peerEdPub: pubA,
  peerDid: DID_A,
  openWith,
  now: EPOCH_WK,
});

test('KAT (iii) rendezvous R_e is deterministic + symmetric for the pair', () => {
  const rFromA = bytesToHex(deriveRendezvousTag(deriveSharedSecret(seedA, pubB), DID_A, DID_B, EPOCH_WK));
  const rFromB = bytesToHex(deriveRendezvousTag(deriveSharedSecret(seedB, pubA), DID_B, DID_A, EPOCH_WK));
  console.log('KAT_RE_TAG=' + rFromA);
  assert.equal(rFromA, rFromB); // both peers derive the SAME rendezvous (sortDids + symmetric DH)
  assert.equal(rFromA.length, 64);
  assert.equal(rFromA, '34757c24b65a5a304178958b5f20e069abf2e352e0e8a320e1e30f039b37d65b');
});

test('bootstrap (epoch 0): seal to peer identity-enc keys → resolve returns the advertised mailbox', async () => {
  const relay = memRelay();
  const pub = await publishMailboxPointer({ relay, ...publishArgs(toPublicKeys(bIdentityEnc), bIdentityEncFp, 0) });
  assert.equal(pub.deposited, true);
  const got = await resolveMailboxPointer({ relay, ...resolveArgs(bCandidates) });
  assert.ok(got, 'bootstrap pointer must resolve');
  assert.equal(got!.mailboxFp, aMailboxFp);
  assert.equal(got!.epoch, 0);
  assert.equal(bytesToHex(got!.x25519Pub), bytesToHex(aMailbox.x25519Pub));
  assert.equal(bytesToHex(got!.mlkem1024Ek), bytesToHex(aMailbox.mlkem1024Pub));
});

test('rotation (epoch 5): seal to peer current mailbox → resolve', async () => {
  const relay = memRelay();
  await publishMailboxPointer({ relay, ...publishArgs(toPublicKeys(bMailbox), bMailboxFp, 5) });
  const got = await resolveMailboxPointer({ relay, ...resolveArgs(bCandidates) });
  assert.ok(got);
  assert.equal(got!.epoch, 5);
  assert.equal(got!.mailboxFp, aMailboxFp);
});

test('monotonic: higher-epoch pointer wins even across mixed seal targets', async () => {
  const relay = memRelay();
  await publishMailboxPointer({ relay, ...publishArgs(toPublicKeys(bIdentityEnc), bIdentityEncFp, 0) }); // bootstrap
  await publishMailboxPointer({ relay, ...publishArgs(toPublicKeys(bMailbox), bMailboxFp, 1) }); // rotation
  const got = await resolveMailboxPointer({ relay, ...resolveArgs(bCandidates) });
  assert.ok(got);
  assert.equal(got!.epoch, 1); // highest valid epoch, regardless of which target it was sealed to
});

test('forged pointer (signed by a non-peer) is rejected on resolve — even if it reaches R_e', async () => {
  const relay = memRelay();
  const seedF = new Uint8Array(32).fill(0x46); // forger, not A
  const forged = buildSignedMailboxPointer(9, aMailbox.x25519Pub, aMailbox.mlkem1024Pub, seedF);
  const sealed = await sealToMailbox(forged, toPublicKeys(bMailbox), bMailboxFp);
  // simulate the blob reaching the pair rendezvous (defense-in-depth: even if R_e leaked, the sig gate holds)
  const rTag = uint8ToBase64(deriveRendezvousTag(deriveSharedSecret(seedA, pubB), DID_A, DID_B, EPOCH_WK));
  await relay.deposit(rTag, JSON.stringify(sealed));
  const got = await resolveMailboxPointer({ relay, ...resolveArgs(bCandidates) }); // expects A's sig
  assert.equal(got, null); // sig by F != A → verifyMailboxPointer rejects
});

test('resolve with non-matching candidate keys → null (wrong-recipient filter)', async () => {
  const relay = memRelay();
  await publishMailboxPointer({ relay, ...publishArgs(toPublicKeys(bMailbox), bMailboxFp, 3) });
  const stranger = generateMailboxKeypair();
  const got = await resolveMailboxPointer({
    relay,
    ...resolveArgs([{ secrets: toSecretKeys(stranger), fp: mailboxFpOf(stranger) }]),
  });
  assert.equal(got, null); // sealed to bMailbox, opened with stranger keys → envelope returns null
});

// INVARIANT (Flint #141682): resolveMailboxPointer polls a RELAY-INJECTABLE queue, JSON.parses each blob,
// and calls openMailboxEnvelope WITHOUT wrapping the open — so a malicious relay cannot wedge resolve ONLY
// IF openMailboxEnvelope is null-not-throw on every hostile input (including JSON.parse yielding null/a
// primitive from a blob like "null"/"123"). This test pins that dependency: swap in a throwing AEAD or
// reorder a guard and CI fails here, right next to the consumer that relies on it.
test('INVARIANT: openMailboxEnvelope is null-not-throw on hostile relay input (resolve depends on this)', async () => {
  const kp = generateMailboxKeypair();
  const secrets = toSecretKeys(kp);
  const myFp = mailboxFpOf(kp);
  const alg = 'X25519+ML-KEM-1024/HKDF-SHA256/AES-256-GCM';
  const b64 = (n: number) => uint8ToBase64(new Uint8Array(n));
  const wellFormed = { v: 1, alg, mailbox_fp: myFp, epk: b64(32), kem_ct: b64(1568), nonce: b64(12), ct: b64(32) };
  const hostile: unknown[] = [
    null, undefined, 123, 'a string', true, [], {}, // JSON.parse of a relay blob can yield any of these
    { ...wellFormed, epk: '!!not base64!!' }, // bad base64
    { ...wellFormed, epk: b64(31) }, // wrong epk length
    { ...wellFormed, kem_ct: b64(1567) }, // wrong kem_ct length
    { ...wellFormed, nonce: b64(11) }, // wrong nonce length
    { ...wellFormed, v: 2 }, // wrong version
    { ...wellFormed, alg: 'nope' }, // wrong alg
    { ...wellFormed, mailbox_fp: 'deadbeef' }, // wrong recipient
    wellFormed, // valid shape, garbage ct → AEAD tag fail
  ];
  for (const pkg of hostile) {
    let result: unknown = '__THREW__';
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      result = await openMailboxEnvelope(pkg as any, secrets, myFp);
    } catch {
      /* result stays __THREW__ */
    }
    assert.equal(result, null, `must return null (not throw) for: ${String(JSON.stringify(pkg)).slice(0, 48)}`);
  }
});
