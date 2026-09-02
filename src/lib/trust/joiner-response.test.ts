// R1 pending-joiner return-channel crypto — proves the KNOWN-tier handshake is sound end-to-end and
// fails CLOSED on every attack surface: tamper, anti-downgrade, cross-giver replay, unsolicited
// (nonce), fingerprint-spoof (Invariant-1), confidentiality, wrong-type demux, and domain separation.
// Run: npx tsx --test src/lib/trust/joiner-response.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import {
  buildJoinerResponseEnvelope,
  buildJoinerResponse,
  signJoinerResponse,
  encryptJoinerResponseTo,
  verifyJoinerResponse,
  JoinerResponseSignError,
  type BuildJoinerResponseArgs,
} from './joiner-response';
import {
  DOMAIN_JOINER_RESPONSE,
  DOMAIN_CONTACT_UPDATE,
  joinerResponseSigningInput,
} from '../format/envelope';
import { verifyWithEnvelope } from '../crypto/sign-envelope';
import { generateSigningKeypair, uint8ToBase64, type PQSigningKeypair } from '../crypto/pq';

const pass = 'test-passphrase-r1';
const CODE = 'A7K9QX'; // stand-in relay code = invite_nonce

// Two identities: Alice = GIVER (receives + decrypts), Bob = JOINER (signs the response). Carol =
// unrelated third party (cross-giver / confidentiality). Keygen is expensive → once in before().
let alicePriv: string, alicePub: string, aliceFp: string;
let bobPriv: string, bobPub: string, bobFp: string;
let carolPriv: string, carolPub: string, carolFp: string;
let bobPq: PQSigningKeypair;

before(async () => {
  ({ privateKey: alicePriv, publicKey: alicePub } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Alice', email: 'alice@example.test' }], passphrase: pass, format: 'armored',
  }));
  aliceFp = (await readKey({ armoredKey: alicePub })).getFingerprint();
  ({ privateKey: bobPriv, publicKey: bobPub } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Bob', email: 'bob@example.test' }], passphrase: pass, format: 'armored',
  }));
  bobFp = (await readKey({ armoredKey: bobPub })).getFingerprint();
  ({ privateKey: carolPriv, publicKey: carolPub } = await generateKey({
    type: 'curve25519', userIDs: [{ name: 'Carol', email: 'carol@example.test' }], passphrase: pass, format: 'armored',
  }));
  carolFp = (await readKey({ armoredKey: carolPub })).getFingerprint();
  bobPq = generateSigningKeypair();
});

// Bob's honest args: joiner = Bob, giver = Alice, nonce = the code Alice issued.
function bobArgs(o: Partial<BuildJoinerResponseArgs> = {}): BuildJoinerResponseArgs {
  return {
    joinerFp: bobFp, joinerEpoch: 1, joinerPubKeyArmored: bobPub, joinerName: 'Bob',
    giverFp: aliceFp, inviteNonce: CODE, ts: '2026-09-02T00:00:00Z', ...o,
  };
}
const aliceGiver = () => ({ fingerprint: aliceFp, privateKeyArmored: alicePriv, passphrase: pass });
const yes = (_n: string) => true;   // accept-any nonce oracle (issued-code membership stubbed true)

// ── Round-trip: Bob → mailbox → Alice surfaces Bob as KNOWN ──────────────────────
test('round-trip (classical): Bob signs+encrypts → Alice verifies → PendingJoiner is Bob', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  const joiner = await verifyJoinerResponse(blob, aliceGiver(), (n) => n === CODE);
  assert.ok(joiner, 'a valid joiner-response must verify');
  assert.equal(joiner!.fingerprint, bobFp);
  assert.equal(joiner!.epoch, 1);
  assert.equal(joiner!.publicKeyArmored, bobPub);
  assert.equal(joiner!.displayName, 'Bob');
  assert.equal(joiner!.inviteNonce, CODE);
  assert.equal(joiner!.pqSigningPublicKey, undefined, 'classical → no pq key returned');
});

// ── Hybrid PQ round-trip + anti-downgrade ────────────────────────────────────────
test('round-trip (hybrid): PQ-signed response verifies under requirePq and returns the pq key bytes', async () => {
  const signed = await buildJoinerResponse(
    bobArgs({ joinerPqSigPublicKey: uint8ToBase64(bobPq.publicKey) }), bobPriv, pass, bobPq.secretKey,
  );
  assert.ok(signed.signature.pq_signature, 'hybrid signature must carry a pq half');
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  const joiner = await verifyJoinerResponse(blob, aliceGiver(), yes, { requirePq: true });
  assert.ok(joiner, 'hybrid response must verify');
  assert.deepEqual(joiner!.pqSigningPublicKey, bobPq.publicKey, 'returned pq key must round-trip exactly');
});

test('anti-downgrade: stripping the pq half of a hybrid response fails verification (→ null)', async () => {
  const signed = await buildJoinerResponse(
    bobArgs({ joinerPqSigPublicKey: uint8ToBase64(bobPq.publicKey) }), bobPriv, pass, bobPq.secretKey,
  );
  delete signed.signature.pq_signature; // suite flips to classical → signedBytes differ → classical half fails
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), yes), null);
});

test('suite floor: requirePq rejects a classical-only response (→ null)', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass); // classical only
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), yes, { requirePq: true }), null);
});

// ── Tamper-evidence: the signature binds every envelope field ────────────────────
test('tamper: mutating the display name after signing fails (→ null)', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  signed.envelope.joiner_display_name = 'Mallory';
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), yes), null);
});

test('nonce is BOUND: swapping invite_nonce to another (also-accepted) code fails the signature (→ null)', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  signed.envelope.invite_nonce = 'B8L0RY'; // a different code the oracle would also accept…
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), () => true), null); // …still rejected: nonce was signed
});

test('tamper: swapping the joiner public key (keep fp) fails (fp-binding or signature) (→ null)', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  signed.envelope.joiner_public_key = carolPub; // now fp≠H(key) AND the signature was over bobPub
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), yes), null);
});

// ── Cross-giver replay: a response for Alice cannot be surfaced by another giver ──
test('cross-giver replay: giver_fingerprint binds the recipient — Carol (able to decrypt) still rejects (→ null)', async () => {
  // Bob addresses Alice (giver_fingerprint = aliceFp) but the blob is encrypted to Carol so she CAN
  // decrypt — isolating the giver-binding check from the encryption layer. Carol must still reject.
  const signed = await buildJoinerResponse(bobArgs({ giverFp: aliceFp }), bobPriv, pass);
  const blobToCarol = await encryptJoinerResponseTo(signed, carolPub);
  const carolGiver = { fingerprint: carolFp, privateKeyArmored: carolPriv, passphrase: pass };
  assert.equal(await verifyJoinerResponse(blobToCarol, carolGiver, yes), null);
});

// ── Solicited-gate: an unsolicited deposit (nonce not issued) is dropped ──────────
test('solicited-gate: a valid signature with an unissued nonce is dropped (acceptNonce=false → null)', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), () => false), null);
});

test('solicited-gate: acceptNonce is called with the exact invite_nonce', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  let seen: string | undefined;
  await verifyJoinerResponse(blob, aliceGiver(), (n) => { seen = n; return true; });
  assert.equal(seen, CODE);
});

test('solicited-gate: a throwing acceptNonce oracle fails closed (→ null)', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), () => { throw new Error('store down'); }), null);
});

test('single-use pattern: first accept, then (caller marks consumed) a replay is dropped', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  const issued = new Set([CODE]);
  const consumed = new Set<string>();
  const oracle = (n: string) => issued.has(n) && !consumed.has(n);
  const first = await verifyJoinerResponse(blob, aliceGiver(), oracle);
  assert.ok(first, 'first use accepted');
  consumed.add(first!.inviteNonce); // caller marks consumed (single-use closure)
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), oracle), null, 'replay rejected');
});

// ── Invariant-1: a spoofed fingerprint (real fp + attacker key) is refused ────────
test('Invariant-1: joiner_fingerprint that does not hash to joiner_public_key is refused (→ null)', async () => {
  // Bob claims CAROL's fingerprint while presenting HIS OWN key and signing with his own key. The
  // signature is internally valid, but fp≠H(key) — the exact spoof fingerprintMatchesKey exists to stop.
  const signed = await buildJoinerResponse(bobArgs({ joinerFp: carolFp }), bobPriv, pass);
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), yes), null);
});

// ── Confidentiality (E2E): only the addressed giver can open the blob ─────────────
test('confidentiality: a blob encrypted to Alice cannot be opened by Carol (→ null)', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  const blobToAlice = await encryptJoinerResponseTo(signed, alicePub);
  const carolGiver = { fingerprint: carolFp, privateKeyArmored: carolPriv, passphrase: pass };
  assert.equal(await verifyJoinerResponse(blobToAlice, carolGiver, yes), null);
});

// ── Mixed-mailbox demux + noise: wrong-shape and junk blobs drop silently ─────────
test('demux: a contact-update-shaped blob (no joiner fields) is dropped by verifyJoinerResponse (→ null)', async () => {
  const notAJoiner = { envelope: { fingerprint: bobFp, epoch: 1, version: 1, changed_fields: ['emails'], delta: { emails: ['x@y.z'] } }, signature: { classical: 'x' } };
  const { createMessage, encrypt, readKey } = await import('openpgp');
  const blob = (await encrypt({ message: await createMessage({ text: JSON.stringify(notAJoiner) }), encryptionKeys: await readKey({ armoredKey: alicePub }) })) as string;
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), yes), null);
});

test('noise: a non-PGP blob decrypts-fails and drops (→ null)', async () => {
  assert.equal(await verifyJoinerResponse('not-an-armored-message', aliceGiver(), yes), null);
});

// ── Domain separation: the joiner-response signature is not a contact-update sig ──
test('domain separation: the same signed bytes verify under JOINER_RESPONSE but NOT under CONTACT_UPDATE', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  const input = joinerResponseSigningInput(signed.envelope);
  assert.equal(await verifyWithEnvelope(DOMAIN_JOINER_RESPONSE, input, signed.signature, bobPub), true);
  assert.equal(await verifyWithEnvelope(DOMAIN_CONTACT_UPDATE, input, signed.signature, bobPub), false);
});

// ── Fail-loud-at-BUILD (send side controls its own inputs) ────────────────────────
test('build: empty joiner fingerprint refused (bad-joiner-fingerprint)', () => {
  assert.throws(() => buildJoinerResponseEnvelope(bobArgs({ joinerFp: '' })),
    (e: unknown) => e instanceof JoinerResponseSignError && e.reason === 'bad-joiner-fingerprint');
});
test('build: empty invite nonce refused (bad-invite-nonce)', () => {
  assert.throws(() => buildJoinerResponseEnvelope(bobArgs({ inviteNonce: '' })),
    (e: unknown) => e instanceof JoinerResponseSignError && e.reason === 'bad-invite-nonce');
});
test('build: empty giver fingerprint refused (bad-giver-fingerprint)', () => {
  assert.throws(() => buildJoinerResponseEnvelope(bobArgs({ giverFp: '' })),
    (e: unknown) => e instanceof JoinerResponseSignError && e.reason === 'bad-giver-fingerprint');
});
test('build: negative epoch refused (bad-joiner-epoch)', () => {
  assert.throws(() => buildJoinerResponseEnvelope(bobArgs({ joinerEpoch: -1 })),
    (e: unknown) => e instanceof JoinerResponseSignError && e.reason === 'bad-joiner-epoch');
});
test('build: present-but-empty pq key refused (bad-pq-key)', () => {
  assert.throws(() => buildJoinerResponseEnvelope(bobArgs({ joinerPqSigPublicKey: '' })),
    (e: unknown) => e instanceof JoinerResponseSignError && e.reason === 'bad-pq-key');
});
test('build: optional pq key is OMITTED (not null) when absent — canonical stays null-free', () => {
  const env = buildJoinerResponseEnvelope(bobArgs());
  assert.equal('joiner_pq_sig_public_key' in env, false);
});
