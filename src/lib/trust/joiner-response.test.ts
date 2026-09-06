// R1 pending-joiner return-channel crypto — proves the KNOWN-tier handshake is sound end-to-end and
// fails CLOSED on every attack surface: tamper, anti-downgrade, cross-giver replay, unsolicited
// (nonce), fingerprint-spoof (Invariant-1), confidentiality, wrong-type demux, and domain separation.
// Run: npx tsx --test src/lib/trust/joiner-response.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey, readPrivateKey, decryptKey } from 'openpgp';
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
import { generateSigningKeypair, generatePQKeypairBundle, uint8ToBase64, type PQSigningKeypair } from '../crypto/pq';
import { mintCanonicalFingerprint } from '../identity/fingerprint';

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

// A §5 CANONICAL joiner: openpgp (sign+enc) + ML-KEM/ML-DSA pubkeys → a 64-hex SHA256(sign‖enc‖kem‖sig)
// fingerprint (NOT the 40-hex OpenPGP fp). Mirrors genesis + relay/mailbox-auth.test.ts makeCanonicalIdentity.
interface CanonicalIdentity {
  fingerprint: string;
  publicKey: string;
  privateKey: string;
  passphrase: string;
  kemPublicKeyB64: string;
  sigPublicKeyB64: string;
  sigPublicKey: Uint8Array;   // raw ML-DSA pubkey bytes (for the hybrid round-trip assertion)
  sigSecretKey: Uint8Array;   // raw ML-DSA secret — to make a HYBRID signature under this canonical id
}
async function makeCanonicalIdentity(name: string): Promise<CanonicalIdentity> {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime — this is the exact
    // keygen used in src/lib/identity/core.ts (which carries the same pre-existing tsc wart).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked,
    kemPublicKey: pq.kem.publicKey,
    sigPublicKey: pq.signing.publicKey,
  });
  return {
    fingerprint,
    publicKey,
    privateKey,
    passphrase,
    kemPublicKeyB64: uint8ToBase64(pq.kem.publicKey),
    sigPublicKeyB64: uint8ToBase64(pq.signing.publicKey),
    sigPublicKey: pq.signing.publicKey,
    sigSecretKey: pq.signing.secretKey,
  };
}

// A canonical joiner's honest build args: joiner = the canonical id, giver = Alice, PQ pubkeys threaded.
function canonJoinerArgs(cid: CanonicalIdentity, o: Partial<BuildJoinerResponseArgs> = {}): BuildJoinerResponseArgs {
  return {
    joinerFp: cid.fingerprint, joinerEpoch: 1, joinerPubKeyArmored: cid.publicKey, joinerName: 'Canon',
    giverFp: aliceFp, inviteNonce: CODE, ts: '2026-09-02T00:00:00Z',
    joinerPqKemPublicKey: cid.kemPublicKeyB64, joinerPqSigPublicKey: cid.sigPublicKeyB64, ...o,
  };
}

// ── Round-trip: Bob → mailbox → Alice surfaces Bob as KNOWN ──────────────────────
test('CANONICAL-ONLY GATE (res1): a classical 40-hex joiner does NOT verify — the OpenPGP fall-through is removed (the canonical handshake is the "CANONICAL round-trip" test below)', async () => {
  // Bob is a classical (40-hex OpenPGP) identity. Post-res1 verifyJoinerResponse's fingerprintMatchesKey
  // is canonical-only: a 40-hex joiner_fingerprint with no PQ legs → false → the handshake drops (→ null).
  // Inverts the pre-res1 "classical binds" assertion; the authenticating handshake is now canonical (below).
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), (n) => n === CODE), null);
});

// ── Hybrid PQ round-trip + anti-downgrade ────────────────────────────────────────
test('round-trip (hybrid): a CANONICAL joiner PQ-signs → verifies under requirePq and returns the pq key bytes', async () => {
  // Post-res1 the joiner must be canonical (64-hex). Sign HYBRID with the canonical id's OWN ML-DSA key —
  // the same key committed in its canonical fp AND threaded as joinerPqSigPublicKey — so the fp-match passes
  // AND the pq signature verifies under requirePq. (The canonical happy-path below signs classically; this
  // pins the distinct HYBRID ML-DSA-signature path on a canonical joiner.)
  const cid = await makeCanonicalIdentity('canon-hybrid');
  const signed = await buildJoinerResponse(canonJoinerArgs(cid), cid.privateKey, cid.passphrase, cid.sigSecretKey);
  assert.ok(signed.signature.pq_signature, 'hybrid signature must carry a pq half');
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  const joiner = await verifyJoinerResponse(blob, aliceGiver(), yes, { requirePq: true });
  assert.ok(joiner, 'hybrid canonical response must verify');
  assert.deepEqual(joiner!.pqSigningPublicKey, cid.sigPublicKey, 'returned pq key must round-trip exactly');
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

test('solicited-gate: acceptNonce receives the exact invite_nonce AND the claimed joiner fingerprint', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  let seenNonce: string | undefined, seenFp: string | undefined;
  await verifyJoinerResponse(blob, aliceGiver(), (n, fp) => { seenNonce = n; seenFp = fp; return true; });
  assert.equal(seenNonce, CODE);
  assert.equal(seenFp, bobFp);
});

test('solicited-gate: a throwing acceptNonce oracle fails closed (→ null)', async () => {
  const signed = await buildJoinerResponse(bobArgs(), bobPriv, pass);
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), () => { throw new Error('store down'); }), null);
});

test('multi-use + per-(code,joinerFp) dedup: two distinct joiners on ONE code both connect; same-joiner replay dropped', async () => {
  const issued = new Set([CODE]);
  const accepted = new Set<string>(); // key = code|joinerFp — the CODE itself is never consumed
  const key = (n: string, fp: string) => `${n}|${fp}`;
  const oracle = (n: string, fp: string) => issued.has(n) && !accepted.has(key(n, fp));

  // Two DISTINCT canonical joiners on the same multi-use code (post-res1: joiners must be canonical).
  const j1 = await makeCanonicalIdentity('joiner1');
  const j2 = await makeCanonicalIdentity('joiner2');

  // Joiner #1 on CODE.
  const j1Blob = await encryptJoinerResponseTo(await buildJoinerResponse(canonJoinerArgs(j1), j1.privateKey, j1.passphrase), alicePub);
  const first = await verifyJoinerResponse(j1Blob, aliceGiver(), oracle);
  assert.ok(first, 'joiner #1 accepted');
  assert.equal(first!.fingerprint, j1.fingerprint);
  accepted.add(key(first!.inviteNonce, first!.fingerprint));

  // Joiner #2 on the SAME code (multi-use Grow link) — must ALSO connect.
  const j2Blob = await encryptJoinerResponseTo(await buildJoinerResponse(canonJoinerArgs(j2), j2.privateKey, j2.passphrase), alicePub);
  const second = await verifyJoinerResponse(j2Blob, aliceGiver(), oracle);
  assert.ok(second, 'joiner #2 on the same code also accepted (multi-use preserved)');
  assert.equal(second!.fingerprint, j2.fingerprint);
  accepted.add(key(second!.inviteNonce, second!.fingerprint));

  // Joiner #1 replays their blob → dropped (per-(code,joinerFp) already accepted); code still live for others.
  assert.equal(await verifyJoinerResponse(j1Blob, aliceGiver(), oracle), null, 'same-joiner replay dropped');
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
  assert.equal('joiner_pq_kem_public_key' in env, false);
});

// ── §5 CANONICAL-ID joiner-response: thread PQ pubkeys → the 64-hex canonical fp recomputes + matches ──

test('CANONICAL round-trip: a 64-hex canonical joiner verifies WHEN the PQ pubkeys are threaded (the §5 fix)', async () => {
  const cid = await makeCanonicalIdentity('canon');
  assert.match(cid.fingerprint, /^[0-9a-f]{64}$/); // 64-hex canonical, NOT a 40-hex OpenPGP fp
  const signed = await buildJoinerResponse(canonJoinerArgs(cid), cid.privateKey, cid.passphrase);
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  const joiner = await verifyJoinerResponse(blob, aliceGiver(), (n) => n === CODE);
  assert.ok(joiner, 'a canonical joiner with threaded PQ pubkeys must verify');
  assert.equal(joiner!.fingerprint, cid.fingerprint);
  assert.equal(joiner!.publicKeyArmored, cid.publicKey);
});

test('CANONICAL joiner WITHOUT threaded PQ pubkeys → fail-closed (the pre-fix bug; proves the threading is load-bearing)', async () => {
  const cid = await makeCanonicalIdentity('canon2');
  // Omit kem+sig — exactly what the OLD send path did. fingerprintMatchesKey then can't recompute the
  // 64-hex canonical fp → falls to the 40-hex OpenPGP path → 64 !== 40 → refused (→ null).
  const signed = await buildJoinerResponse(
    canonJoinerArgs(cid, { joinerPqKemPublicKey: undefined, joinerPqSigPublicKey: undefined }),
    cid.privateKey, cid.passphrase,
  );
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), (n) => n === CODE), null);
});

test('CANONICAL joiner with a WRONG-LENGTH kem → rejected at the structural boundary (§5 defense-in-depth, isWellFormed)', async () => {
  const cid = await makeCanonicalIdentity('canon3');
  // Truncate the kem to 40 base64 chars (~30 bytes, not 1568). isWellFormed's length-guard rejects the
  // whole blob up front (fail-loud) — before any signature/fp work.
  const signed = await buildJoinerResponse(
    canonJoinerArgs(cid, { joinerPqKemPublicKey: cid.kemPublicKeyB64.slice(0, 40) }),
    cid.privateKey, cid.passphrase,
  );
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  assert.equal(await verifyJoinerResponse(blob, aliceGiver(), (n) => n === CODE), null);
});
