// R1 KNOWN handshake — END-TO-END through the REAL mailbox transport (not mocks). Proves the joiner-
// response crypto composes with depositEnvelope/pollMailbox/deriveMailboxId, AND documents the consume
// ROUTING requirement for the wiring: a joiner-response blob is E2E-encrypted to the giver with
// the SAME openpgp the contact-update path uses, so the contact-update decryptor DECRYPTS it (returns
// NON-null) — the discriminator between the two return-channel message types therefore CANNOT be "which
// decrypt returns null"; it MUST be "which VERIFY succeeds". This test pins that so the wiring routes
// by verify, not by decrypt.
// Run: npx tsx --test src/lib/trust/joiner-response.e2e.test.ts
process.env.RELAY_DB_PATH = ':memory:'; // OPT-2: in-memory SQLite for tests (runner sets no NODE_ENV)
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { buildJoinerResponse, encryptJoinerResponseTo, verifyJoinerResponse } from './joiner-response';
import { depositEnvelope, pollMailbox, ackDelete } from '../relay/mailbox-store';
import { deriveMailboxId } from '../relay/mailbox-auth';
import { openpgpEnvelopeDecryptor } from '../sync/contact-update-envelope';
import { mailboxConfig } from '../relay/mailbox-config';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from '../identity/fingerprint';

const pass = 'test-passphrase-e2e';
const CODE = 'A7K9QX';
const NOW = 1_756_800_000_000; // fixed ms — deposit/poll take `now` explicitly (deterministic; no Date.now)

// §5 CANONICAL identities: openpgp (sign+enc) + ML-KEM/ML-DSA pubkeys → a 64-hex SHA256(sign‖enc‖kem‖sig)
// fingerprint (NOT the 40-hex OpenPGP fp). Post-res1 fingerprintMatchesKey is canonical-only, so the
// joiner MUST be canonical and thread its PQ pubkeys for verifyJoinerResponse's Invariant-1 step to pass.
// Mirrors makeCanonicalIdentity in joiner-response.test.ts.
interface CanonicalIdentity {
  fingerprint: string;
  publicKey: string;
  privateKey: string;
  kemPublicKeyB64: string;
  sigPublicKeyB64: string;
}
async function makeCanonicalIdentity(name: string, email: string): Promise<CanonicalIdentity> {
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same as src/lib/identity/core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email }],
    passphrase: pass,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey,
  });
  return {
    fingerprint, publicKey, privateKey,
    kemPublicKeyB64: uint8ToBase64(pq.kem.publicKey),
    sigPublicKeyB64: uint8ToBase64(pq.signing.publicKey),
  };
}

let alicePriv: string, alicePub: string, aliceFp: string; // GIVER (mailbox owner)
let bobPriv: string, bobPub: string, bobFp: string;        // JOINER
let bobKemB64: string, bobSigB64: string;                  // JOINER's PQ pubkeys (canonical-fp binding)

before(async () => {
  ({ privateKey: alicePriv, publicKey: alicePub, fingerprint: aliceFp } = await makeCanonicalIdentity('Alice', 'alice@example.test'));
  ({ privateKey: bobPriv, publicKey: bobPub, fingerprint: bobFp, kemPublicKeyB64: bobKemB64, sigPublicKeyB64: bobSigB64 } =
    await makeCanonicalIdentity('Bob', 'bob@example.test'));
});

async function bobDepositsToAlice(): Promise<{ mailboxId: string; blob: string }> {
  const signed = await buildJoinerResponse(
    {
      joinerFp: bobFp, joinerEpoch: 1, joinerPubKeyArmored: bobPub, joinerName: 'Bob', giverFp: aliceFp, inviteNonce: CODE, ts: '2026-09-02T00:00:00Z',
      joinerPqKemPublicKey: bobKemB64, joinerPqSigPublicKey: bobSigB64,
    },
    bobPriv, pass,
  );
  const blob = await encryptJoinerResponseTo(signed, alicePub);
  const mailboxId = deriveMailboxId(aliceFp);
  const r = depositEnvelope(mailboxId, blob, NOW);
  assert.equal(r.ok, true, 'deposit must succeed (blob within size cap, mailbox not at cap)');
  return { mailboxId, blob };
}

// ── The full path: build → encrypt → deposit → poll → verify → KNOWN ──────────────
test('E2E: a joiner-response survives the real mailbox and Alice verifies it to a PendingJoiner', async () => {
  const { mailboxId, blob } = await bobDepositsToAlice();

  const polled = pollMailbox(mailboxId, NOW);
  const mine = polled.find((e) => e.blob === blob);
  assert.ok(mine, 'the deposited blob must be pollable by the owner');
  assert.equal(mine!.blob, blob, 'blob must survive the transport byte-identical (no truncation/re-encode)');

  const joiner = await verifyJoinerResponse(
    mine!.blob,
    { fingerprint: aliceFp, privateKeyArmored: alicePriv, passphrase: pass },
    (n) => n === CODE,
  );
  assert.ok(joiner, 'the polled blob must verify to a PendingJoiner');
  assert.equal(joiner!.fingerprint, bobFp);
  assert.equal(joiner!.inviteNonce, CODE);

  ackDelete(mailboxId, polled.map((e) => e.envelope_id), NOW); // hygiene: clean the shared store
});

// ── The blob is well within the mailbox payload cap (no 413 in practice) ───────────
test('E2E: a joiner-response blob is well under the mailbox payload cap', async () => {
  const { mailboxId, blob } = await bobDepositsToAlice();
  assert.ok(blob.length < mailboxConfig().maxPayloadBytes, `blob ${blob.length}B must be < cap ${mailboxConfig().maxPayloadBytes}B`);
  ackDelete(mailboxId, pollMailbox(mailboxId, NOW).map((e) => e.envelope_id), NOW);
});

// ── THE ROUTING SEAM (for the consume wiring) ─────────────────────────────────
test('SEAM: the contact-update decryptor DECRYPTS a joiner-response (non-null) — so route by VERIFY, not by decrypt', async () => {
  const { mailboxId, blob } = await bobDepositsToAlice();
  const polled = pollMailbox(mailboxId, NOW);
  const mine = polled.find((e) => e.blob === blob)!;

  // The contact-update decryptor is bound to Alice's key. A joiner-response is encrypted to the SAME
  // key with the SAME openpgp, so it decrypts + JSON-parses fine → returns a NON-null object. It is NOT
  // a "decrypt returned null" case. This is the crux for the wiring:
  const asContactUpdate = await openpgpEnvelopeDecryptor(alicePriv, pass)(mine.blob);
  assert.notEqual(asContactUpdate, null, 'contact-update decryptor returns NON-null for a joiner-response (same E2E envelope)');

  // …but the decrypted object is a joiner-response: it has NO envelope.fingerprint (it has
  // joiner_fingerprint), so the contact-update consumeOne path drops it on its `envelope.fingerprint`
  // string check → the joiner would be LOST if routing keyed on "decrypt !== null ⇒ contact-update".
  assert.equal((asContactUpdate as { envelope?: { fingerprint?: unknown } })?.envelope?.fingerprint, undefined,
    'a joiner-response has no envelope.fingerprint → contact-update consume drops it (terminal)');

  // The CORRECT discriminator: verifyJoinerResponse returns a PendingJoiner for this blob (verify
  // succeeds), while verifyIncomingContactUpdate would reject it. Route the return channel by WHICH
  // VERIFY SUCCEEDS on the (already-decrypted) blob, not by which decrypt returns non-null.
  const joiner = await verifyJoinerResponse(mine.blob, { fingerprint: aliceFp, privateKeyArmored: alicePriv, passphrase: pass }, () => true);
  assert.ok(joiner, 'verifyJoinerResponse is the correct discriminator — it accepts the joiner-response');

  ackDelete(mailboxId, polled.map((e) => e.envelope_id), NOW);
});

// ── Ack-delete drains the mailbox (transport hygiene) ──────────────────────────────
test('E2E: ack-delete removes the consumed envelope (owner drains after apply)', async () => {
  const { mailboxId } = await bobDepositsToAlice();
  const before = pollMailbox(mailboxId, NOW);
  assert.ok(before.length >= 1, 'mailbox has the deposited envelope');
  const removed = ackDelete(mailboxId, before.map((e) => e.envelope_id), NOW);
  assert.ok(removed >= 1, 'ack-delete removes it');
  assert.equal(pollMailbox(mailboxId, NOW).length, 0, 'mailbox drains to empty');
});
