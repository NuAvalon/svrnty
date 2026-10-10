// e2e/fixtures/return-channel-owner.ts
// A-half owner-auth fixture for the return-channel gate. Generates ONE real
// openpgp identity and derives its mailbox_id, so the owner-dependent functional tests (A1–A4) can
// prove deposit → owner-poll → ack-delete against real owner-auth. Two distinct getters because poll
// and ack are domain-separated: an ack MUST be signed with signMailboxAckRequest (it binds the exact
// envelope_ids) — reusing the poll header for an ack fails the ack-domain check by design.

import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '../../src/lib/crypto/pq';
import { mintCanonicalFingerprint } from '../../src/lib/identity/fingerprint';
import { deriveMailboxId, signMailboxPollRequest, signMailboxAckRequest } from '../../src/lib/relay/mailbox-auth';

interface Owner {
  fingerprint: string; // 64-hex CANONICAL (SHA256(sign‖enc‖kem‖sig))
  publicKey: string;
  privateKey: string;
  passphrase: string;
  mailboxId: string;
  kemPublicKeyB64: string; // base64(ML-KEM-1024 pubkey) — owner-auth canonical fp overlay
  sigPublicKeyB64: string; // base64(ML-DSA-87 pubkey)
}

let cached: Promise<Owner> | null = null;

function owner(): Promise<Owner> {
  if (!cached) {
    cached = (async () => {
      const passphrase = 'return-channel-owner-fixture';
      const { privateKey, publicKey } = await generateKey({
        type: 'ecc',
        // @ts-expect-error openpgp v6 curve-type wart — 'ed25519' is valid at runtime (see core.ts).
        curve: 'ed25519',
        userIDs: [{ name: 'rc-owner', email: 'owner@rc.test' }],
        passphrase,
        format: 'armored',
      });
      // §5 canonical owner: openpgp classical key + Cat-5 PQ bundle → 64-hex canonical fingerprint.
      // Post-res1-gate the mailbox owner-auth verifies fp↔key via the canonical branch, so the owner
      // must be canonical + thread its PQ pubkeys into the poll/ack owner-auth bundle (below).
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
        mailboxId: deriveMailboxId(fingerprint),
        kemPublicKeyB64: uint8ToBase64(pq.kem.publicKey),
        sigPublicKeyB64: uint8ToBase64(pq.signing.publicKey),
      };
    })();
  }
  return cached;
}

/** The owner's real mailbox_id (deriveMailboxId(fingerprint)) — NOT the arbitrary mailboxIdFor(). */
export async function ownerMailboxId(): Promise<string> {
  return (await owner()).mailboxId;
}

/** Signed owner-auth header for a POLL of the owner's mailbox. */
export async function pollHeaders(): Promise<Record<string, string>> {
  const o = await owner();
  return signMailboxPollRequest({
    mailboxId: o.mailboxId,
    fingerprint: o.fingerprint,
    publicKeyArmored: o.publicKey,
    privateKeyArmored: o.privateKey,
    passphrase: o.passphrase,
    kemPublicKey: o.kemPublicKeyB64,
    sigPublicKey: o.sigPublicKeyB64,
    now: Date.now(),
  });
}

/** Signed owner-auth header for an ACK-delete of `envelopeIds` (binds the exact ids). */
export async function ackHeaders(envelopeIds: string[]): Promise<Record<string, string>> {
  const o = await owner();
  return signMailboxAckRequest({
    mailboxId: o.mailboxId,
    envelopeIds,
    fingerprint: o.fingerprint,
    publicKeyArmored: o.publicKey,
    privateKeyArmored: o.privateKey,
    passphrase: o.passphrase,
    kemPublicKey: o.kemPublicKeyB64,
    sigPublicKey: o.sigPublicKeyB64,
    now: Date.now(),
  });
}
