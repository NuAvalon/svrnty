// e2e/fixtures/deposit-contact-update.ts
// Beat-4 SEND simulation for the demo-arc e2e. Constructs a GENUINE SignedContactUpdate
// (Ed25519 over contactUpdateSigningInput, sender-signed) and E2E-encrypts it to the recipient (openpgp),
// then deposits the opaque blob to the return-channel mailbox. This drives the recipient's consume caller
// through the SAME decrypt → verify → whitelist(I-2) → apply it runs in production — so beat-4 honestly
// exercises the CONSUME-side security (the sender's signature + the recipient's in-book whitelist), and
// only that. It is NOT a raw/stub POST; the raw variant below exists so the test can also assert the
// honest NEGATIVE path (a corrupt/unsigned blob → verify rejects → NO repaint).
//
// RELAY COHERENCE (why this and not the satellite /send): the send + consume must share ONE relay. The
// consume caller polls /api/relay/queue (the Next.js in-memory mailbox; Bob + Alice are two contexts of
// the same app instance → shared server-side store), so the deposit MUST hit /api/relay/envelope. The
// satellite /send is a SEPARATE store — a deposit there never reaches the consume. The deposit is
// identity-blind BY DESIGN (custody is receiver-side, anti-sender-oracle I-1/I-4); the security that
// matters is the inner signed update — which is why this helper builds a real one.

import type { APIRequestContext, Page } from '@playwright/test';
import { generateKey, readKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '../../src/lib/crypto/pq';
import { mintCanonicalFingerprint } from '../../src/lib/identity/fingerprint';
import { signWithEnvelope } from '../../src/lib/crypto/sign-envelope';
import {
  DOMAIN_CONTACT_UPDATE,
  contactUpdateSigningInput,
  type ContactUpdateEnvelope,
} from '../../src/lib/format/envelope';
import type { SignedContactUpdate } from '../../src/lib/trust/contact-update';
import { encryptContactUpdateTo } from '../../src/lib/sync/contact-update-envelope';
import { deriveMailboxId } from '../../src/lib/relay/mailbox-auth';

export interface E2EIdentity {
  fingerprint: string; // 64-hex CANONICAL = SHA256(sign‖enc‖kem‖sig) — §5 canonical identity
  publicKey: string; // armored
  privateKey: string; // armored
  passphrase: string;
  kemPublicKeyB64: string; // base64(ML-KEM-1024 pubkey) — the canonical fp-match overlay
  sigPublicKeyB64: string; // base64(ML-DSA-87 pubkey)
}

/**
 * Generate a real §5 CANONICAL identity node-side: an openpgp (Ed25519) classical key + a Cat-5 PQ bundle,
 * with the durable 64-hex canonical fingerprint = SHA256(sign‖enc‖kem‖sig). Post-res1-gate the consume
 * verifies fp↔key via the canonical branch (the 40-hex OpenPGP fall-through is removed), so the fixture's
 * synthetic sender MUST be canonical + carry its PQ pubkeys. Mirrors core.ts mint + the makeCanonicalIdentity
 * unit fixture (mailbox-auth.test.ts).
 */
export async function makeE2EIdentity(name: string): Promise<E2EIdentity> {
  const passphrase = `e2e-${name}-pass`;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart — 'ed25519' is valid at runtime (mirrors core.ts + the unit fixture).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@e2e.test` }],
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
  };
}

export interface ContactUpdateFields {
  epoch?: number; // default 0 — a field-change rides the receiver's KNOWN epoch; only a key rotation bumps
  //             it (epoch-ahead is rejected as needs-lineage until the receiver catches up). Set this
  //             ONLY if the recipient already knows the sender at a higher epoch.
  version?: number; // default 1 (> a fresh contact's 0 floor → applies)
  updatedAt?: string; // default now
  changedFields: string[]; // e.g. ['display_name'] — must be an allowlisted subset
  delta: Record<string, unknown>; // only the changed fields, e.g. { display_name: 'Bob (NEW name)' }
}

/**
 * Build the exact opaque blob that would ride sender → recipient: the sender signs a contact.update
 * envelope with its identity key, then encrypts the SignedContactUpdate to the recipient's public key.
 * Exposed on its own so a unit/round-trip check can decrypt+verify it without a running app.
 */
export async function buildEncryptedUpdate(
  sender: E2EIdentity,
  recipientPublicKeyArmored: string,
  fields: ContactUpdateFields,
): Promise<string> {
  const env: ContactUpdateEnvelope = {
    fingerprint: sender.fingerprint,
    epoch: fields.epoch ?? 0,
    version: fields.version ?? 1,
    updated_at: fields.updatedAt ?? new Date().toISOString(),
    changed_fields: fields.changedFields,
    delta: fields.delta,
  };
  const signature = await signWithEnvelope(
    DOMAIN_CONTACT_UPDATE,
    contactUpdateSigningInput(env),
    sender.privateKey,
    sender.passphrase,
  );
  const signed: SignedContactUpdate = { envelope: env, signature };
  return encryptContactUpdateTo(signed, recipientPublicKeyArmored);
}

/**
 * Simulate the sender's SEND: build a real signed + encrypted contact.update and deposit it to the
 * recipient's mailbox. The recipient's consume caller then genuinely verifies + applies it → beat-4
 * flips the row data-live="push". Returns the deposit HTTP status (200 = queued).
 */
export async function depositContactUpdate(
  request: APIRequestContext,
  args: {
    baseURL?: string;
    sender: E2EIdentity;
    recipientFingerprint: string;
    recipientPublicKeyArmored: string;
    fields: ContactUpdateFields;
  },
): Promise<number> {
  const blob = await buildEncryptedUpdate(args.sender, args.recipientPublicKeyArmored, args.fields);
  const res = await request.post(`${args.baseURL ?? ''}/api/relay/envelope`, {
    data: { mailbox_id: deriveMailboxId(args.recipientFingerprint), blob },
  });
  return res.status();
}

/**
 * Deposit an arbitrary (unsigned / corrupt) blob — for the HONEST NEGATIVE path. The deposit itself
 * still 200s (the relay is blind by design), but the recipient's consume decrypt/verify rejects it →
 * NO repaint (no data-live="push"), silently (I-1). Asserts "we don't repaint on an unauthorized update."
 */
export async function depositRawBlob(
  request: APIRequestContext,
  args: { baseURL?: string; recipientFingerprint: string; blob: string },
): Promise<number> {
  const res = await request.post(`${args.baseURL ?? ''}/api/relay/envelope`, {
    data: { mailbox_id: deriveMailboxId(args.recipientFingerprint), blob: args.blob },
  });
  return res.status();
}

/**
 * Put a genesis'd Alice into a beat-4-ready state: extract her fingerprint + armored public key from the
 * plaintext `identities` store, and seed a fresh Bob (makeE2EIdentity) into her `contacts` book at the
 * default epoch so the consume-side I-2 whitelist passes with no epoch-ahead reject. Returns the recipient
 * keys (for depositContactUpdate) + Bob (the sender).
 *
 * ⚠ PRECONDITION + NO RELOAD: call AFTER Alice's genesis, and do NOT reload the page afterwards. Genesis
 * stores Alice's key ENCRYPTED at rest and unlocks the session only IN MEMORY (lost on refresh); a reload
 * would relock her, loadKey would fail, and the poll would no-op. The genesis session stays unlocked and
 * the poll is already running (ContactManagement mounted on the Contacts tab), so it picks up the deposit
 * within its interval — assert data-live="push" with a generous timeout (~10s).
 *
 * Seeds via raw IndexedDB (self-contained — no app code / no client-store window access). Only the plaintext
 * `identities` + `contacts` stores are touched; the encrypted `keys` store is left to genesis.
 */
export async function seedAliceWithBob(
  page: Page,
): Promise<{ aliceFp: string; aliceArmoredPub: string; bob: E2EIdentity }> {
  const bob = await makeE2EIdentity('bob');
  const alice = await page.evaluate(
    async ({ bobFp, bobPub, bobKem, bobSig }: { bobFp: string; bobPub: string; bobKem: string; bobSig: string }) => {
      const openDb = () =>
        new Promise<IDBDatabase>((resolve, reject) => {
          const r = indexedDB.open('svrnty'); // no version → open the app's existing DB as-is
          r.onsuccess = () => resolve(r.result);
          r.onerror = () => reject(r.error);
        });
      const db = await openDb();
      const identities = await new Promise<Array<{ data?: { identity?: { fingerprint?: string; public_key?: string } } }>>(
        (resolve, reject) => {
          const rq = db.transaction('identities', 'readonly').objectStore('identities').getAll();
          rq.onsuccess = () => resolve(rq.result);
          rq.onerror = () => reject(rq.error);
        },
      );
      const rec = identities.find((r) => r?.data?.identity?.fingerprint && r?.data?.identity?.public_key);
      if (!rec) {
        db.close();
        throw new Error('seedAliceWithBob: no genesis identity in IndexedDB — call AFTER Alice genesis');
      }
      const aliceFp = rec.data!.identity!.fingerprint!;
      const aliceArmoredPub = rec.data!.identity!.public_key!;
      await new Promise<void>((resolve, reject) => {
        const tx = db.transaction('contacts', 'readwrite');
        tx.objectStore('contacts').put({
          id: `e2e-bob-${bobFp.slice(0, 12)}`,
          fingerprint: bobFp,
          name: 'Bob',
          email: 'bob@e2e.test',
          public_key: bobPub,
          // §5 CRUX: Bob's canonical PQ pubkeys on his STORED contact record — the consume's
          // fingerprintMatchesKey (via updateContact) reads pq from HERE (next.pq_kem/sig), NOT the
          // envelope, so post-res1-gate the canonical branch matches Bob's 64-hex fp (beat-4 stays green).
          pq_kem_public_key: bobKem,
          pq_sig_public_key: bobSig,
          trust_level: 'verified',
          added_at: new Date().toISOString(),
          owner_fingerprint: aliceFp,
          epoch: 0,
          version: 0,
        });
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
      db.close();
      return { aliceFp, aliceArmoredPub };
    },
    { bobFp: bob.fingerprint, bobPub: bob.publicKey, bobKem: bob.kemPublicKeyB64, bobSig: bob.sigPublicKeyB64 },
  );
  return { aliceFp: alice.aliceFp, aliceArmoredPub: alice.aliceArmoredPub, bob };
}
