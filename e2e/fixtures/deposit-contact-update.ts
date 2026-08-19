// e2e/fixtures/deposit-contact-update.ts
// Beat-4 SEND simulation for the demo-arc e2e (Athena). Constructs a GENUINE SignedContactUpdate
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

import type { APIRequestContext } from '@playwright/test';
import { generateKey, readKey } from 'openpgp';
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
  fingerprint: string;
  publicKey: string; // armored
  privateKey: string; // armored
  passphrase: string;
}

/** Generate a real openpgp (Ed25519) identity node-side — deterministic keys the test fully controls. */
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
  const fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  return { fingerprint, publicKey, privateKey, passphrase };
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
