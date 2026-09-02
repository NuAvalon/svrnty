// Full E2E for the wired send: buildContactUpdateDeposits (sender) → opaque relay blob → recipient
// decrypt (openpgpEnvelopeDecryptor) → verifyIncomingContactUpdate → the exact delta. Proves the send
// composer produces what the ALREADY-BUILT consume path accepts, per-recipient-encrypted + fail-closed.
// Run: npx tsx --test src/lib/sync/send-contact-update.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import {
  buildContactUpdateDeposits,
  sendContactUpdate,
  type ContactUpdateOwner,
  type ContactUpdateRecipient,
} from './send-contact-update';
import { openpgpEnvelopeDecryptor } from './contact-update-envelope';
import { verifyIncomingContactUpdate, type KnownContactIdentity } from '../trust/contact-update';
import { deriveMailboxId } from '../relay/mailbox-auth';

const ownerPass = 'owner-pass-0';
const bobPass = 'bob-pass-1';
const carolPass = 'carol-pass-2';

let owner: ContactUpdateOwner;
let bob: ContactUpdateRecipient, bobPriv: string;
let carol: ContactUpdateRecipient, carolPriv: string;
let ownerPub: string;

async function mkIdentity(name: string, pass: string) {
  const { privateKey, publicKey } = await generateKey({
    type: 'curve25519',
    userIDs: [{ name, email: `${name}@example.test` }],
    passphrase: pass,
    format: 'armored',
  });
  const fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  return { privateKey, publicKey, fingerprint };
}

before(async () => {
  const o = await mkIdentity('Alice', ownerPass);
  ownerPub = o.publicKey;
  owner = { fingerprint: o.fingerprint, epoch: 1, privateKeyArmored: o.privateKey, passphrase: ownerPass };
  const b = await mkIdentity('Bob', bobPass);
  bob = { fingerprint: b.fingerprint, publicKeyArmored: b.publicKey };
  bobPriv = b.privateKey;
  const c = await mkIdentity('Carol', carolPass);
  carol = { fingerprint: c.fingerprint, publicKeyArmored: c.publicKey };
  carolPriv = c.privateKey;
});

// The recipient's stored view of the owner (their card): fingerprint + owner pubkey, last-seen v0.
function ownerAsKnown(o: Partial<KnownContactIdentity> = {}): KnownContactIdentity {
  return { fingerprint: owner.fingerprint, epoch: 1, version: 0, classicalPublicKeyArmored: ownerPub, ...o };
}

test('E2E: a deposit decrypts + verifies to the exact delta at the recipient', async () => {
  const { deposits, skipped } = await buildContactUpdateDeposits(
    { version: 1, delta: { display_name: 'Alice Q.' }, updated_at: '2026-09-02T00:00:00Z' },
    owner,
    [bob],
  );
  assert.equal(skipped.length, 0);
  assert.equal(deposits.length, 1);
  assert.equal(deposits[0].mailbox_id, deriveMailboxId(bob.fingerprint), 'addressed to bob’s mailbox');

  const decrypt = openpgpEnvelopeDecryptor(bobPriv, bobPass);
  const signed = await decrypt(deposits[0].blob);
  assert.ok(signed, 'bob can decrypt the blob addressed to him');
  const v = await verifyIncomingContactUpdate(signed!, ownerAsKnown());
  assert.equal(v.version, 1);
  assert.deepEqual(v.delta, { display_name: 'Alice Q.' });
});

test('sign-once, encrypt-per-recipient: two recipients get the SAME signature, DIFFERENT blobs', async () => {
  const { deposits, skipped } = await buildContactUpdateDeposits(
    { version: 2, delta: { emails: ['alice@x.test'] } },
    owner,
    [bob, carol],
  );
  assert.equal(skipped.length, 0);
  assert.equal(deposits.length, 2);
  // Distinct mailboxes, distinct ciphertext (per-recipient encryption).
  assert.notEqual(deposits[0].mailbox_id, deposits[1].mailbox_id);
  assert.notEqual(deposits[0].blob, deposits[1].blob);

  const forBob = await openpgpEnvelopeDecryptor(bobPriv, bobPass)(deposits[0].blob);
  const forCarol = await openpgpEnvelopeDecryptor(carolPriv, carolPass)(deposits[1].blob);
  assert.ok(forBob && forCarol);
  // ONE signature over the envelope — identical for both recipients.
  assert.deepEqual(forBob!.signature, forCarol!.signature);
  assert.deepEqual(forBob!.envelope, forCarol!.envelope);
});

test('confidentiality: Carol CANNOT decrypt the blob addressed to Bob', async () => {
  const { deposits } = await buildContactUpdateDeposits(
    { version: 1, delta: { note: 'secret' } },
    owner,
    [bob],
  );
  const wrong = await openpgpEnvelopeDecryptor(carolPriv, carolPass)(deposits[0].blob);
  assert.equal(wrong, null, 'a non-recipient private key returns null (never the plaintext)');
});

test('fail-closed: a recipient with no public key is SKIPPED (reported), others still sent — no downgrade', async () => {
  const noKey: ContactUpdateRecipient = { fingerprint: 'FPNOKEY', publicKeyArmored: '' };
  const { deposits, skipped } = await buildContactUpdateDeposits(
    { version: 1, delta: { display_name: 'Alice' } },
    owner,
    [bob, noKey],
  );
  assert.equal(deposits.length, 1, 'bob still gets it');
  assert.equal(deposits[0].mailbox_id, deriveMailboxId(bob.fingerprint));
  assert.equal(skipped.length, 1);
  assert.deepEqual(skipped[0], { fingerprint: 'FPNOKEY', reason: 'no-public-key' });
});

test('fail-closed: a malformed recipient key is SKIPPED (encrypt-failed), never aborts the batch', async () => {
  const badKey: ContactUpdateRecipient = { fingerprint: 'FPBAD', publicKeyArmored: 'not-a-pgp-key' };
  const { deposits, skipped } = await buildContactUpdateDeposits(
    { version: 1, delta: { display_name: 'Alice' } },
    owner,
    [badKey, bob],
  );
  assert.equal(deposits.length, 1, 'bob still gets it despite the bad key earlier in the list');
  assert.equal(skipped.length, 1);
  assert.equal(skipped[0].fingerprint, 'FPBAD');
  assert.equal(skipped[0].reason, 'encrypt-failed');
});

test('unsendable change throws before ANY deposit (field firewall — whole-update failure)', async () => {
  await assert.rejects(
    buildContactUpdateDeposits({ version: 1, delta: { location: { lat: 1 } } }, owner, [bob]),
    /field-not-allowed/,
  );
});

// ── sendContactUpdate: the POST-loop (mock fetch) ───────────────────────────────
function mockFetch(handler: (url: string, body: { mailbox_id: string; blob: string }) => { ok: boolean; status: number }): typeof fetch {
  return (async (url: unknown, init: { body: string }) => {
    const r = handler(String(url), JSON.parse(init.body));
    return { ok: r.ok, status: r.status, json: async () => ({ status: 'queued' }) } as Response;
  }) as unknown as typeof fetch;
}

test('sendContactUpdate: all deposits POST OK → deposited=all, POST shape {mailbox_id,blob} to /api/relay/envelope', async () => {
  const seen: Array<{ url: string; body: { mailbox_id: string; blob: string } }> = [];
  const fetchImpl = mockFetch((url, body) => { seen.push({ url, body }); return { ok: true, status: 200 }; });
  const r = await sendContactUpdate({ version: 1, delta: { display_name: 'A' } }, owner, [bob, carol], { fetchImpl });
  assert.deepEqual(r.deposited.sort(), [deriveMailboxId(bob.fingerprint), deriveMailboxId(carol.fingerprint)].sort());
  assert.equal(r.failed.length, 0);
  assert.equal(r.skipped.length, 0);
  assert.ok(seen.every((s) => s.url.endsWith('/api/relay/envelope')));
  assert.ok(seen.every((s) => typeof s.body.mailbox_id === 'string' && typeof s.body.blob === 'string'));
});

test('sendContactUpdate: a relay 429 → that deposit in failed, others still deposited', async () => {
  const bobMbx = deriveMailboxId(bob.fingerprint);
  const fetchImpl = mockFetch((_u, body) => (body.mailbox_id === bobMbx ? { ok: false, status: 429 } : { ok: true, status: 200 }));
  const r = await sendContactUpdate({ version: 1, delta: { display_name: 'A' } }, owner, [bob, carol], { fetchImpl });
  assert.deepEqual(r.failed, [{ mailbox_id: bobMbx, status: 429 }]);
  assert.deepEqual(r.deposited, [deriveMailboxId(carol.fingerprint)]);
});

test('sendContactUpdate: a network throw → network-error in failed, batch continues', async () => {
  const bobMbx = deriveMailboxId(bob.fingerprint);
  const fetchImpl = (async (_u: unknown, init: { body: string }) => {
    if (JSON.parse(init.body).mailbox_id === bobMbx) throw new Error('net down');
    return { ok: true, status: 200, json: async () => ({}) } as Response;
  }) as unknown as typeof fetch;
  const r = await sendContactUpdate({ version: 1, delta: { display_name: 'A' } }, owner, [bob, carol], { fetchImpl });
  assert.deepEqual(r.failed, [{ mailbox_id: bobMbx, status: 'network-error' }]);
  assert.equal(r.deposited.length, 1);
});

test('sendContactUpdate: a no-key recipient is skipped (never POSTed), others sent', async () => {
  const fetchImpl = mockFetch(() => ({ ok: true, status: 200 }));
  const r = await sendContactUpdate(
    { version: 1, delta: { display_name: 'A' } },
    owner,
    [bob, { fingerprint: 'FPNOKEY', publicKeyArmored: '' }],
    { fetchImpl },
  );
  assert.equal(r.deposited.length, 1);
  assert.deepEqual(r.skipped, [{ fingerprint: 'FPNOKEY', reason: 'no-public-key' }]);
});
