// Full E2E for the wired send: buildContactUpdateDeposits (sender) → opaque relay blob → recipient
// decrypt (openpgpEnvelopeDecryptor) → verifyIncomingContactUpdate → the exact delta. Proves the send
// composer produces what the ALREADY-BUILT consume path accepts, per-recipient-encrypted + fail-closed.
// Run: npx tsx --test src/lib/sync/send-contact-update.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  buildContactUpdateDeposits as buildWithGate,
  sendContactUpdate as sendWithGate,
  type ContactUpdateOwner,
  type ContactUpdateRecipient,
} from './send-contact-update';

// The tests above the block section exercise everything except the recipient check, so they pass a check that admits everyone.
const ALLOW = () => true;
const buildContactUpdateDeposits = (c: Parameters<typeof buildWithGate>[0], o: Parameters<typeof buildWithGate>[1], r: Parameters<typeof buildWithGate>[2]) =>
  buildWithGate(c, o, r, ALLOW);
const sendContactUpdate = (c: Parameters<typeof sendWithGate>[0], o: Parameters<typeof sendWithGate>[1], r: Parameters<typeof sendWithGate>[2], opts: Parameters<typeof sendWithGate>[4]) =>
  sendWithGate(c, o, r, ALLOW, opts);
import { openpgpEnvelopeDecryptor, parseContactUpdateWire } from './contact-update-envelope';
import { mintHybridRecipient, openerFor, type HybridRecipient } from './hybrid-test-fixture';
import { verifyIncomingContactUpdate, type KnownContactIdentity } from '../trust/contact-update';
import { deriveMailboxId } from '../relay/mailbox-auth';


let owner: ContactUpdateOwner;
let bob: ContactUpdateRecipient, bobId: HybridRecipient;
let carol: ContactUpdateRecipient, carolId: HybridRecipient;
let ownerPub: string;

const asRecipient = (r: HybridRecipient): ContactUpdateRecipient => ({
  fingerprint: r.fingerprint, publicKeyArmored: r.publicKeyArmored, pqKemPublicKey: r.pqKemPublicKey,
});
// The recipient's consume-side opener (S14: hybrid first, classical fallback) for contact-updates.
const openFor = (r: HybridRecipient) =>
  openerFor(r, parseContactUpdateWire, openpgpEnvelopeDecryptor(r.privateKeyArmored, r.passphrase));

before(async () => {
  const o = await mintHybridRecipient();
  ownerPub = o.publicKeyArmored;
  owner = { fingerprint: o.fingerprint, epoch: 1, privateKeyArmored: o.privateKeyArmored, passphrase: o.passphrase };
  bobId = await mintHybridRecipient();
  bob = asRecipient(bobId);
  carolId = await mintHybridRecipient();
  carol = asRecipient(carolId);
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

  const decrypt = openFor(bobId);
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

  const forBob = await openFor(bobId)(deposits[0].blob);
  const forCarol = await openFor(carolId)(deposits[1].blob);
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
  const wrong = await openFor(carolId)(deposits[0].blob);
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

test('fail-closed (S14, HNDL): a recipient with NO pq_kem is SKIPPED as no-pq-kem — never sealed classically', async () => {
  const classicalOnly: ContactUpdateRecipient = { fingerprint: carol.fingerprint, publicKeyArmored: carol.publicKeyArmored };
  const { deposits, skipped } = await buildContactUpdateDeposits(
    { version: 1, delta: { display_name: 'Alice' } },
    owner,
    [bob, classicalOnly],
  );
  assert.equal(deposits.length, 1, 'only the pq_kem-bearing recipient gets a deposit');
  assert.equal(deposits[0].mailbox_id, deriveMailboxId(bob.fingerprint));
  assert.deepEqual(skipped, [{ fingerprint: carol.fingerprint, reason: 'no-pq-kem' }]);
});

test('S14: the deposit is a hybrid MailboxEnvelopePackage, not armored OpenPGP', async () => {
  const { deposits } = await buildContactUpdateDeposits({ version: 1, delta: { display_name: 'Alice' } }, owner, [bob]);
  assert.ok(!deposits[0].blob.includes('BEGIN PGP MESSAGE'), 'no classical armor on the wire');
  assert.equal(JSON.parse(deposits[0].blob).v, 1, 'raw-JSON hybrid package');
});

test('fail-closed: a malformed recipient key is SKIPPED (encrypt-failed), never aborts the batch', async () => {
  const badKey: ContactUpdateRecipient = { fingerprint: 'FPBAD', publicKeyArmored: 'not-a-pgp-key', pqKemPublicKey: bob.pqKemPublicKey };
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


// --- a blocked contact is never sent an update, whatever list the caller was handed ---
const CHANGE = { version: 1, delta: { display_name: 'Alice' } };

test('blocked: that recipient gets no deposit and is reported; the others are still sent', async () => {
  const { deposits, skipped } = await buildWithGate(CHANGE, owner, [bob, carol], (fp) => fp !== bob.fingerprint);
  assert.deepEqual(deposits.map((d) => d.mailbox_id), [deriveMailboxId(carol.fingerprint)]);
  assert.deepEqual(skipped, [{ fingerprint: bob.fingerprint, reason: 'blocked' }]);
});

test('blocked wins over every other skip reason, so nothing is even attempted for that recipient', async () => {
  const bad = { fingerprint: bob.fingerprint, publicKeyArmored: 'not a key', pqKemPublicKey: 'not a key' };
  const none = { fingerprint: carol.fingerprint, publicKeyArmored: '' };
  const { deposits, skipped } = await buildWithGate(CHANGE, owner, [bad, none], () => false);
  assert.equal(deposits.length, 0);
  assert.deepEqual(skipped, [{ fingerprint: bob.fingerprint, reason: 'blocked' }, { fingerprint: carol.fingerprint, reason: 'blocked' }]);
});

test('the check is asked once per recipient, with that recipient', async () => {
  const asked: string[] = [];
  await buildWithGate(CHANGE, owner, [bob, carol], (fp) => { asked.push(fp); return true; });
  assert.deepEqual(asked, [bob.fingerprint, carol.fingerprint]);
});

for (const missing of [undefined, null, 'yes', {}, true]) {
  test(`no usable check (${String(missing)}): refuses outright, and sends nothing`, async () => {
    await assert.rejects(buildWithGate(CHANGE, owner, [bob], missing as never), /recipient check/);
    const posted: unknown[] = [];
    const fetchImpl = mockFetch((_u, body) => { posted.push(body); return { ok: true, status: 200 }; });
    await assert.rejects(sendWithGate(CHANGE, owner, [bob], missing as never, { fetchImpl }), /recipient check/);
    assert.equal(posted.length, 0);
  });
}

test('a check that throws sends nothing to anyone, including recipients it had already passed', async () => {
  const posted: unknown[] = [];
  const fetchImpl = mockFetch((_u, body) => { posted.push(body); return { ok: true, status: 200 }; });
  let n = 0;
  const boom = () => { if (++n === 2) throw new Error('store went away'); return true; };
  await assert.rejects(sendWithGate(CHANGE, owner, [bob, carol], boom, { fetchImpl }));
  assert.equal(posted.length, 0);
});

test('sendContactUpdate: no POST for a blocked recipient; the result says so', async () => {
  const posted: Array<{ mailbox_id: string }> = [];
  const fetchImpl = mockFetch((_u, body) => { posted.push(body); return { ok: true, status: 200 }; });
  const r = await sendWithGate(CHANGE, owner, [bob, carol], (fp) => fp === carol.fingerprint, { fetchImpl });
  assert.deepEqual(posted.map((b) => b.mailbox_id), [deriveMailboxId(carol.fingerprint)]);
  assert.deepEqual(r.deposited, [deriveMailboxId(carol.fingerprint)]);
  assert.deepEqual(r.skipped, [{ fingerprint: bob.fingerprint, reason: 'blocked' }]);
});
