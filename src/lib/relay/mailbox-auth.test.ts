// src/lib/relay/mailbox-auth.test.ts
// Owner-auth (signed poll/ack) round-trips + the adversarial cases that make it load-bearing:
// wrong-owner, stale-replay, tampered signature/fingerprint/key, poll-auth replayed as ack, and a
// tampered ack id-list. Uses REAL openpgp identities (same keygen as core.ts).
//
// Run: PATH=/home/alpha/.nvm/versions/node/v22.22.1/bin:$PATH npx tsx --test mailbox-auth.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import {
  deriveMailboxId,
  signMailboxPollRequest,
  signMailboxAckRequest,
  verifyMailboxPollAuth,
  verifyMailboxAckAuth,
  OWNER_AUTH_HEADER,
} from './mailbox-auth';

interface Identity {
  fingerprint: string;
  publicKey: string;
  privateKey: string;
  passphrase: string;
}

async function makeIdentity(name: string): Promise<Identity> {
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
  const fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  return { fingerprint, publicKey, privateKey, passphrase };
}

let owner: Identity;
let attacker: Identity;

before(async () => {
  owner = await makeIdentity('owner');
  attacker = await makeIdentity('attacker');
});

const NOW = 1_700_000_000_000;

function reqWith(headers: Record<string, string>): Request {
  return new Request('http://relay.test/api/relay/queue', { headers });
}

// Decode → mutate → re-encode the base64url(JSON) owner-auth header (bundle content is ASCII).
function mutateHeader(headers: Record<string, string>, fn: (b: Record<string, unknown>) => void): Record<string, string> {
  const val = headers[OWNER_AUTH_HEADER];
  const b = JSON.parse(atob(val.replace(/-/g, '+').replace(/_/g, '/')));
  fn(b);
  const enc = btoa(JSON.stringify(b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return { [OWNER_AUTH_HEADER]: enc };
}

async function ownerPollHeader(mailboxId: string, now = NOW): Promise<Record<string, string>> {
  return signMailboxPollRequest({
    mailboxId,
    fingerprint: owner.fingerprint,
    publicKeyArmored: owner.publicKey,
    privateKeyArmored: owner.privateKey,
    passphrase: owner.passphrase,
    now,
  });
}

test('poll round-trip — the owner can prove ownership of their own mailbox', async () => {
  const mid = deriveMailboxId(owner.fingerprint);
  const h = await ownerPollHeader(mid);
  assert.equal(await verifyMailboxPollAuth(reqWith(h), mid, NOW), true);
});

test('ack round-trip — the owner can authorize a delete of specific ids', async () => {
  const mid = deriveMailboxId(owner.fingerprint);
  const ids = ['env-1', 'env-2'];
  const h = await signMailboxAckRequest({
    mailboxId: mid,
    envelopeIds: ids,
    fingerprint: owner.fingerprint,
    publicKeyArmored: owner.publicKey,
    privateKeyArmored: owner.privateKey,
    passphrase: owner.passphrase,
    now: NOW,
  });
  assert.equal(await verifyMailboxAckAuth(reqWith(h), mid, ids, NOW), true);
});

test('no owner-auth header → not the owner (the bare-GET occupancy oracle is closed)', async () => {
  const mid = deriveMailboxId(owner.fingerprint);
  assert.equal(await verifyMailboxPollAuth(reqWith({}), mid, NOW), false);
});

test('wrong owner — an attacker cannot poll a mailbox they do not derive', async () => {
  const victimMid = deriveMailboxId(owner.fingerprint);
  // Attacker signs a valid request for the VICTIM's mailbox_id, presenting their OWN identity.
  const h = await signMailboxPollRequest({
    mailboxId: victimMid,
    fingerprint: attacker.fingerprint,
    publicKeyArmored: attacker.publicKey,
    privateKeyArmored: attacker.privateKey,
    passphrase: attacker.passphrase,
    now: NOW,
  });
  // deriveMailboxId(attacker.fp) !== victimMid → rejected (the mailbox binds to the owner's identity).
  assert.equal(await verifyMailboxPollAuth(reqWith(h), victimMid, NOW), false);
});

test('stale request → rejected once outside the freshness window (replay bound)', async () => {
  const mid = deriveMailboxId(owner.fingerprint);
  const h = await ownerPollHeader(mid, NOW);
  // Verify 10 minutes later (>> 60s default window).
  assert.equal(await verifyMailboxPollAuth(reqWith(h), mid, NOW + 10 * 60_000), false);
});

test('tampered signature → rejected', async () => {
  const mid = deriveMailboxId(owner.fingerprint);
  const h = await ownerPollHeader(mid);
  const tampered = mutateHeader(h, (b) => {
    const s = b.signature as string;
    // Flip a character in the middle of the armored signature.
    const i = Math.floor(s.length / 2);
    b.signature = s.slice(0, i) + (s[i] === 'A' ? 'B' : 'A') + s.slice(i + 1);
  });
  assert.equal(await verifyMailboxPollAuth(reqWith(tampered), mid, NOW), false);
});

test('tampered fingerprint (claim another identity, keep own key) → rejected', async () => {
  const mid = deriveMailboxId(owner.fingerprint);
  const h = await ownerPollHeader(mid);
  const tampered = mutateHeader(h, (b) => {
    b.fingerprint = attacker.fingerprint; // now fp no longer derives mid, and fp↔key breaks
  });
  assert.equal(await verifyMailboxPollAuth(reqWith(tampered), mid, NOW), false);
});

test('swapped public_key (attacker key under the owner fingerprint) → rejected (fp↔key binding)', async () => {
  const mid = deriveMailboxId(owner.fingerprint);
  const h = await ownerPollHeader(mid);
  const tampered = mutateHeader(h, (b) => {
    b.public_key = attacker.publicKey; // fp still owner's, but H(attacker.key) !== owner.fp
  });
  assert.equal(await verifyMailboxPollAuth(reqWith(tampered), mid, NOW), false);
});

test('poll-auth replayed as an ack → rejected (domain separation)', async () => {
  const mid = deriveMailboxId(owner.fingerprint);
  const h = await ownerPollHeader(mid); // signed under DOMAIN_MAILBOX_POLL
  // Present the poll header to the ACK verifier — different domain + input → signature fails.
  assert.equal(await verifyMailboxAckAuth(reqWith(h), mid, [], NOW), false);
});

test('ack with a tampered id-list → rejected (the signed input binds the exact ids)', async () => {
  const mid = deriveMailboxId(owner.fingerprint);
  const h = await signMailboxAckRequest({
    mailboxId: mid,
    envelopeIds: ['env-1'],
    fingerprint: owner.fingerprint,
    publicKeyArmored: owner.publicKey,
    privateKeyArmored: owner.privateKey,
    passphrase: owner.passphrase,
    now: NOW,
  });
  // Owner signed to delete [env-1]; an attacker widens it to also drop env-2 → signature mismatch.
  assert.equal(await verifyMailboxAckAuth(reqWith(h), mid, ['env-1', 'env-2'], NOW), false);
});

test('deriveMailboxId is deterministic and identity-specific', () => {
  assert.equal(deriveMailboxId(owner.fingerprint), deriveMailboxId(owner.fingerprint));
  assert.notEqual(deriveMailboxId(owner.fingerprint), deriveMailboxId(attacker.fingerprint));
  assert.match(deriveMailboxId(owner.fingerprint), /^mbx_[0-9a-f]{64}$/);
});
