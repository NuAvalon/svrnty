// src/lib/relay/mailbox-auth.test.ts
// Owner-auth (signed poll/ack) round-trips + the adversarial cases that make it load-bearing:
// wrong-owner, stale-replay, tampered signature/fingerprint/key, poll-auth replayed as ack, and a
// tampered ack id-list. Uses REAL openpgp identities (same keygen as core.ts).
//
// Run: npx tsx --test mailbox-auth.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { mintCanonicalFingerprint } from '@/lib/identity/fingerprint';
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

interface CanonicalIdentity extends Identity {
  kemPublicKeyB64: string;
  sigPublicKeyB64: string;
}

// A §5 CANONICAL identity: openpgp (sign+enc) + ML-KEM/ML-DSA pubkeys → a 64-hex
// SHA256(sign‖enc‖kem‖sig) fingerprint (NOT the 40-hex OpenPGP fp). Mirrors genesis
// (browser-identity.ts / core.ts): generate → pqBundle → mintCanonicalFingerprint.
async function makeCanonicalIdentity(name: string): Promise<CanonicalIdentity> {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same as makeIdentity).
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
  };
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

test('CANONICAL-ONLY GATE (res1): a classical 40-hex owner does NOT prove ownership — the OpenPGP fall-through is removed (the canonical poll happy-path is the "CANONICAL poll round-trip" test below)', async () => {
  // owner is a classical (40-hex OpenPGP) identity. Post-res1 verifyMailboxPollAuth's fingerprintMatchesKey
  // is canonical-only: a 40-hex claimed fp with no PQ legs → false. Inverts the pre-res1 "classical binds".
  const mid = deriveMailboxId(owner.fingerprint);
  const h = await ownerPollHeader(mid);
  assert.equal(await verifyMailboxPollAuth(reqWith(h), mid, NOW), false);
});

test('CANONICAL-ONLY GATE (res1): a classical 40-hex owner cannot authorize an ack — canonical-only (the canonical ack happy-path is the "CANONICAL ack round-trip" test below)', async () => {
  // Same res1 gate: a 40-hex owner → verifyMailboxAckAuth's fingerprintMatchesKey → false.
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
  assert.equal(await verifyMailboxAckAuth(reqWith(h), mid, ids, NOW), false);
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

// ── §5 CANONICAL-ID owner-auth: the beat-4 fix (thread PQ pubkeys → 64-hex fp recomputes + matches) ──

test('CANONICAL poll round-trip — a 64-hex canonical id verifies WHEN the PQ pubkeys are threaded (the §5 fix)', async () => {
  const cid = await makeCanonicalIdentity('canon');
  assert.match(cid.fingerprint, /^[0-9a-fA-F]{64}$/); // 64-hex canonical, NOT a 40-hex OpenPGP fp
  const mid = deriveMailboxId(cid.fingerprint);
  const h = await signMailboxPollRequest({
    mailboxId: mid,
    fingerprint: cid.fingerprint,
    publicKeyArmored: cid.publicKey,
    privateKeyArmored: cid.privateKey,
    passphrase: cid.passphrase,
    kemPublicKey: cid.kemPublicKeyB64,
    sigPublicKey: cid.sigPublicKeyB64,
    now: NOW,
  });
  assert.equal(await verifyMailboxPollAuth(reqWith(h), mid, NOW), true);
});

test('CANONICAL id WITHOUT threaded PQ pubkeys → fail-closed (the pre-fix bug; proves the threading is load-bearing)', async () => {
  const cid = await makeCanonicalIdentity('canon2');
  const mid = deriveMailboxId(cid.fingerprint);
  // Omit kem/sig — exactly what the OLD signer did. verifyOwner's fingerprintMatchesKey then can't
  // recompute the 64-hex canonical fp → falls to the 40-hex OpenPGP path → 64 !== 40 → refused.
  // This 401-on-every-poll WAS the beat-4 break.
  const h = await signMailboxPollRequest({
    mailboxId: mid,
    fingerprint: cid.fingerprint,
    publicKeyArmored: cid.publicKey,
    privateKeyArmored: cid.privateKey,
    passphrase: cid.passphrase,
    now: NOW,
  });
  assert.equal(await verifyMailboxPollAuth(reqWith(h), mid, NOW), false);
});

test('CANONICAL ack round-trip — the owner can authorize a delete with the PQ pubkeys threaded', async () => {
  const cid = await makeCanonicalIdentity('canon3');
  const mid = deriveMailboxId(cid.fingerprint);
  const ids = ['env-a', 'env-b'];
  const h = await signMailboxAckRequest({
    mailboxId: mid,
    envelopeIds: ids,
    fingerprint: cid.fingerprint,
    publicKeyArmored: cid.publicKey,
    privateKeyArmored: cid.privateKey,
    passphrase: cid.passphrase,
    kemPublicKey: cid.kemPublicKeyB64,
    sigPublicKey: cid.sigPublicKeyB64,
    now: NOW,
  });
  assert.equal(await verifyMailboxAckAuth(reqWith(h), mid, ids, NOW), true);
});

test('CANONICAL bundle with a WRONG-LENGTH PQ pubkey → rejected at the boundary (§5 defense-in-depth, fail-loud)', async () => {
  const cid = await makeCanonicalIdentity('canon4');
  const mid = deriveMailboxId(cid.fingerprint);
  const h = await signMailboxPollRequest({
    mailboxId: mid,
    fingerprint: cid.fingerprint,
    publicKeyArmored: cid.publicKey,
    privateKeyArmored: cid.privateKey,
    passphrase: cid.passphrase,
    kemPublicKey: cid.kemPublicKeyB64,
    sigPublicKey: cid.sigPublicKeyB64,
    now: NOW,
  });
  // Truncate the kem pubkey (40 base64 chars → ~30 bytes, not 1568) → decodeBundle rejects the whole
  // bundle up front (fail-loud) rather than relying on the downstream fingerprintMatchesKey length gate.
  const tampered = mutateHeader(h, (b) => {
    b.kem_public_key = (b.kem_public_key as string).slice(0, 40);
  });
  assert.equal(await verifyMailboxPollAuth(reqWith(tampered), mid, NOW), false);
});
