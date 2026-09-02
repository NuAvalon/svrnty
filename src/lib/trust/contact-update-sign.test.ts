// Send-side signer for 0.4 contact.update — proves the sign path is the exact inverse of the verify
// floor: what buildAndSignContactUpdate produces, verifyIncomingContactUpdate accepts; and the
// build-time firewall refuses (LOUDLY) anything the verifier would silently drop.
// Run: npx tsx --test src/lib/trust/contact-update-sign.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { verifyIncomingContactUpdate, ContactUpdateRejected, type KnownContactIdentity } from './contact-update';
import {
  buildContactUpdateEnvelope,
  signContactUpdate,
  buildAndSignContactUpdate,
  ContactUpdateSignError,
} from './contact-update-sign';
import { generateSigningKeypair, type PQSigningKeypair } from '../crypto/pq';

const passphrase = 'test-passphrase-0';

// Keygen is expensive → once in before() (mirrors contact-update.test.ts).
let privateKey: string, publicKey: string, fingerprint: string;
let pq: PQSigningKeypair;

before(async () => {
  ({ privateKey, publicKey } = await generateKey({
    type: 'curve25519',
    userIDs: [{ name: 'Alice', email: 'alice@example.test' }],
    passphrase,
    format: 'armored',
  }));
  fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  pq = generateSigningKeypair(); // ML-DSA-87 { publicKey, secretKey }
});

function known(o: Partial<KnownContactIdentity> = {}): KnownContactIdentity {
  return { fingerprint, epoch: 1, version: 0, classicalPublicKeyArmored: publicKey, ...o };
}

// ── The round-trip: what we sign, the verify floor accepts ──────────────────────
test('round-trip: buildAndSign → verify returns the declared delta', async () => {
  const signed = await buildAndSignContactUpdate(
    { fingerprint, epoch: 1, version: 1, delta: { display_name: 'Alice Quinn' }, updated_at: '2026-09-02T00:00:00Z' },
    privateKey,
    passphrase,
  );
  const v = await verifyIncomingContactUpdate(signed, known());
  assert.equal(v.fingerprint, fingerprint);
  assert.equal(v.version, 1);
  assert.deepEqual(v.changed_fields, ['display_name']);
  assert.deepEqual(v.delta, { display_name: 'Alice Quinn' });
});

test('round-trip: multi-field (note + emails) verifies, honest manifest derived from delta keys', async () => {
  const signed = await buildAndSignContactUpdate(
    { fingerprint, epoch: 1, version: 2, delta: { note: 'met at the equinox', emails: ['a@x.test', 'a@alt.test'] } },
    privateKey,
    passphrase,
  );
  const v = await verifyIncomingContactUpdate(signed, known());
  assert.deepEqual([...v.changed_fields].sort(), ['emails', 'note']);
  assert.deepEqual(v.delta, { note: 'met at the equinox', emails: ['a@x.test', 'a@alt.test'] });
});

test('round-trip: phones (the earned grow) verifies end-to-end', async () => {
  const signed = await buildAndSignContactUpdate(
    { fingerprint, epoch: 1, version: 1, delta: { phones: ['+15551234567'] } },
    privateKey,
    passphrase,
  );
  const v = await verifyIncomingContactUpdate(signed, known());
  assert.deepEqual(v.delta, { phones: ['+15551234567'] });
});

// ── Hybrid PQ round-trip + anti-downgrade ───────────────────────────────────────
test('hybrid: a PQ-signed update verifies with the PQ public key under requirePq', async () => {
  const signed = await buildAndSignContactUpdate(
    { fingerprint, epoch: 1, version: 1, delta: { display_name: 'Alice' } },
    privateKey,
    passphrase,
    pq.secretKey,
  );
  assert.ok(signed.signature.pq_signature, 'hybrid signature must carry a pq half');
  const v = await verifyIncomingContactUpdate(signed, known({ pqSigningPublicKey: pq.publicKey }), { requirePq: true });
  assert.equal(v.version, 1);
});

test('anti-downgrade: stripping the pq half of our hybrid signature fails verification', async () => {
  const signed = await buildAndSignContactUpdate(
    { fingerprint, epoch: 1, version: 1, delta: { display_name: 'Alice' } },
    privateKey,
    passphrase,
    pq.secretKey,
  );
  delete signed.signature.pq_signature;
  await assert.rejects(
    verifyIncomingContactUpdate(signed, known({ pqSigningPublicKey: pq.publicKey })),
    (e: unknown) => e instanceof ContactUpdateRejected && e.reason === 'bad-signature',
  );
});

// ── Tamper-evidence: our signature binds the envelope ───────────────────────────
test('tamper: mutating the delta after signing fails bad-signature', async () => {
  const signed = await buildAndSignContactUpdate(
    { fingerprint, epoch: 1, version: 1, delta: { display_name: 'Alice' } },
    privateKey,
    passphrase,
  );
  signed.envelope.delta.display_name = 'Mallory';
  await assert.rejects(
    verifyIncomingContactUpdate(signed, known()),
    (e: unknown) => e instanceof ContactUpdateRejected && e.reason === 'bad-signature',
  );
});

// ── Fail-loud-at-send: the build-time firewall refuses what verify would drop ────
test('firewall: a location field is refused at BUILD time (field-not-allowed), never signed', async () => {
  assert.throws(
    () => buildContactUpdateEnvelope({ fingerprint, epoch: 1, version: 1, delta: { location: { lat: 1, lng: 2 } } }),
    (e: unknown) => e instanceof ContactUpdateSignError && e.reason === 'field-not-allowed',
  );
});

test('firewall: public_key (moved to key.rotate) is refused at build time', async () => {
  assert.throws(
    () => buildContactUpdateEnvelope({ fingerprint, epoch: 1, version: 1, delta: { public_key: 'AAAA' } }),
    (e: unknown) => e instanceof ContactUpdateSignError && e.reason === 'field-not-allowed',
  );
});

test('build: empty delta is refused (empty-delta)', () => {
  assert.throws(
    () => buildContactUpdateEnvelope({ fingerprint, epoch: 1, version: 1, delta: {} }),
    (e: unknown) => e instanceof ContactUpdateSignError && e.reason === 'empty-delta',
  );
});

test('build: a negative/junk version is refused (bad-version) — no rollback minting', () => {
  assert.throws(
    () => buildContactUpdateEnvelope({ fingerprint, epoch: 1, version: -1, delta: { display_name: 'A' } }),
    (e: unknown) => e instanceof ContactUpdateSignError && e.reason === 'bad-version',
  );
});

test('build: an empty fingerprint is refused (bad-fingerprint)', () => {
  assert.throws(
    () => buildContactUpdateEnvelope({ fingerprint: '', epoch: 1, version: 1, delta: { display_name: 'A' } }),
    (e: unknown) => e instanceof ContactUpdateSignError && e.reason === 'bad-fingerprint',
  );
});

// ── The recipient's own floors still hold against a well-formed signed update ────
test('recipient floor: a stale version is still dropped by verify even though we signed it correctly', async () => {
  const signed = await buildAndSignContactUpdate(
    { fingerprint, epoch: 1, version: 3, delta: { display_name: 'Alice' } },
    privateKey,
    passphrase,
  );
  await assert.rejects(
    verifyIncomingContactUpdate(signed, known({ version: 3 })),
    (e: unknown) => e instanceof ContactUpdateRejected && e.reason === 'stale-version',
  );
});
