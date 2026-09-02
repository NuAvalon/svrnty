// R1 mutual-vouch (TRUSTED tier) — proves the directional vouch is sound and fails CLOSED: verified
// against the HELD voucher key (NOT TOFU), vouchee-bound (no cross-recipient replay), refused from a
// stranger, epoch-gated, anti-downgrade, confidential, demuxed, domain-separated.
// Run: npx tsx --test src/lib/trust/mutual-vouch.test.ts
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import {
  buildVouchEnvelope,
  buildVouch,
  encryptVouchTo,
  verifyVouch,
  VouchSignError,
  type KnownVoucher,
} from './mutual-vouch';
import {
  DOMAIN_MUTUAL_VOUCH,
  DOMAIN_JOINER_RESPONSE,
  mutualVouchSigningInput,
} from '../format/envelope';
import { verifyWithEnvelope } from '../crypto/sign-envelope';
import { generateSigningKeypair, uint8ToBase64, type PQSigningKeypair } from '../crypto/pq';

const pass = 'test-passphrase-vouch';

// Alice = VOUCHER (signs "I verified Bob"), Bob = VOUCHEE (receives + decrypts). Carol = third party.
let alicePriv: string, alicePub: string, aliceFp: string;
let bobPriv: string, bobPub: string, bobFp: string;
let carolPriv: string, carolPub: string, carolFp: string;
let alicePq: PQSigningKeypair;

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
  alicePq = generateSigningKeypair();
});

// Alice vouches for Bob.
const aliceVouchArgs = (o = {}) => ({ voucherFp: aliceFp, voucherEpoch: 1, voucheeFp: bobFp, ts: '2026-09-02T00:00:00Z', ...o });
const bobVouchee = () => ({ fingerprint: bobFp, privateKeyArmored: bobPriv, passphrase: pass });
// Bob holds Alice as a contact at epoch 1 (classical). Extend for the pq/wrong-key/epoch cases.
const holdsAlice = (o: Partial<KnownVoucher> = {}) =>
  (fp: string): KnownVoucher | null => (fp === aliceFp ? { epoch: 1, publicKeyArmored: alicePub, ...o } : null);

// ── Round-trip ───────────────────────────────────────────────────────────────────
test('round-trip (classical): Alice vouches for Bob → Bob verifies against the held key', async () => {
  const blob = await encryptVouchTo(await buildVouch(aliceVouchArgs(), alicePriv, pass), bobPub);
  const v = await verifyVouch(blob, bobVouchee(), holdsAlice());
  assert.ok(v, 'a valid vouch must verify');
  assert.equal(v!.voucherFingerprint, aliceFp);
  assert.equal(v!.voucheeFingerprint, bobFp);
  assert.equal(v!.voucherEpoch, 1);
});

test('round-trip (hybrid): PQ-signed vouch verifies under requirePq against the held pq key', async () => {
  const signed = await buildVouch(aliceVouchArgs(), alicePriv, pass, alicePq.secretKey);
  assert.ok(signed.signature.pq_signature, 'hybrid vouch must carry a pq half');
  const blob = await encryptVouchTo(signed, bobPub);
  const v = await verifyVouch(blob, bobVouchee(), holdsAlice({ pqSigningPublicKey: alicePq.publicKey }), { requirePq: true });
  assert.ok(v, 'hybrid vouch must verify');
});

// ── Anti-downgrade + suite floor ──────────────────────────────────────────────────
test('anti-downgrade: stripping the pq half of a hybrid vouch fails (→ null)', async () => {
  const signed = await buildVouch(aliceVouchArgs(), alicePriv, pass, alicePq.secretKey);
  delete signed.signature.pq_signature;
  const blob = await encryptVouchTo(signed, bobPub);
  assert.equal(await verifyVouch(blob, bobVouchee(), holdsAlice({ pqSigningPublicKey: alicePq.publicKey })), null);
});

test('suite floor: requirePq rejects a classical-only vouch (→ null)', async () => {
  const blob = await encryptVouchTo(await buildVouch(aliceVouchArgs(), alicePriv, pass), bobPub);
  assert.equal(await verifyVouch(blob, bobVouchee(), holdsAlice(), { requirePq: true }), null);
});

// ── Tamper-evidence ────────────────────────────────────────────────────────────────
test('tamper: bumping voucher_epoch after signing fails (→ null)', async () => {
  const signed = await buildVouch(aliceVouchArgs(), alicePriv, pass);
  signed.envelope.voucher_epoch = 2; // also mismatches held epoch, but the signature is what breaks first-or-either
  const blob = await encryptVouchTo(signed, bobPub);
  assert.equal(await verifyVouch(blob, bobVouchee(), holdsAlice()), null);
});

// ── Vouchee-binding: no cross-recipient replay ──────────────────────────────────────
test('vouchee-binding: a vouch FOR Bob, re-deposited to Carol (who can decrypt), is rejected (→ null)', async () => {
  // Alice's vouch names Bob as vouchee, but we encrypt it to Carol so she CAN decrypt — isolating the
  // vouchee-binding check. Carol (who also holds Alice) must still reject: it isn't addressed to her.
  const signed = await buildVouch(aliceVouchArgs({ voucheeFp: bobFp }), alicePriv, pass);
  const blobToCarol = await encryptVouchTo(signed, carolPub);
  const carolVouchee = { fingerprint: carolFp, privateKeyArmored: carolPriv, passphrase: pass };
  assert.equal(await verifyVouch(blobToCarol, carolVouchee, holdsAlice()), null);
});

// ── Not TOFU: a vouch from a stranger (not held) is refused ──────────────────────────
test('not-a-contact: a vouch whose voucher we do not hold is refused (lookupVoucher → null ⇒ null)', async () => {
  const blob = await encryptVouchTo(await buildVouch(aliceVouchArgs(), alicePriv, pass), bobPub);
  assert.equal(await verifyVouch(blob, bobVouchee(), () => null), null); // we hold nobody
});

test('wrong held key: verifying Alice’s vouch against a DIFFERENT held key fails (→ null)', async () => {
  const blob = await encryptVouchTo(await buildVouch(aliceVouchArgs(), alicePriv, pass), bobPub);
  // lookupVoucher returns Carol's key for Alice's fp — sig was made by Alice → fails against Carol's key.
  assert.equal(await verifyVouch(blob, bobVouchee(), (fp) => (fp === aliceFp ? { epoch: 1, publicKeyArmored: carolPub } : null)), null);
});

// ── Epoch gate ───────────────────────────────────────────────────────────────────
test('epoch: a vouch at epoch 1 is refused when we hold the voucher at epoch 2 (→ null, needs lineage)', async () => {
  const blob = await encryptVouchTo(await buildVouch(aliceVouchArgs({ voucherEpoch: 1 }), alicePriv, pass), bobPub);
  assert.equal(await verifyVouch(blob, bobVouchee(), holdsAlice({ epoch: 2 })), null);
});

// ── Confidentiality ────────────────────────────────────────────────────────────────
test('confidentiality: a vouch encrypted to Bob cannot be opened by Carol (→ null)', async () => {
  const blobToBob = await encryptVouchTo(await buildVouch(aliceVouchArgs(), alicePriv, pass), bobPub);
  const carolVouchee = { fingerprint: carolFp, privateKeyArmored: carolPriv, passphrase: pass };
  assert.equal(await verifyVouch(blobToBob, carolVouchee, holdsAlice()), null);
});

// ── Demux + noise + fail-closed oracle ───────────────────────────────────────────────
test('demux: a joiner-response-shaped blob (no vouch fields) is dropped by verifyVouch (→ null)', async () => {
  const notAVouch = { envelope: { joiner_fingerprint: aliceFp, joiner_epoch: 1, joiner_public_key: alicePub, joiner_display_name: 'A', giver_fingerprint: bobFp, invite_nonce: 'X', ts: 't' }, signature: { classical: 'x' } };
  const { createMessage, encrypt, readKey } = await import('openpgp');
  const blob = (await encrypt({ message: await createMessage({ text: JSON.stringify(notAVouch) }), encryptionKeys: await readKey({ armoredKey: bobPub }) })) as string;
  assert.equal(await verifyVouch(blob, bobVouchee(), holdsAlice()), null);
});

test('noise: a non-PGP blob drops (→ null)', async () => {
  assert.equal(await verifyVouch('not-an-armored-message', bobVouchee(), holdsAlice()), null);
});

test('fail-closed: a throwing lookupVoucher oracle → null', async () => {
  const blob = await encryptVouchTo(await buildVouch(aliceVouchArgs(), alicePriv, pass), bobPub);
  assert.equal(await verifyVouch(blob, bobVouchee(), () => { throw new Error('store down'); }), null);
});

test('lookupVoucher receives the exact voucher fingerprint', async () => {
  const blob = await encryptVouchTo(await buildVouch(aliceVouchArgs(), alicePriv, pass), bobPub);
  let seen: string | undefined;
  await verifyVouch(blob, bobVouchee(), (fp) => { seen = fp; return { epoch: 1, publicKeyArmored: alicePub }; });
  assert.equal(seen, aliceFp);
});

// ── Domain separation ────────────────────────────────────────────────────────────────
test('domain separation: a vouch signature verifies under MUTUAL_VOUCH but NOT under JOINER_RESPONSE', async () => {
  const signed = await buildVouch(aliceVouchArgs(), alicePriv, pass);
  const input = mutualVouchSigningInput(signed.envelope);
  assert.equal(await verifyWithEnvelope(DOMAIN_MUTUAL_VOUCH, input, signed.signature, alicePub), true);
  assert.equal(await verifyWithEnvelope(DOMAIN_JOINER_RESPONSE, input, signed.signature, alicePub), false);
});

// ── Fail-loud-at-BUILD ────────────────────────────────────────────────────────────────
test('build: empty voucher fingerprint refused (bad-voucher-fingerprint)', () => {
  assert.throws(() => buildVouchEnvelope(aliceVouchArgs({ voucherFp: '' })),
    (e: unknown) => e instanceof VouchSignError && e.reason === 'bad-voucher-fingerprint');
});
test('build: empty vouchee fingerprint refused (bad-vouchee-fingerprint)', () => {
  assert.throws(() => buildVouchEnvelope(aliceVouchArgs({ voucheeFp: '' })),
    (e: unknown) => e instanceof VouchSignError && e.reason === 'bad-vouchee-fingerprint');
});
test('build: negative epoch refused (bad-voucher-epoch)', () => {
  assert.throws(() => buildVouchEnvelope(aliceVouchArgs({ voucherEpoch: -1 })),
    (e: unknown) => e instanceof VouchSignError && e.reason === 'bad-voucher-epoch');
});
