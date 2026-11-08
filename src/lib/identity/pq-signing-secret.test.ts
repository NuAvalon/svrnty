// src/lib/identity/pq-signing-secret.test.ts
// PINS TODAY'S BEHAVIOUR, on purpose, so the next person to "fix" it meets this file before they break every contact update.
//
// What happens today: genesis stores the PQ keys as the NESTED bundle serializeKeypairBundle() returns ({signing:{secretKey}, kem:{..}}),
// but the contact-update send path asks for a FLAT field (`pq_signing_secret_key`, the PrivateKeyBundle shape). The two never meet, so the
// PQ signing secret is always undefined and every contact update from a normal identity is signed CLASSICAL. Receivers accept those.
//
// The trap: a receiver builds its `known` contact WITHOUT the sender's PQ public key (live-book-poll.ts recordToKnownContact, "omitted by
// design"), and hybrid.ts refuses a hybrid signature when it has no PQ key. So if the sender starts reading the nested key (T1 flips) while
// receivers still omit it (T5 stays), EVERY update from that sender is silently dropped (the relay still answers 200). Verifiers first:
// receivers must map pq_sig_public_key (the receiver-mapping change) BEFORE the sender is changed. When that lands, T1 and T5 flip TOGETHER, on purpose.
//
// Run: npx tsx --test src/lib/identity/pq-signing-secret.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { generatePQKeypairBundle, serializeKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { buildAndSignContactUpdate } from '@/lib/trust/contact-update-sign';
import { verifyIncomingContactUpdate, ContactUpdateRejected } from '@/lib/trust/contact-update';
import { recordToKnownContact } from '@/lib/sync/live-book-poll';
import { pqSigningSecretForSend } from './pq-signing-secret';

const PASS = 'pw-pin';

async function sender() {
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same as the other fixtures).
    curve: 'ed25519',
    userIDs: [{ name: 'pin', email: 'pin@x.test' }],
    passphrase: PASS,
    format: 'armored',
  });
  const fp = (await readKey({ armoredKey: publicKey })).getFingerprint();
  const pq = generatePQKeypairBundle();
  return { privateKey, publicKey, fp, pq };
}

const envelopeArgs = (fp: string, version = 1) => ({
  fingerprint: fp,
  epoch: 0,
  version,
  delta: { handles: { signal: 'pin-handle' } },
  updated_at: '2026-11-08T00:00:00.000Z',
});

test('T1 PIN: the PQ bundle genesis stores (nested) yields NO signing secret, so the send path signs classical', async () => {
  const { pq } = await sender();
  const storedAtGenesis = serializeKeypairBundle(pq); // exactly what browser-identity.ts stores via storePQKeys
  assert.equal(pqSigningSecretForSend(storedAtGenesis), undefined);
});

test('T2 the flat PrivateKeyBundle shape WOULD be read (a dead branch today: no stored identity has this shape)', async () => {
  const { pq } = await sender();
  const flat = { pq_signing_secret_key: uint8ToBase64(pq.signing.secretKey) };
  const got = pqSigningSecretForSend(flat);
  assert.ok(got instanceof Uint8Array);
  assert.deepEqual(Array.from(got!), Array.from(pq.signing.secretKey));
});

test('T3 nothing stored, or garbage stored, is classical (never throws, never blocks a send)', () => {
  assert.equal(pqSigningSecretForSend(null), undefined);
  assert.equal(pqSigningSecretForSend(undefined), undefined);
  assert.equal(pqSigningSecretForSend({}), undefined);
  assert.equal(pqSigningSecretForSend({ pq_signing_secret_key: '' }), undefined);
});

test('T4 CHAIN, real shapes: genesis sender -> classical-signed update -> receiver (as wired) APPLIES it', async () => {
  const s = await sender();
  const sk = pqSigningSecretForSend(serializeKeypairBundle(s.pq));
  const signed = await buildAndSignContactUpdate(envelopeArgs(s.fp), s.privateKey, PASS, sk);
  assert.deepEqual(Object.keys(signed.signature as object), ['classical'], 'a normal identity signs classical only');
  const known = recordToKnownContact({ fingerprint: s.fp, epoch: 0, version: 0, public_key: s.publicKey } as never);
  const verified = await verifyIncomingContactUpdate(signed, known);
  assert.equal(verified.fingerprint, s.fp);
  assert.deepEqual(verified.delta, { handles: { signal: 'pin-handle' } }, 'the receiver applies the delta the sender signed');
});

test('T5 TRAP PIN: a HYBRID-signed update is REFUSED by a receiver built as today (no sender PQ key); flips with the receiver-mapping change, together with T1', async () => {
  const s = await sender();
  const signed = await buildAndSignContactUpdate(envelopeArgs(s.fp), s.privateKey, PASS, s.pq.signing.secretKey);
  assert.ok('pq_signature' in (signed.signature as object), 'precondition: this signature IS hybrid');
  const known = recordToKnownContact({ fingerprint: s.fp, epoch: 0, version: 0, public_key: s.publicKey } as never);
  await assert.rejects(
    () => verifyIncomingContactUpdate(signed, known),
    (e: unknown) => e instanceof ContactUpdateRejected && e.reason === 'bad-signature',
    'if this starts ACCEPTING, receivers now map the sender PQ key: update T1 and the comment in SoverentityFrontend deliberately',
  );
  // and the same hybrid update IS accepted by a receiver that holds the sender's PQ key: the fix direction is real
  const knownWithPq = { ...known, pqSigningPublicKey: s.pq.signing.publicKey };
  const ok = await verifyIncomingContactUpdate({ ...signed }, knownWithPq);
  assert.equal(ok.fingerprint, s.fp);
});
