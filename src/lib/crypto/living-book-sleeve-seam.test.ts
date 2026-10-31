// src/lib/crypto/living-book-sleeve-seam.test.ts
// Regression guard for the L7 wire-format SEAM (Flint 2026-10-10).
//
// THE BUG this locks out: the sleeve build sealed the hybrid blob ARMORED (armorMailboxEnvelope →
// `-----BEGIN SVRNTY ENCRYPTED MESSAGE-----`), but the consume dual-read discriminator
// (hybrid-dual-read.ts asMailboxEnvelopePackage) is JSON.parse — it expects RAW JSON. An armored blob
// fails JSON.parse → the discriminator reads it as "classical" → the classical opener can't open it →
// undecryptable → acked+dropped = SILENT LOSS of EVERY hybrid blob. The fix: one canonical wire format
// (raw JSON) + one discriminator. This test asserts the seal format and the discriminator agree, and that
// the OLD armored format is REJECTED by the discriminator (so the regression can never silently return).

import { test } from 'node:test';
import assert from 'node:assert';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys } from './mailbox-keys';
import { sealToMailbox, openMailboxEnvelope, deriveMailboxFp } from './mailbox-envelope';
import { armorMailboxEnvelope } from './contact-message';
import { asMailboxEnvelopePackage } from '../sync/hybrid-dual-read';

test('L7 seam: sealLivingBookHybrid wire format is RAW JSON the dual-read discriminator accepts', async () => {
  const kp = await generateMailboxKeypair();
  const pub = toPublicKeys(kp);
  const pkg = await sealToMailbox(new TextEncoder().encode('x'), pub);
  const rawBlob = JSON.stringify(pkg); // == what sealLivingBookHybrid emits post-fix
  assert.notEqual(asMailboxEnvelopePackage(rawBlob), null, 'raw-JSON hybrid blob must be recognized as a package');
});

test('L7 seam REGRESSION GUARD: the OLD armored format is REJECTED by the discriminator (would silent-drop)', async () => {
  const kp = await generateMailboxKeypair();
  const pkg = await sealToMailbox(new TextEncoder().encode('x'), toPublicKeys(kp));
  const armored = armorMailboxEnvelope(pkg); // the pre-fix format
  // If this ever returns non-null, armoring is back and every hybrid blob silently drops.
  assert.equal(asMailboxEnvelopePackage(armored), null, 'armored blob must NOT pass the JSON discriminator');
});

test('L7 seam: a classical armored-PGP blob falls through (null) — classical path, no cross-eat', () => {
  assert.equal(asMailboxEnvelopePackage('-----BEGIN PGP MESSAGE-----\nabc\n-----END PGP MESSAGE-----'), null);
});

test('L7 seam: full round-trip through the fixed format — seal(raw JSON) → discriminator → open → bytes', async () => {
  const kp = await generateMailboxKeypair();
  const pub = toPublicKeys(kp);
  const sec = toSecretKeys(kp);
  const myFp = deriveMailboxFp(pub.x25519Pub, pub.mlkem1024Pub);
  const msg = 'living-book hybrid round-trip';
  const rawBlob = JSON.stringify(await sealToMailbox(new TextEncoder().encode(msg), pub));
  const parsed = asMailboxEnvelopePackage(rawBlob);
  assert.notEqual(parsed, null);
  const out = await openMailboxEnvelope(parsed!, sec, myFp);
  assert.notEqual(out, null, 'open must recover the bytes');
  assert.equal(new TextDecoder().decode(out!), msg);
});

test('L7 seam: wrong-recipient open returns null (reject), never throws', async () => {
  const kp = await generateMailboxKeypair();
  const pub = toPublicKeys(kp);
  const myFp = deriveMailboxFp(pub.x25519Pub, pub.mlkem1024Pub);
  const rawBlob = JSON.stringify(await sealToMailbox(new TextEncoder().encode('secret'), pub));
  const otherSec = toSecretKeys(await generateMailboxKeypair());
  const out = await openMailboxEnvelope(asMailboxEnvelopePackage(rawBlob)!, otherSec, myFp);
  assert.equal(out, null, 'a non-recipient must get null, not plaintext and not a throw');
});
