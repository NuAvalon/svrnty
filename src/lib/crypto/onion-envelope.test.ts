// src/lib/crypto/onion-envelope.test.ts
// Functional + BLINDING gate for the #558 onion two-shell primitive (K0).
// Run: npx tsx --test src/lib/crypto/onion-envelope.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from './mailbox-keys.js';
import { sealToMailbox, openMailboxEnvelope, deriveMailboxFp } from './mailbox-envelope.js';
import { sealOnion, peelOnion, openOnionInner } from './onion-envelope.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

test('roundtrip: device-seal → onion-wrap → satellite-peel → device-open (route preserved)', async () => {
  const device = generateMailboxKeypair();
  const satellite = generateMailboxKeypair();

  const inner = await sealToMailbox(enc.encode('hello through the onion'), toPublicKeys(device));
  const outer = await sealOnion(inner, toPublicKeys(satellite), 'route-abc');

  const peeled = await peelOnion(outer, toSecretKeys(satellite), mailboxFpOf(satellite));
  assert.ok(peeled, 'satellite must peel the outer');
  assert.equal(peeled.route, 'route-abc', 'route datum preserved through the shell');

  // Device re-supplies its own fp (stripped on the wire) and opens the inner.
  const opened = await openOnionInner(peeled.inner, toSecretKeys(device), mailboxFpOf(device));
  assert.ok(opened, 'device must open the peeled inner via re-supplied fp');
  assert.equal(dec.decode(opened), 'hello through the onion');
});

test('SEPARATION: satellite peels routing but CANNOT read content (inner stays device-sealed)', async () => {
  const device = generateMailboxKeypair();
  const satellite = generateMailboxKeypair();

  const inner = await sealToMailbox(enc.encode('for the device only'), toPublicKeys(device));
  const outer = await sealOnion(inner, toPublicKeys(satellite), 'r');

  const peeled = await peelOnion(outer, toSecretKeys(satellite), mailboxFpOf(satellite));
  assert.ok(peeled);
  // The satellite holds the peeled inner but its OWN secrets cannot open it — content is device-sealed.
  // (Re-insert the SATELLITE's own fp to give openMailboxEnvelope a well-formed package; it must still reject.)
  const cannotRead = await openMailboxEnvelope(
    { ...peeled.inner, mailbox_fp: mailboxFpOf(satellite) },
    toSecretKeys(satellite),
    mailboxFpOf(satellite),
  );
  assert.equal(cannotRead, null, 'satellite must NOT be able to read the inner content');
});

// ── K0-1 BLINDING (Flint gate, KB#91389): the satellite must not be handed a stable recipient id ──────
test('BLINDING: peeled inner carries NO mailbox_fp (stable recipient id stripped)', async () => {
  const device = generateMailboxKeypair();
  const satellite = generateMailboxKeypair();

  const inner = await sealToMailbox(enc.encode('x'), toPublicKeys(device));
  const outer = await sealOnion(inner, toPublicKeys(satellite), 'r');
  const peeled = await peelOnion(outer, toSecretKeys(satellite), mailboxFpOf(satellite));
  assert.ok(peeled);
  assert.ok(!('mailbox_fp' in peeled.inner), 'inner.mailbox_fp must be stripped on the wire');
  // The device's stable fp hex must not appear ANYWHERE in what the satellite sees post-peel.
  assert.ok(
    !JSON.stringify(peeled).includes(mailboxFpOf(device)),
    'recipient device fp must not leak through the peel',
  );
});

test('BLINDING/linkability: two messages to the SAME device share NO stable field post-peel', async () => {
  const device = generateMailboxKeypair();
  const satellite = generateMailboxKeypair();

  const outer1 = await sealOnion(await sealToMailbox(enc.encode('m1'), toPublicKeys(device)), toPublicKeys(satellite), 'r');
  const outer2 = await sealOnion(await sealToMailbox(enc.encode('m2'), toPublicKeys(device)), toPublicKeys(satellite), 'r');
  const p1 = await peelOnion(outer1, toSecretKeys(satellite), mailboxFpOf(satellite));
  const p2 = await peelOnion(outer2, toSecretKeys(satellite), mailboxFpOf(satellite));
  assert.ok(p1 && p2);
  // No mailbox_fp on either, and every remaining inner field is per-message fresh → nothing links them.
  assert.ok(!('mailbox_fp' in p1.inner) && !('mailbox_fp' in p2.inner));
  assert.notEqual(p1.inner.epk, p2.inner.epk, 'ephemeral pubkeys differ (fresh per message)');
  assert.notEqual(p1.inner.kem_ct, p2.inner.kem_ct, 'KEM ciphertexts differ (fresh per message)');
  assert.notEqual(p1.inner.nonce, p2.inner.nonce, 'nonces differ (fresh per message)');
  assert.notEqual(p1.inner.ct, p2.inner.ct, 'ciphertexts differ');
});

test('wrong satellite: peel with a different satellite rejects (null)', async () => {
  const device = generateMailboxKeypair();
  const satellite = generateMailboxKeypair();
  const other = generateMailboxKeypair();

  const inner = await sealToMailbox(enc.encode('x'), toPublicKeys(device));
  const outer = await sealOnion(inner, toPublicKeys(satellite), 'r');
  assert.equal(await peelOnion(outer, toSecretKeys(other), mailboxFpOf(other)), null);
});

test('footgun-B: outer mailbox_fp is DERIVED from satellite pubkeys, never supplied', async () => {
  const device = generateMailboxKeypair();
  const satellite = generateMailboxKeypair();

  const inner = await sealToMailbox(enc.encode('x'), toPublicKeys(device));
  const outer = await sealOnion(inner, toPublicKeys(satellite), 'r');
  assert.equal(outer.mailbox_fp, deriveMailboxFp(satellite.x25519Pub, satellite.mlkem1024Pub));
});

test('tamper: flipping an outer field makes peel reject (null)', async () => {
  const device = generateMailboxKeypair();
  const satellite = generateMailboxKeypair();

  const inner = await sealToMailbox(enc.encode('x'), toPublicKeys(device));
  const outer = await sealOnion(inner, toPublicKeys(satellite), 'r');
  const tampered = { ...outer, ct: outer.ct.slice(0, -4) + 'AAAA' };
  assert.equal(await peelOnion(tampered, toSecretKeys(satellite), mailboxFpOf(satellite)), null);
});

test('malformed / hostile outer never throws → null', async () => {
  const satellite = generateMailboxKeypair();

  // A validly-sealed outer whose plaintext is NOT the expected JSON shape.
  const junk = await sealToMailbox(enc.encode('not our json'), toPublicKeys(satellite));
  assert.equal(await peelOnion(junk, toSecretKeys(satellite), mailboxFpOf(satellite)), null);

  // A JSON object missing required fields.
  const badShape = await sealToMailbox(enc.encode(JSON.stringify({ route: 'r' })), toPublicKeys(satellite));
  assert.equal(await peelOnion(badShape, toSecretKeys(satellite), mailboxFpOf(satellite)), null);

  // Hostile non-object package.
  // @ts-expect-error deliberately passing a non-package to prove null-not-throw
  assert.equal(await peelOnion(null, toSecretKeys(satellite), mailboxFpOf(satellite)), null);
});
