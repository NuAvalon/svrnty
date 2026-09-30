// src/lib/crypto/onion-envelope.test.ts
// Functional gate for the #558 onion two-shell primitive (K0).
// Run: npx tsx --test src/lib/crypto/onion-envelope.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from './mailbox-keys.js';
import { sealToMailbox, openMailboxEnvelope, deriveMailboxFp } from './mailbox-envelope.js';
import { sealOnion, peelOnion } from './onion-envelope.js';

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

  const opened = await openMailboxEnvelope(peeled.inner, toSecretKeys(device), mailboxFpOf(device));
  assert.ok(opened, 'device must open the peeled inner');
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
  const cannotRead = await openMailboxEnvelope(peeled.inner, toSecretKeys(satellite), mailboxFpOf(satellite));
  assert.equal(cannotRead, null, 'satellite must NOT be able to read the inner content');
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
