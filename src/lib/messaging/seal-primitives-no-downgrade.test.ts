// src/lib/messaging/seal-primitives-no-downgrade.test.ts
// #720 close-out (Archie #2014, Hypatia #2015): every seal primitive THROWS without a recipient ML-KEM key, like sealNoteTo, so a future
// caller that forgets the key fails loudly instead of silently sending a classical blob. Production was already hybrid-only because the
// composers skip such recipients; this makes the PRIMITIVE reject-classical by construction, which is what a claim may rest on.
// NEG-first: before this change both primitives returned a classical OpenPGP blob for a missing key.
// Run: npx tsx --test src/lib/messaging/seal-primitives-no-downgrade.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { mintHeadlessAgent } from '../identity/headless-mint';
import { encryptContactUpdateTo } from '../sync/contact-update-envelope';
import { encryptJoinerResponseTo } from '../trust/joiner-response';
import { encryptContactUpdateClassicalFixture, encryptJoinerResponseClassicalFixture } from './seal-classical-fixture';

let pub = '';
let kem = '';
const signedCU = { envelope: { fingerprint: 'fp', epoch: 0, version: 1 }, signature: 's' } as never;
const signedJR = { response: { joiner_fingerprint: 'fp' }, signature: 's' } as never;

before(async () => {
  const peer = await mintHeadlessAgent({ throwaway: true });
  const id = peer.introduction.card.identity as unknown as { public_key: string; pq_kem_public_key: string };
  pub = id.public_key;
  kem = id.pq_kem_public_key;
});

const PGP = /BEGIN PGP MESSAGE/;

test('S1 encryptContactUpdateTo refuses without a recipient ML-KEM key (undefined, empty): no classical downgrade, loud', async () => {
  await assert.rejects(() => encryptContactUpdateTo(signedCU, pub), /ML-KEM/);
  await assert.rejects(() => encryptContactUpdateTo(signedCU, pub, undefined), /ML-KEM/);
  await assert.rejects(() => encryptContactUpdateTo(signedCU, pub, ''), /ML-KEM/);
});

test('S2 encryptJoinerResponseTo refuses without the giver ML-KEM key (undefined, empty): no classical downgrade, loud', async () => {
  await assert.rejects(() => encryptJoinerResponseTo(signedJR, pub), /ML-KEM/);
  await assert.rejects(() => encryptJoinerResponseTo(signedJR, pub, undefined), /ML-KEM/);
  await assert.rejects(() => encryptJoinerResponseTo(signedJR, pub, ''), /ML-KEM/);
});

test('S3 control: WITH the KEM key both seal hybrid (not an OpenPGP armor blob)', async () => {
  const a = await encryptContactUpdateTo(signedCU, pub, kem);
  const b = await encryptJoinerResponseTo(signedJR, pub, kem);
  for (const blob of [a, b]) {
    assert.ok(blob.length > 100);
    assert.doesNotMatch(blob, PGP);
    assert.equal((JSON.parse(blob) as { v?: number }).v, 1, 'a mailbox-envelope package');
  }
});

test('S4 the classical fixtures still build the classical shape, so the open path keeps a way to prove it refuses/opens it', async () => {
  assert.match(await encryptContactUpdateClassicalFixture(signedCU, pub), PGP);
  assert.match(await encryptJoinerResponseClassicalFixture(signedJR, pub), PGP);
});

test('S5 static: neither primitive file contains a classical OpenPGP encrypt() any more', () => {
  for (const f of ['../sync/contact-update-envelope.ts', '../trust/joiner-response.ts']) {
    const src = readFileSync(new URL(f, import.meta.url), 'utf8');
    assert.doesNotMatch(src, /\bencrypt\(\s*\{\s*message/, `${f}: classical encrypt({ message ... }) must be gone`);
  }
});
