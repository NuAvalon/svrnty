// signAllowedAdd / allowedAddPreimage — the sender-bound PSI-consent signature primitive.
// Run: npx tsx --test src/lib/identity/raw-sign.allowed-add.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { allowedAddPreimage, signAllowedAdd, psiAuthPreimage } from './raw-sign';

// Deterministic test key (any 32 bytes is a valid Ed25519 seed).
const seed = new Uint8Array(32);
for (let i = 0; i < 32; i++) seed[i] = (i * 7 + 3) & 0xff;
const pub = ed25519.getPublicKey(seed);

const owner = 'ab'.repeat(20);
const sender = 'cd'.repeat(20);
const unix = 1_700_000_123;

test('signAllowedAdd round-trips: verifies against allowedAddPreimage under the sign key', () => {
  const sig = signAllowedAdd(seed, owner, sender, unix);
  assert.equal(ed25519.verify(sig, allowedAddPreimage(owner, sender, unix), pub), true);
});

test('allowedAddPreimage is the exact sender-bound bytes ⚠ GATED on Flint Q1 (#138504) — if he pins a different string, update HERE + satellite together', () => {
  const expected = new TextEncoder().encode(`svrnty-allowed-add:${owner}:${sender}:${unix}`);
  assert.deepEqual(allowedAddPreimage(owner, sender, unix), expected);
});

test('NOT psi-auth-wrapped (no double-tag): a psi-auth verifier rejects an allowed-add sig', () => {
  // Proves signAllowedAdd uses rawSign on the raw preimage and does NOT route through
  // signPsiAuthWrapped (which would sign svrnty-psi-auth:svrnty-allowed-add:... = wrong bytes).
  const sig = signAllowedAdd(seed, owner, sender, unix);
  assert.equal(ed25519.verify(sig, psiAuthPreimage(owner, unix), pub), false);
});

test('preimage binds BOTH owner and sender: a swapped-role sig does not verify (anti-replay-forgery)', () => {
  const sig = signAllowedAdd(seed, owner, sender, unix);
  // The whole point of the KB#89666 hardening: the sig is bound to THIS sender. A verifier
  // reconstructing owner/sender in the other order must reject it.
  assert.equal(ed25519.verify(sig, allowedAddPreimage(sender, owner, unix), pub), false);
  assert.notDeepEqual(signAllowedAdd(seed, owner, sender, unix), signAllowedAdd(seed, sender, owner, unix));
});
