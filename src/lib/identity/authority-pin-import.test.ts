// src/lib/identity/authority-pin-import.test.ts
// #787 (F0a): a card's authority pin (identity.next_authority_commitment) is handed to the import ONLY under a VALID signature, and only when it is
// canonical (64 lowercase hex). Same contract as the card-borne device mailbox (device-mailbox-card-e2e.test.ts): real openpgp, canonical fp.
//   npx tsx --test src/lib/identity/authority-pin-import.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { signIdentityCard, verifySignedIdentityCard, classifyImportedCard, canonicalAuthorityPin } from './identity-card-sign';
import type { IdentityCard } from '../format/envelope';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from './fingerprint';

interface CanonId { fingerprint: string; publicKey: string; privateKey: string; passphrase: string; kemB64: string; sigB64: string }
async function makeCanonicalId(name: string): Promise<CanonId> {
  const pass = 'pw-' + name;
  const { privateKey: priv, publicKey: pub } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime (same keygen as core.ts).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }], passphrase: pass, format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: priv });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase: pass });
  const { fingerprint } = await mintCanonicalFingerprint({ decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey });
  return { fingerprint, publicKey: pub, privateKey: priv, passphrase: pass, kemB64: uint8ToBase64(pq.kem.publicKey), sigB64: uint8ToBase64(pq.signing.publicKey) };
}
function card(id: CanonId, pin: unknown): IdentityCard {
  return {
    version: '1.1', type: 'identity-exchange', created_at: '2026-11-09T00:00:00.000Z',
    identity: {
      fingerprint: id.fingerprint, display_name: 'Alice', public_key: id.publicKey, email: 'alice@example.test',
      pq_sig_public_key: id.sigB64, pq_kem_public_key: id.kemB64, next_authority_commitment: pin as string,
    },
  };
}
const PIN = 'be9e7bee4ca082f34afc66053ef52d9a2d5aabc7597b5f0774911b7dc96cebaf';
const OTHER = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

test('P1 a VALID signed card hands its canonical pin to the import (branch 4b)', async () => {
  const id = await makeCanonicalId('p1');
  const signed = await signIdentityCard(card(id, PIN), id.privateKey, id.passphrase);
  assert.equal(await verifySignedIdentityCard(signed), true);
  const d = await classifyImportedCard(signed);
  assert.equal(d.branch, '4b');
  assert.equal(d.authorityPin, PIN);
});

test('P2 a legacy card with an empty pin under a valid signature hands over NO pin (not an empty string)', async () => {
  const id = await makeCanonicalId('p2');
  const d = await classifyImportedCard(await signIdentityCard(card(id, ''), id.privateKey, id.passphrase));
  assert.equal(d.importClassical, true);
  assert.equal(d.authorityPin, null);
});

test('P3 NEG SIG-COVERAGE: swapping the pin AFTER signing breaks verify, so the import drops it (branch 3, loud)', async () => {
  const id = await makeCanonicalId('p3');
  const signed = await signIdentityCard(card(id, PIN), id.privateKey, id.passphrase);
  const tampered = { ...signed, identity: { ...signed.identity, next_authority_commitment: OTHER } };
  assert.equal(await verifySignedIdentityCard(tampered), false);
  const d = await classifyImportedCard(tampered);
  assert.equal(d.branch, 3);
  assert.equal(d.alarm, 'loud');
  assert.equal(d.authorityPin, null);
});

test('P4 NEG a card with NO signature is imported classical-only and its pin is dropped (branch 2)', async () => {
  const id = await makeCanonicalId('p4');
  const signed = await signIdentityCard(card(id, PIN), id.privateKey, id.passphrase);
  const { signature: _drop, ...unsigned } = signed as IdentityCard & { signature?: string };
  const d = await classifyImportedCard(unsigned);
  assert.equal(d.branch, 2);
  assert.equal(d.authorityPin, null);
});

test('P5 NEG a fingerprint that does not match its key refuses the card and carries no pin (branch 1)', async () => {
  const id = await makeCanonicalId('p5');
  const signed = await signIdentityCard(card(id, PIN), id.privateKey, id.passphrase);
  const flipped = id.fingerprint.replace(/.$/, id.fingerprint.endsWith('0') ? '1' : '0');
  const d = await classifyImportedCard({ ...signed, identity: { ...signed.identity, fingerprint: flipped } });
  assert.equal(d.importClassical, false);
  assert.equal(d.authorityPin, null);
});

test('P6 NEG even under a VALID signature, a pin that is not exactly 64 lowercase hex is dropped', async () => {
  const id = await makeCanonicalId('p6');
  for (const bad of [PIN.toUpperCase(), PIN.slice(0, 63), PIN + '0', 'zz'.repeat(32), 12345, ' ' + PIN]) {
    const signed = await signIdentityCard(card(id, bad), id.privateKey, id.passphrase);
    const d = await classifyImportedCard(signed);
    assert.equal(d.authorityPin, null, `dropped: ${String(bad).slice(0, 20)}`);
  }
});

test('P7 canonicalAuthorityPin accepts exactly 64 lowercase hex and nothing else', () => {
  assert.equal(canonicalAuthorityPin(PIN), PIN);
  for (const bad of ['', PIN.toUpperCase(), PIN.slice(1), undefined, null, 7, {}, [PIN]]) assert.equal(canonicalAuthorityPin(bad), null);
});
