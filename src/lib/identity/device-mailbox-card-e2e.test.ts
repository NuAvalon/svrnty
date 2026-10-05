// src/lib/identity/device-mailbox-card-e2e.test.ts
// piece-2 device-mailbox — END-TO-END over a REAL signed identity card (openpgp + canonical fp). Proves
// the two load-bearing security properties of the card-borne seal-target:
//   (1) the mailbox fields are SIGNATURE-COVERED (tampering one breaks verify → import drops the mailbox),
//   (2) a legacy card WITHOUT mailbox fields still verifies (OMIT is byte-preserving).
//   npx tsx --test src/lib/identity/device-mailbox-card-e2e.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { signIdentityCard, verifySignedIdentityCard, classifyImportedCard, buildSignedIdentityCard } from './identity-card-sign';
import type { IdentityCard } from '../format/envelope';
import { generatePQKeypairBundle, uint8ToBase64 } from '../crypto/pq';
import { mintCanonicalFingerprint } from './fingerprint';
import { generateMailboxKeypair, toPublicKeys } from '../crypto/mailbox-keys';
import { mailboxPublicOf, type DeviceMailboxPublic } from './device-mailbox';

interface CanonId { fingerprint: string; publicKey: string; privateKey: string; passphrase: string; kemB64: string; sigB64: string; }
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
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey,
  });
  return { fingerprint, publicKey: pub, privateKey: priv, passphrase: pass, kemB64: uint8ToBase64(pq.kem.publicKey), sigB64: uint8ToBase64(pq.signing.publicKey) };
}
function canonCard(id: CanonId, over: Partial<IdentityCard['identity']> = {}): IdentityCard {
  return {
    version: '1.1', type: 'identity-exchange', created_at: '2026-10-05T00:00:00.000Z',
    identity: {
      fingerprint: id.fingerprint, display_name: 'Alice', public_key: id.publicKey, email: 'alice@example.test',
      pq_sig_public_key: id.sigB64, pq_kem_public_key: id.kemB64, next_authority_commitment: '', ...over,
    },
  };
}
function freshMailbox(): DeviceMailboxPublic {
  return mailboxPublicOf(toPublicKeys(generateMailboxKeypair()));
}

test('a VALID mailbox card signs, verifies, and import extracts the authenticated seal-target', async () => {
  const id = await makeCanonicalId('mbok');
  const mb = freshMailbox();
  const signed = await signIdentityCard(
    canonCard(id, { mailbox_fp: mb.mailbox_fp, mailbox_x25519_pk: mb.mailbox_x25519_pk, mailbox_mlkem1024_pk: mb.mailbox_mlkem1024_pk }),
    id.privateKey, id.passphrase,
  );
  assert.equal(await verifySignedIdentityCard(signed), true);
  const d = await classifyImportedCard(signed);
  assert.equal(d.importClassical, true);
  assert.equal(d.branch, '4b'); // valid sig + real ML-KEM-1024 suite
  assert.deepEqual(d.deviceMailbox, mb);
});

test('SIG-COVERAGE: tampering mailbox_x25519_pk after signing breaks verify → import DROPS the mailbox', async () => {
  const id = await makeCanonicalId('mbtamper');
  const mb = freshMailbox();
  const signed = await signIdentityCard(
    canonCard(id, { mailbox_fp: mb.mailbox_fp, mailbox_x25519_pk: mb.mailbox_x25519_pk, mailbox_mlkem1024_pk: mb.mailbox_mlkem1024_pk }),
    id.privateKey, id.passphrase,
  );
  // Swap the seal-target's x25519 key to an attacker's (one hex nibble flip is enough — it's signed).
  const flipped = signed.identity.mailbox_x25519_pk!.startsWith('0')
    ? '1' + signed.identity.mailbox_x25519_pk!.slice(1)
    : '0' + signed.identity.mailbox_x25519_pk!.slice(1);
  const tampered = { ...signed, identity: { ...signed.identity, mailbox_x25519_pk: flipped } };
  assert.equal(await verifySignedIdentityCard(tampered), false); // the seal-target IS under the signature
  const d = await classifyImportedCard(tampered);
  assert.equal(d.branch, 3);            // present-but-invalid signature
  assert.equal(d.alarm, 'loud');        // possible tampering
  assert.equal(d.deviceMailbox, null);  // never store an unauthenticated seal-target
});

test('BYTE-PRESERVING: a legacy card with NO mailbox fields still verifies; import yields deviceMailbox null', async () => {
  const id = await makeCanonicalId('mblegacy');
  const signed = await signIdentityCard(canonCard(id), id.privateKey, id.passphrase); // no mailbox fields
  assert.equal(await verifySignedIdentityCard(signed), true);
  assert.equal(signed.identity.mailbox_fp, undefined); // omitted, not null
  const d = await classifyImportedCard(signed);
  assert.equal(d.importClassical, true);
  assert.equal(d.deviceMailbox, null);
});

test('buildSignedIdentityCard: carries the wrapper device_mailbox onto a verifiable card', async () => {
  const id = await makeCanonicalId('mbbuild');
  const mb = freshMailbox();
  const wrapper = {
    identity: { fingerprint: id.fingerprint, display_name: 'Alice', public_key: id.publicKey, email: 'a@x.test' },
    post_quantum: { sig_public_key: id.sigB64, kem_public_key: id.kemB64 },
    device_mailbox: mb,
  };
  const signed = await buildSignedIdentityCard(wrapper, id.privateKey, id.passphrase);
  assert.equal(signed.identity.mailbox_fp, mb.mailbox_fp);
  assert.equal(signed.identity.mailbox_x25519_pk, mb.mailbox_x25519_pk);
  assert.equal(signed.identity.mailbox_mlkem1024_pk, mb.mailbox_mlkem1024_pk);
  assert.equal(await verifySignedIdentityCard(signed), true);
});

test('buildSignedIdentityCard: a wrapper WITHOUT a mailbox omits the fields (and still verifies)', async () => {
  const id = await makeCanonicalId('mbnone');
  const wrapper = {
    identity: { fingerprint: id.fingerprint, display_name: 'Bob', public_key: id.publicKey, email: 'b@x.test' },
    post_quantum: { sig_public_key: id.sigB64, kem_public_key: id.kemB64 },
  };
  const signed = await buildSignedIdentityCard(wrapper, id.privateKey, id.passphrase);
  assert.equal(signed.identity.mailbox_fp, undefined);
  assert.equal(signed.identity.mailbox_x25519_pk, undefined);
  assert.equal(await verifySignedIdentityCard(signed), true);
});

test('buildSignedIdentityCard: an INCONSISTENT wrapper mailbox (fp ≠ H(keys)) is dropped, not carried', async () => {
  const id = await makeCanonicalId('mbinc');
  const mb = freshMailbox();
  const wrapper = {
    identity: { fingerprint: id.fingerprint, display_name: 'Eve', public_key: id.publicKey, email: 'e@x.test' },
    post_quantum: { sig_public_key: id.sigB64, kem_public_key: id.kemB64 },
    device_mailbox: { ...mb, mailbox_fp: '0'.repeat(64) }, // self-inconsistent
  };
  const signed = await buildSignedIdentityCard(wrapper, id.privateKey, id.passphrase);
  assert.equal(signed.identity.mailbox_fp, undefined); // validateMailboxPublic rejected it → omitted
  assert.equal(await verifySignedIdentityCard(signed), true);
});
