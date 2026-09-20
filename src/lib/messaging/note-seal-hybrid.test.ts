// src/lib/messaging/note-seal-hybrid.test.ts
// Real-key e2e for the PQ-hybrid note seal: proves Flint-pinned B (Ed25519→Montgomery, ephemeral×static)
// round-trips with actual OpenPGP + ML-KEM identities, rejects the wrong recipient / a stripped PQ leg,
// and that the reader dispatch routes hybrid vs legacy OpenPGP. Run: node --import tsx --test <file>
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readPrivateKey, decryptKey } from 'openpgp';
import { generatePQKeypairBundle } from '@/lib/crypto/pq';
import { canonicalPubsFromArmoredPublicKey } from '@/lib/identity/fingerprint';
import { NOTE_WIRE_TYPE } from './domains';
import type { NoteWireV0 } from './types';
import { sealNoteTo, noteOpenpgpDecryptor } from './seal';
import {
  sealNoteHybrid,
  hybridNoteDecryptor,
  noteDecryptor,
  isHybridNoteWire,
  NOTE_SEAL_DOMAIN,
  type HybridNoteRecipient,
  type HybridNoteSecrets,
} from './note-seal-hybrid';

const passphrase = 'note-seal-e2e-passphrase';
const senderFp = 'b'.repeat(64);

interface TestIdentity {
  publicKey: string;
  privateKeyArmored: string; // still passphrase-encrypted — for the legacy OpenPGP decryptor
  unlocked: any;
  kemB64: string;
  sigB64: string;
  kemSecret: Uint8Array;
  fingerprint: string;
  recipient: HybridNoteRecipient;
  secrets: HybridNoteSecrets;
}

async function mintIdentity(name: string): Promise<TestIdentity> {
  const gen = await generateKey({
    type: 'ecc', curve: 'ed25519',
    userIDs: [{ name, email: `${name}@example.test` }],
    passphrase, format: 'armored',
  });
  const locked = await readPrivateKey({ armoredKey: gen.privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const pq = generatePQKeypairBundle();
  const kemB64 = Buffer.from(pq.kem.publicKey).toString('base64');
  const sigB64 = Buffer.from(pq.signing.publicKey).toString('base64');
  const pubs = await canonicalPubsFromArmoredPublicKey(gen.publicKey, kemB64, sigB64);
  return {
    publicKey: gen.publicKey, privateKeyArmored: gen.privateKey, unlocked, kemB64, sigB64,
    kemSecret: pq.kem.secretKey, fingerprint: pubs.fingerprint,
    recipient: { publicKeyArmored: gen.publicKey, pqKemPublicKeyB64: kemB64, pqSigPublicKeyB64: sigB64 },
    secrets: { decryptedIdentityKey: unlocked, pqKemSecretKey: pq.kem.secretKey, myFingerprint: pubs.fingerprint },
  };
}

const note = (): NoteWireV0 => ({
  type: NOTE_WIRE_TYPE, note_id: 'n1', thread_id: 't1',
  from_fingerprint: senderFp, sent_at: '2026-09-20T21:00:00.000Z',
  body: 'hello over PQ-hybrid', participant_kind: 'human',
});

let alice: TestIdentity; // recipient
let mallory: TestIdentity; // wrong recipient

before(async () => {
  alice = await mintIdentity('Alice');
  mallory = await mintIdentity('Mallory');
});

test('e2e round-trip: seal to Alice → Alice opens (Ed25519→Montgomery DH agrees)', async () => {
  const wire = await sealNoteHybrid(note(), alice.recipient, senderFp);
  assert.ok(isHybridNoteWire(wire), 'wire must be recognized as a hybrid package');
  const opened = await hybridNoteDecryptor(alice.secrets)(wire);
  assert.ok(opened, 'Alice failed to open her own note');
  assert.equal(opened!.body, 'hello over PQ-hybrid');
  assert.equal(opened!.from_fingerprint, senderFp);
});

test('package binds the recipient fp + carries a fresh ephemeral (forward secrecy)', async () => {
  const w1 = await sealNoteHybrid(note(), alice.recipient, senderFp);
  const w2 = await sealNoteHybrid(note(), alice.recipient, senderFp);
  const p1 = JSON.parse(w1), p2 = JSON.parse(w2);
  assert.equal(p1.domain, NOTE_SEAL_DOMAIN);
  assert.equal(p1.recip_fp, alice.fingerprint);
  assert.notEqual(p1.epk, p2.epk, 'each seal must use a fresh ephemeral X25519 key');
  assert.notEqual(p1.ct, p2.ct, 'fresh ephemeral + nonce ⇒ distinct ciphertext per send');
});

test('reject: the wrong recipient (Mallory) cannot open a note sealed to Alice', async () => {
  const wire = await sealNoteHybrid(note(), alice.recipient, senderFp);
  const opened = await hybridNoteDecryptor(mallory.secrets)(wire);
  assert.equal(opened, null, 'Mallory must not open Alice’s note (fp reject + wrong DH/decap → tag fail)');
});

test('reject: stripped/absent PQ leg cannot be substituted (reject-classical-by-construction)', async () => {
  const wire = await sealNoteHybrid(note(), alice.recipient, senderFp);
  const pkg = JSON.parse(wire);
  // Attacker swaps the ML-KEM ciphertext for another valid-length one → decap yields a different ss_pq.
  const otherWire = await sealNoteHybrid(note(), alice.recipient, senderFp);
  pkg.kem_ct = JSON.parse(otherWire).kem_ct;
  const opened = await hybridNoteDecryptor(alice.secrets)(JSON.stringify(pkg));
  assert.equal(opened, null, 'a swapped kem_ct must break the tag — no classical-only fallback');
});

test('reader dispatch: hybrid → hybrid path; legacy OpenPGP → legacy path', async () => {
  const legacy = noteOpenpgpDecryptor(alice.privateKeyArmored, passphrase);
  const reader = noteDecryptor(legacy, hybridNoteDecryptor(alice.secrets));

  const hybridWire = await sealNoteHybrid(note(), alice.recipient, senderFp);
  const viaHybrid = await reader(hybridWire);
  assert.equal(viaHybrid?.body, 'hello over PQ-hybrid');

  const legacyBlob = await sealNoteTo(note(), alice.publicKey); // classical OpenPGP note
  assert.equal(isHybridNoteWire(legacyBlob), false, 'OpenPGP armor must not be mistaken for hybrid');
  const viaLegacy = await reader(legacyBlob);
  assert.equal(viaLegacy?.body, 'hello over PQ-hybrid', 'legacy notes must still decrypt (REPLACE-forward)');
});
