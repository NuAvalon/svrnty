// src/lib/messaging/note-auth.test.ts
// Executable proof that the notes forgeable-sender gap is CLOSED (Flint #55, Apollo).
// The vuln: acceptInboundNote trusted `from_fingerprint` after only isAdmitted() — admission is not
// authentication, so anyone could deposit a note "from" an admitted contact. These tests prove that
// after signNoteWire + verifyNoteSender, the ONLY note that authenticates is one actually signed by
// the identity key whose fingerprint == from_fingerprint. Every forgery variant is rejected — and
// rejected BEFORE admit inside acceptInboundNote (so admission=true cannot rescue a forgery).
// Run: npx tsx --test src/lib/messaging/note-auth.test.ts

import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey, readPrivateKey, decryptKey } from 'openpgp';
import { signWithEnvelope } from '@/lib/crypto/sign-envelope';
import { generatePQKeypairBundle, uint8ToBase64 } from '@/lib/crypto/pq';
import { mintCanonicalFingerprint } from '@/lib/identity/fingerprint';
import { DOMAIN_NOTE, NOTE_WIRE_TYPE } from './domains';
import { noteSigningInput } from './canonical';
import { signNoteWire, verifyNoteSender } from './note-auth';
import { acceptInboundNote } from './transport';
import type { NoteWireV0 } from './types';

const alicePass = 'alice-pass-0';
const malloryPass = 'mallory-pass-1';

let alicePriv: string, alicePub: string, aliceFp: string;
let malloryPriv: string, malloryPub: string, malloryFp: string;

before(async () => {
  ({ privateKey: alicePriv, publicKey: alicePub } = await generateKey({
    type: 'curve25519',
    userIDs: [{ name: 'Alice', email: 'alice@example.test' }],
    passphrase: alicePass,
    format: 'armored',
  }));
  aliceFp = (await readKey({ armoredKey: alicePub })).getFingerprint();

  ({ privateKey: malloryPriv, publicKey: malloryPub } = await generateKey({
    type: 'curve25519',
    userIDs: [{ name: 'Mallory', email: 'm@example.test' }],
    passphrase: malloryPass,
    format: 'armored',
  }));
  malloryFp = (await readKey({ armoredKey: malloryPub })).getFingerprint();
});

/** An UNSIGNED note wire; from_fingerprint defaults to Alice (the honest sender). */
function unsignedWire(over: Partial<NoteWireV0> = {}): NoteWireV0 {
  return {
    type: NOTE_WIRE_TYPE,
    note_id: 'note-1',
    thread_id: 'thread-1',
    from_fingerprint: aliceFp,
    sent_at: '2026-09-04T00:00:00.000Z',
    body: 'hello from alice',
    participant_kind: 'human',
    ...over,
  };
}

// A §5 CANONICAL identity: openpgp (sign+enc) + ML-KEM/ML-DSA pubkeys → a 64-hex SHA256(sign‖enc‖kem‖sig)
// fingerprint (NOT the 40-hex OpenPGP fp). Mirrors relay/mailbox-auth.test.ts makeCanonicalIdentity.
interface CanonicalIdentity {
  fingerprint: string;
  publicKey: string;
  privateKey: string;
  passphrase: string;
  kemPublicKeyB64: string;
  sigPublicKeyB64: string;
}
async function makeCanonicalIdentity(name: string): Promise<CanonicalIdentity> {
  const passphrase = 'pw-' + name;
  const { privateKey, publicKey } = await generateKey({
    type: 'ecc',
    // @ts-expect-error openpgp v6 curve-type wart: 'ed25519' is valid at runtime — the exact keygen used
    // in src/lib/identity/core.ts (which carries the same pre-existing tsc wart).
    curve: 'ed25519',
    userIDs: [{ name, email: `${name}@x.test` }],
    passphrase,
    format: 'armored',
  });
  const pq = generatePQKeypairBundle();
  const locked = await readPrivateKey({ armoredKey: privateKey });
  const unlocked = locked.isDecrypted() ? locked : await decryptKey({ privateKey: locked, passphrase });
  const { fingerprint } = await mintCanonicalFingerprint({
    decryptedIdentityKey: unlocked, kemPublicKey: pq.kem.publicKey, sigPublicKey: pq.signing.publicKey,
  });
  return {
    fingerprint, publicKey, privateKey, passphrase,
    kemPublicKeyB64: uint8ToBase64(pq.kem.publicKey),
    sigPublicKeyB64: uint8ToBase64(pq.signing.publicKey),
  };
}

// ── the happy path authenticates ───────────────────────────────────────────────────────────────

test('CANONICAL-ONLY GATE (res1): a classical 40-hex note does NOT authenticate — the OpenPGP fall-through is removed (the canonical happy-path is the "CANONICAL sender" test below)', async () => {
  // alice is a classical (40-hex OpenPGP) identity. Post-res1 fingerprintMatchesKey is canonical-only:
  // a 40-hex claimed fp with no PQ legs → false. This inverts the pre-res1 "classical binds" assertion
  // (mirrors canonical-fingerprint.test.ts). The authenticating happy-path is now canonical (below).
  const signed = await signNoteWire(unsignedWire(), alicePub, alicePriv, alicePass);
  assert.equal(await verifyNoteSender(signed), false);
});

// ── every forgery / tamper is refused ───────────────────────────────────────────────────────────

test('unsigned note is rejected (no signature/public_key ⇒ unauthenticated)', async () => {
  assert.equal(await verifyNoteSender(unsignedWire()), false);
});

test('tampered body is rejected (signature no longer covers content)', async () => {
  const signed = await signNoteWire(unsignedWire(), alicePub, alicePriv, alicePass);
  const tampered: NoteWireV0 = { ...signed, body: 'malicious replacement' };
  assert.equal(await verifyNoteSender(tampered), false);
});

test('THE ATTACK — forge "from Alice" with attacker key: rejected by fp↔key binding', async () => {
  // Mallory claims to be Alice (an admitted contact) and signs with HER OWN key, carrying HER key.
  const forged = await signNoteWire(
    unsignedWire({ from_fingerprint: aliceFp }),
    malloryPub,
    malloryPriv,
    malloryPass,
  );
  // fingerprintMatchesKey(aliceFp, malloryPub) === false → refuse.
  assert.equal(await verifyNoteSender(forged), false);
});

test('THE ATTACK v2 — carry victim\'s public key but sign with attacker key: rejected by signature', async () => {
  const w = unsignedWire({ from_fingerprint: aliceFp });
  const malSig = await signWithEnvelope(DOMAIN_NOTE, noteSigningInput(w), malloryPriv, malloryPass);
  // fp↔key passes (aliceFp ↔ alicePub) but the signature was Mallory's → verifyWithEnvelope fails.
  const forged: NoteWireV0 = { ...w, public_key: alicePub, signature: malSig };
  assert.equal(await verifyNoteSender(forged), false);
});

test('swapped from_fingerprint (valid Alice sig, claim Mallory) is rejected', async () => {
  const signed = await signNoteWire(unsignedWire(), alicePub, alicePriv, alicePass);
  const swapped: NoteWireV0 = { ...signed, from_fingerprint: malloryFp };
  assert.equal(await verifyNoteSender(swapped), false);
});

test('domain confusion — a signature made under a different domain does not verify as a note', async () => {
  const w = unsignedWire();
  const wrongDomainSig = await signWithEnvelope('svrnty:not-a-note:v9', noteSigningInput(w), alicePriv, alicePass);
  const forged: NoteWireV0 = { ...w, public_key: alicePub, signature: wrongDomainSig };
  assert.equal(await verifyNoteSender(forged), false);
});

// ── the integration point: verify happens BEFORE admit ────────────────────────────────────────

test('acceptInboundNote DROPS a forged note even when isAdmitted() returns true', async () => {
  const forged = await signNoteWire(
    unsignedWire({ from_fingerprint: aliceFp }),
    malloryPub,
    malloryPriv,
    malloryPass,
  );
  // admission cannot rescue a forgery — the authenticate gate runs first, so this returns null
  // WITHOUT ever reaching the note store.
  const result = await acceptInboundNote({ wire: forged, isAdmitted: async () => true });
  assert.equal(result, null);
});

test('acceptInboundNote DROPS an unsigned note even when isAdmitted() returns true', async () => {
  const result = await acceptInboundNote({ wire: unsignedWire(), isAdmitted: async () => true });
  assert.equal(result, null);
});

// ── §5 CANONICAL-ID sender-auth: thread PQ pubkeys → the 64-hex canonical fp recomputes + matches ──

test('CANONICAL sender: a 64-hex canonical note authenticates WHEN the PQ pubkeys are threaded (the §5 fix)', async () => {
  const cid = await makeCanonicalIdentity('canon');
  assert.match(cid.fingerprint, /^[0-9a-f]{64}$/); // 64-hex canonical, NOT a 40-hex OpenPGP fp
  const signed = await signNoteWire(
    unsignedWire({ from_fingerprint: cid.fingerprint }),
    cid.publicKey, cid.privateKey, cid.passphrase, cid.kemPublicKeyB64, cid.sigPublicKeyB64,
  );
  assert.equal(await verifyNoteSender(signed), true);
});

test('CANONICAL sender WITHOUT threaded PQ pubkeys → fail-closed (the pre-fix bug; proves the threading is load-bearing)', async () => {
  const cid = await makeCanonicalIdentity('canon2');
  // Sign classical-only (omit the PQ pubkeys). verifyNoteSender's fingerprintMatchesKey then can't
  // recompute the 64-hex canonical fp → falls to the 40-hex OpenPGP path → 64 !== 40 → refused.
  const signed = await signNoteWire(unsignedWire({ from_fingerprint: cid.fingerprint }), cid.publicKey, cid.privateKey, cid.passphrase);
  assert.equal(await verifyNoteSender(signed), false);
});

test('CANONICAL sender with a WRONG-LENGTH kem → rejected at the boundary (§5 defense-in-depth, fail-loud)', async () => {
  const cid = await makeCanonicalIdentity('canon3');
  const signed = await signNoteWire(
    unsignedWire({ from_fingerprint: cid.fingerprint }),
    cid.publicKey, cid.privateKey, cid.passphrase, cid.kemPublicKeyB64, cid.sigPublicKeyB64,
  );
  // Truncate the kem to 40 base64 chars (~30 bytes, not 1568). The PQ pubkeys are EXCLUDED from the note
  // preimage (unsigned), so this doesn't touch the signature — verifyNoteSender's length-guard rejects it.
  const tampered: NoteWireV0 = { ...signed, pq_kem_public_key: signed.pq_kem_public_key!.slice(0, 40) };
  assert.equal(await verifyNoteSender(tampered), false);
});

test('SATELLITE-SAFE: PQ pubkeys are EXCLUDED from noteSigningInput — a canonical note verifies, and the signed preimage is independent of the attached pq (so the satellite verifies the sig without pq)', async () => {
  // Post-res1 the identity is canonical, but the satellite-safe property is unchanged and load-bearing:
  // pq_kem/pq_sig are NOT part of the signed bytes (noteSigningInput). The satellite verifies the note
  // signature WITHOUT the pq pubkeys; they're carried only so the RECEIVER can recompute the 64-hex fp.
  // Sign a canonical note (pq forwarded for the fp-match, NOT for the preimage), then prove directly that
  // noteSigningInput does not depend on the pq pubkeys' presence or value.
  const cid = await makeCanonicalIdentity('sat');
  const signed = await signNoteWire(
    unsignedWire({ from_fingerprint: cid.fingerprint }),
    cid.publicKey, cid.privateKey, cid.passphrase, cid.kemPublicKeyB64, cid.sigPublicKeyB64,
  );
  assert.equal(await verifyNoteSender(signed), true);
  const base = noteSigningInput(signed);
  assert.equal(
    noteSigningInput({ ...signed, pq_kem_public_key: undefined, pq_sig_public_key: undefined }),
    base, 'pq pubkeys must be EXCLUDED from noteSigningInput (satellite verifies without them)',
  );
  assert.equal(
    noteSigningInput({ ...signed, pq_kem_public_key: 'ZZZZ', pq_sig_public_key: 'ZZZZ' }),
    base, 'noteSigningInput must not depend on the pq pubkey values',
  );
});
