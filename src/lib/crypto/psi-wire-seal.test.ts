// src/lib/crypto/psi-wire-seal.test.ts
// Adversarial co-verify reference for the PSI wire-seal (joint build: Apollo client-half ↔ Athena satellite
// decap). Each test refutes a property that PROTECTS the person, not "the seal runs":
//   - a wire harvester gets only ML-KEM ciphertext (HNDL-safe), NOT the blinded points   [Peter's gate]
//   - the SATELLITE (holding its secret) CAN recover the blinded set to relay it           [relay still works]
//   - a WRONG key (or a non-satellite) CANNOT open it                                       [sealed-to-satellite]
//   - a tampered / malformed envelope opens to null, never throws                           [fail-closed]
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  sealPsiToSatellite,
  openPsiFromSatellite,
  newPsiSessionKey,
  openPsiSessionResponse,
  verifySatelliteKey,
  PINNED_SATELLITE_MAILBOX_FP_DEV,
} from './psi-wire-seal.js';
import {
  generateMailboxKeypair,
  toPublicKeys,
  toSecretKeys,
  mailboxFpOf,
} from './mailbox-keys.js';

// A representative PSI initiate body: the X25519-blinded trusted-contact set + session fields.
const SAMPLE_PSI_BODY = {
  blinded_set: [
    'YmxpbmRlZF9wb2ludF9vbmVfYmFzZTY0AAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    'YmxpbmRlZF9wb2ludF90d29fYmFzZTY0AAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  ],
  initiator_ephemeral_pub: 'ZXBoZW1lcmFsX3B1Yl9iYXNlNjQAAAAAAAAAAAAAAAAAAAAAAAA=',
};

test('(gate) a wire harvester gets only ML-KEM ciphertext — the blinded points are NOT on the wire', async () => {
  const satellite = generateMailboxKeypair();
  const pkg = await sealPsiToSatellite(SAMPLE_PSI_BODY, toPublicKeys(satellite));

  // The envelope that leaves the device carries no cleartext blinded point.
  const wire = JSON.stringify(pkg);
  for (const point of SAMPLE_PSI_BODY.blinded_set) {
    assert.ok(!wire.includes(point), 'a blinded point must not appear in cleartext on the wire');
  }
  // POSITIVE CONTROL: the UNWRAPPED path (today's plain JSON) DOES leak the points — proves the test can fail.
  const plainWire = JSON.stringify(SAMPLE_PSI_BODY);
  assert.ok(plainWire.includes(SAMPLE_PSI_BODY.blinded_set[0]!), 'control: plain JSON leaks the blinded point');
  // The envelope is hybrid (has an ML-KEM ciphertext leg) — not a classical-only wrap.
  assert.ok(typeof pkg.kem_ct === 'string' && pkg.kem_ct.length > 0, 'envelope carries an ML-KEM-1024 ciphertext');
});

test('(relay) the SATELLITE decaps and recovers the blinded set EXACTLY — relay still works', async () => {
  const satellite = generateMailboxKeypair();
  const pkg = await sealPsiToSatellite(SAMPLE_PSI_BODY, toPublicKeys(satellite));

  // Satellite-side: open with the satellite's own secrets (this is Athena's decap, mirrored here).
  const recovered = await openPsiFromSatellite(pkg, toSecretKeys(satellite), mailboxFpOf(satellite));
  assert.deepEqual(recovered, SAMPLE_PSI_BODY, 'satellite recovers the blinded set byte-for-byte to relay it');
});

test('(response) satellite seals the result to the CLIENT key; client opens it; a wire harvester cannot', async () => {
  const client = generateMailboxKeypair();
  const result = { reblinded_initiator_set: SAMPLE_PSI_BODY.blinded_set, responder_blinded_set: [], session_id: 'sess_abc' };

  // Satellite-side: seal the PSI result to the requesting client's mailbox key.
  const pkg = await sealPsiToSatellite(result, toPublicKeys(client));
  const wire = JSON.stringify(pkg);
  assert.ok(!wire.includes('sess_abc'), 'response session id is not cleartext on the wire');

  // Client opens with its own secrets.
  const opened = await openPsiFromSatellite(pkg, toSecretKeys(client), mailboxFpOf(client));
  assert.deepEqual(opened, result, 'client recovers the PSI result');
});

test('(sealed-to-satellite) a WRONG recipient cannot open the request — null, not throw', async () => {
  const satellite = generateMailboxKeypair();
  const attacker = generateMailboxKeypair();
  const pkg = await sealPsiToSatellite(SAMPLE_PSI_BODY, toPublicKeys(satellite));

  // Attacker with its own keys (and even the satellite's fp label) cannot open.
  assert.equal(await openPsiFromSatellite(pkg, toSecretKeys(attacker), mailboxFpOf(satellite)), null);
  assert.equal(await openPsiFromSatellite(pkg, toSecretKeys(attacker), mailboxFpOf(attacker)), null);
});

test('(fail-closed) a tampered or malformed envelope opens to null, never throws', async () => {
  const satellite = generateMailboxKeypair();
  const pkg = await sealPsiToSatellite(SAMPLE_PSI_BODY, toPublicKeys(satellite));

  // Flip a byte in the ciphertext → AEAD tag fails → null.
  const tampered = { ...pkg, ct: pkg.ct.slice(0, -4) + (pkg.ct.endsWith('A') ? 'B' : 'A') + pkg.ct.slice(-3) };
  assert.equal(await openPsiFromSatellite(tampered, toSecretKeys(satellite), mailboxFpOf(satellite)), null);

  // Structurally malformed packages → null, no throw.
  for (const bad of [{}, { v: 1 }, null, { ...pkg, kem_ct: 'not-base64!!' }]) {
    assert.equal(
      await openPsiFromSatellite(bad as never, toSecretKeys(satellite), mailboxFpOf(satellite)),
      null,
      'malformed envelope → null',
    );
  }
});

test('(non-json) a decrypt that yields non-JSON bytes returns null, not a throw', async () => {
  const satellite = generateMailboxKeypair();
  // Seal raw non-JSON bytes via the underlying primitive, then try to open-as-PSI.
  const { sealToMailbox } = await import('./mailbox-envelope.js');
  const pkg = await sealToMailbox(new TextEncoder().encode('\x00\x01not-json'), toPublicKeys(satellite));
  assert.equal(await openPsiFromSatellite(pkg, toSecretKeys(satellite), mailboxFpOf(satellite)), null);
});

// ════════════════════════════════════════════════════════════════════════
// EPHEMERAL SESSION KEY — the satellite seals responses to a fresh per-session key (forward secrecy).
// ════════════════════════════════════════════════════════════════════════
test('(session) satellite seals a GET response to the ephemeral session key; the client opens it', async () => {
  const session = newPsiSessionKey();
  // Satellite-side: reconstruct the client's ephemeral pub from what rode in the sealed body, seal the result.
  const clientPub = {
    x25519Pub: Buffer.from(session.responsePub.x25519_pub_b64, 'base64'),
    mlkem1024Pub: Buffer.from(session.responsePub.mlkem1024_pub_b64, 'base64'),
  };
  const result = { responder_blinded_set: ['Zm9v', 'YmFy'], session_id: 'sess_xyz' };
  const pkg = await sealPsiToSatellite(result, clientPub);

  const opened = await openPsiSessionResponse(pkg, session);
  assert.deepEqual(opened, result, 'client opens the response with its ephemeral session secret');
});

test('(session-fs) a DIFFERENT session key cannot open another session\'s response', async () => {
  const a = newPsiSessionKey();
  const b = newPsiSessionKey();
  const clientPubA = {
    x25519Pub: Buffer.from(a.responsePub.x25519_pub_b64, 'base64'),
    mlkem1024Pub: Buffer.from(a.responsePub.mlkem1024_pub_b64, 'base64'),
  };
  const pkg = await sealPsiToSatellite({ session_id: 'a' }, clientPubA);
  assert.deepEqual(await openPsiSessionResponse(pkg, a), { session_id: 'a' }, 'the right session opens it');
  assert.equal(await openPsiSessionResponse(pkg, b), null, 'a different session key cannot (blast-radius isolation)');
});

// ════════════════════════════════════════════════════════════════════════
// S4 ANTI-SWAP SATELLITE KEY — the client rejects a swapped GET /satellite/key.
// ════════════════════════════════════════════════════════════════════════
test('(s4) the pinned satellite key verifies; a SWAPPED key is REJECTED (null)', async () => {
  // Model the real satellite as a keypair; pin ITS fp; a swapped key has a different fp.
  const satellite = generateMailboxKeypair();
  const pin = mailboxFpOf(satellite);
  const swapped = generateMailboxKeypair(); // attacker's key — self-consistent fp, but != pin

  // Honest key under its own pin → accepted, returns the pubkeys to seal to.
  const ok = verifySatelliteKey(satellite.x25519Pub, satellite.mlkem1024Pub, pin);
  assert.ok(ok && ok.x25519Pub.length === 32 && ok.mlkem1024Pub.length === 1568, 'pinned key accepted');

  // Swapped key (different, self-consistent) under the honest pin → REJECTED. This is the S4 gate.
  assert.equal(verifySatelliteKey(swapped.x25519Pub, swapped.mlkem1024Pub, pin), null, 'swapped key rejected');

  // Wrong-length inputs → rejected, never throws.
  assert.equal(verifySatelliteKey(new Uint8Array(31), satellite.mlkem1024Pub, pin), null);
  assert.equal(verifySatelliteKey(satellite.x25519Pub, new Uint8Array(1567), pin), null);
});

test('(s4) the exported dev pin is the expected satellite mailbox_fp', () => {
  assert.equal(
    PINNED_SATELLITE_MAILBOX_FP_DEV,
    '746ba505b57221e7f149125b3f41f081a1d3befdbdeee49030219f06ed43a03c',
    'dev pin matches the deployed GET /satellite/key fp',
  );
});
