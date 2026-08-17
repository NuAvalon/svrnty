// 0.9 invariant floor for 0.4 contact.update consume — the E2E-invariant made executable.
// Run: npx tsx --test src/lib/trust/contact-update.test.ts
//
// What this suite proves (maps to shared/outbox/flint/svrnty_master_spec_security_invariants.md §S1):
//   • THE FLOOR (Archie #115561): once-signed-never-unsigned. Every consume-path that would skip or
//     fail a check throws LOUDLY — the only success is a fully-verified return. No silent-false path.
//   • I-7 tamper-evidence: any mutation of a signed field fails verification.
//   • I-4 reachability-not-location / I-6 render-provenance: the field firewall refuses a location or
//     presence/last_seen field even under a valid signature.
//   • Inherited from the 0.1 primitive (we delegate, never re-implement): domain-separation (a
//     signature for another object type cannot verify here) and anti-downgrade (stripping the PQ half
//     of a hybrid signature fails).
//   • Replay/rollback: a version <= last-seen is dropped BEFORE any crypto (DoS-resistant ordering).
//
// Out of scope HERE (relay-side / other lanes, noted so the gap is explicit, not silent):
//   I-1/I-2 constant-shape+timing live in the satellite relay (Athena's satellite.py D2 leaks);
//   I-3 no-aggregate is architectural; I-5 recovery-soundness lives in crypto/recovery.ts.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKey, readKey } from 'openpgp';
import { signWithEnvelope } from '../crypto/sign-envelope';
import {
  DOMAIN_CONTACT_UPDATE,
  DOMAIN_TRUST_SIGNAL,
  contactUpdateSigningInput,
  type ContactUpdateEnvelope,
} from '../format/envelope';
import { generateSigningKeypair, type PQSigningKeypair } from '../crypto/pq';
import {
  verifyIncomingContactUpdate,
  ContactUpdateRejected,
  CONTACT_UPDATE_ALLOWED_FIELDS,
  type ContactUpdateRejectReason,
  type KnownContactIdentity,
  type SignedContactUpdate,
} from './contact-update';

const passphrase = 'test-passphrase-0';
const otherPass = 'test-passphrase-1';

// Keygen is expensive → generate once in before() (mirrors signals-envelope.test.ts).
let privateKey: string, publicKey: string, fingerprint: string;
let otherPriv: string, otherPub: string, otherFingerprint: string;
let pq: PQSigningKeypair;

before(async () => {
  ({ privateKey, publicKey } = await generateKey({
    type: 'curve25519',
    userIDs: [{ name: 'Alice', email: 'alice@example.test' }],
    passphrase,
    format: 'armored',
  }));
  fingerprint = (await readKey({ armoredKey: publicKey })).getFingerprint();
  pq = generateSigningKeypair(); // ML-DSA-87 { publicKey, secretKey }

  ({ privateKey: otherPriv, publicKey: otherPub } = await generateKey({
    type: 'curve25519',
    userIDs: [{ name: 'Mallory', email: 'm@example.test' }],
    passphrase: otherPass,
    format: 'armored',
  }));
  otherFingerprint = (await readKey({ armoredKey: otherPub })).getFingerprint();
});

function baseEnv(o: Partial<ContactUpdateEnvelope> = {}): ContactUpdateEnvelope {
  return {
    fingerprint,
    epoch: 1,
    version: 1,
    updated_at: '2026-08-17T00:00:00Z',
    changed_fields: ['display_name'],
    delta: { display_name: 'Alice Quinn' },
    ...o,
  };
}

function known(o: Partial<KnownContactIdentity> = {}): KnownContactIdentity {
  return { fingerprint, epoch: 1, version: 0, classicalPublicKeyArmored: publicKey, ...o };
}

async function signAs(
  env: ContactUpdateEnvelope,
  priv = privateKey,
  pass = passphrase,
  pqSecret?: Uint8Array,
): Promise<SignedContactUpdate> {
  const signature = await signWithEnvelope(DOMAIN_CONTACT_UPDATE, contactUpdateSigningInput(env), priv, pass, pqSecret);
  return { envelope: env, signature };
}

const rejectsWith =
  (reason: ContactUpdateRejectReason) =>
  (e: unknown): boolean =>
    e instanceof ContactUpdateRejected && e.reason === reason;

// ── Happy path ────────────────────────────────────────────────────────────────
test('valid contact.update verifies and returns the declared delta', async () => {
  const v = await verifyIncomingContactUpdate(await signAs(baseEnv()), known());
  assert.equal(v.fingerprint, fingerprint);
  assert.equal(v.version, 1);
  assert.deepEqual(v.changed_fields, ['display_name']);
  assert.deepEqual(v.delta, { display_name: 'Alice Quinn' });
});

// ── The floor: unsigned / malformed fails loud ─────────────────────────────────
test('FLOOR: an unsigned (no classical) blob is rejected malformed', async () => {
  const bad = { envelope: baseEnv(), signature: {} } as unknown as SignedContactUpdate;
  await assert.rejects(verifyIncomingContactUpdate(bad, known()), rejectsWith('malformed'));
});

test('FLOOR: a non-object payload is rejected malformed', async () => {
  await assert.rejects(
    verifyIncomingContactUpdate(null as unknown as SignedContactUpdate, known()),
    rejectsWith('malformed'),
  );
});

// ── I-7 tamper-evidence ────────────────────────────────────────────────────────
test('I-7: tampering the delta after signing fails bad-signature', async () => {
  const s = await signAs(baseEnv());
  s.envelope.delta.display_name = 'Mallory'; // mutate post-signature
  await assert.rejects(verifyIncomingContactUpdate(s, known()), rejectsWith('bad-signature'));
});

test('I-7: bumping version after signing (still monotonic) fails bad-signature', async () => {
  const s = await signAs(baseEnv({ version: 5 }));
  s.envelope.version = 6; // 6 > known.version(0) so monotonic passes; signature was over 5 → fails
  await assert.rejects(verifyIncomingContactUpdate(s, known()), rejectsWith('bad-signature'));
});

// ── Attribution ────────────────────────────────────────────────────────────────
test('attribution: envelope.fingerprint != known is rejected wrong-origin (before crypto)', async () => {
  const s = await signAs(baseEnv({ fingerprint: otherFingerprint }));
  await assert.rejects(verifyIncomingContactUpdate(s, known()), rejectsWith('wrong-origin'));
});

test('attribution: a signature by a different key fails bad-signature', async () => {
  const s = await signAs(baseEnv(), otherPriv, otherPass); // Mallory signs a card claiming Alice's fp
  await assert.rejects(verifyIncomingContactUpdate(s, known()), rejectsWith('bad-signature'));
});

// ── Domain separation (inherited from the 0.1 primitive) ───────────────────────
test('domain separation: a trust-signal signature does not verify as a contact.update', async () => {
  const env = baseEnv();
  // Same canonical bytes, but signed under the WRONG domain tag.
  const signature = await signWithEnvelope(DOMAIN_TRUST_SIGNAL, contactUpdateSigningInput(env), privateKey, passphrase);
  await assert.rejects(verifyIncomingContactUpdate({ envelope: env, signature }, known()), rejectsWith('bad-signature'));
});

// ── Replay / rollback: monotonic version, BEFORE any crypto ────────────────────
test('replay: version <= last-seen is rejected stale-version even with a valid signature', async () => {
  const s = await signAs(baseEnv({ version: 3 }));
  await assert.rejects(verifyIncomingContactUpdate(s, known({ version: 3 })), rejectsWith('stale-version'));
});

test('ordering: stale-version wins over a garbage signature (no crypto spent on a rollback)', async () => {
  const bad = { envelope: baseEnv({ version: 1 }), signature: { classical: 'not-a-signature' } };
  await assert.rejects(verifyIncomingContactUpdate(bad, known({ version: 9 })), rejectsWith('stale-version'));
});

// ── Epoch lineage ──────────────────────────────────────────────────────────────
test('epoch: a regressed epoch is rejected epoch-regression', async () => {
  const s = await signAs(baseEnv({ epoch: 1 }));
  await assert.rejects(verifyIncomingContactUpdate(s, known({ epoch: 2 })), rejectsWith('epoch-regression'));
});

test('epoch: an ahead epoch is rejected epoch-ahead-needs-lineage (not accepted blind)', async () => {
  const s = await signAs(baseEnv({ epoch: 2 }));
  await assert.rejects(verifyIncomingContactUpdate(s, known({ epoch: 1 })), rejectsWith('epoch-ahead-needs-lineage'));
});

// ── I-4 / I-6 field firewall ────────────────────────────────────────────────────
// The firewall fires BEFORE any crypto, so these need no valid signature — a dummy classical part is
// enough, and using one proves the field is refused regardless of whether it was "correctly" signed.
test('I-6: a last_seen/presence field is refused (field-not-allowed), pre-crypto', async () => {
  const env = baseEnv({ changed_fields: ['display_name', 'last_seen'], delta: { display_name: 'A', last_seen: 'now' } });
  const s = { envelope: env, signature: { classical: 'unused' } };
  await assert.rejects(verifyIncomingContactUpdate(s, known()), rejectsWith('field-not-allowed'));
});

test('I-4: a device-location field is refused (field-not-allowed), pre-crypto', async () => {
  const env = baseEnv({ changed_fields: ['location'], delta: { location: { lat: 51.5, lng: -0.12 } } });
  const s = { envelope: env, signature: { classical: 'unused' } };
  await assert.rejects(verifyIncomingContactUpdate(s, known()), rejectsWith('field-not-allowed'));
});

// ── Spartan allowlist (Archie #115574 D1=SHRINK; joint verify↔apply pass with Athena's 0.14 apply) ──
// The allowlist is the SHARED verify↔apply contract. It must equal EXACTLY {display_name, note,
// emails}; the same set is re-asserted on the apply side (apply-contact-update.ts:105) and the
// merge-guard cross-checks them post-merge. This test is the verify-side half of that divergence guard.
// Fields that used to be allowlisted (rich vCard set) or that moved to their own signed object type
// (public_key→key.rotate, routing→routing.update) are now refused by the firewall pre-crypto — a
// contact.update can no longer carry them.
test('shrink: the allowlist is EXACTLY the spartan set {display_name, note, emails}', () => {
  assert.deepEqual([...CONTACT_UPDATE_ALLOWED_FIELDS].sort(), ['display_name', 'emails', 'note']);
});

test('shrink: public_key is refused field-not-allowed (moved to key.rotate — not a card field)', async () => {
  const env = baseEnv({ changed_fields: ['public_key'], delta: { public_key: 'AAAA' } });
  const s = { envelope: env, signature: { classical: 'unused' } };
  await assert.rejects(verifyIncomingContactUpdate(s, known()), rejectsWith('field-not-allowed'));
});

test('shrink: routing is refused field-not-allowed (moved to routing.update — not a card field)', async () => {
  const env = baseEnv({ changed_fields: ['routing'], delta: { routing: ['relay://x'] } });
  const s = { envelope: env, signature: { classical: 'unused' } };
  await assert.rejects(verifyIncomingContactUpdate(s, known()), rejectsWith('field-not-allowed'));
});

test('shrink: a rich vCard field (org) is refused field-not-allowed (grow-later, no producer yet)', async () => {
  const env = baseEnv({ changed_fields: ['org'], delta: { org: 'Acme' } });
  const s = { envelope: env, signature: { classical: 'unused' } };
  await assert.rejects(verifyIncomingContactUpdate(s, known()), rejectsWith('field-not-allowed'));
});

test('retained: note + emails still verify end-to-end (the spartan set is functional)', async () => {
  const env = baseEnv({
    changed_fields: ['note', 'emails'],
    delta: { note: 'met at the equinox', emails: ['alice@example.test', 'a@alt.test'] },
  });
  const v = await verifyIncomingContactUpdate(await signAs(env), known());
  assert.deepEqual(v.changed_fields, ['note', 'emails']);
  assert.deepEqual(v.delta, { note: 'met at the equinox', emails: ['alice@example.test', 'a@alt.test'] });
});

// ── Honest manifest: changed_fields must equal delta's keys ─────────────────────
test('smuggling: a delta key not declared in changed_fields is rejected undeclared-delta-field', async () => {
  const env = baseEnv({ changed_fields: ['display_name'], delta: { display_name: 'A', emails: ['x@y.z'] } });
  await assert.rejects(verifyIncomingContactUpdate(await signAs(env), known()), rejectsWith('undeclared-delta-field'));
});

test('honesty: a declared field missing from delta is rejected declared-field-missing', async () => {
  const env = baseEnv({ changed_fields: ['display_name', 'emails'], delta: { display_name: 'A' } });
  await assert.rejects(verifyIncomingContactUpdate(await signAs(env), known()), rejectsWith('declared-field-missing'));
});

// ── PQ suite floor + anti-downgrade (inherited) ─────────────────────────────────
test('hybrid: a PQ-signed update verifies with the PQ public key', async () => {
  const s = await signAs(baseEnv(), privateKey, passphrase, pq.secretKey);
  const v = await verifyIncomingContactUpdate(s, known({ pqSigningPublicKey: pq.publicKey }), { requirePq: true });
  assert.equal(v.version, 1);
});

test('requirePq: a classical-only signature is rejected pq-required', async () => {
  const s = await signAs(baseEnv()); // classical only
  await assert.rejects(
    verifyIncomingContactUpdate(s, known({ pqSigningPublicKey: pq.publicKey }), { requirePq: true }),
    rejectsWith('pq-required'),
  );
});

test('anti-downgrade: stripping the PQ half of a hybrid signature fails bad-signature', async () => {
  const s = await signAs(baseEnv(), privateKey, passphrase, pq.secretKey);
  delete s.signature.pq_signature; // downgrade attempt: flips derived suite → classical sig no longer matches
  await assert.rejects(
    verifyIncomingContactUpdate(s, known({ pqSigningPublicKey: pq.publicKey })),
    rejectsWith('bad-signature'),
  );
});
