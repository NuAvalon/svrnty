import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildOwnerVerifyMeta,
  canGrantTrust,
  currentFingerprintOf,
  formatFingerprintForVerify,
  GROW_INVITE_CAP,
  ownerHasVerified,
  ownerVerifyPersistPatch,
  stripOwnerLocalForPublish,
  trustGrantRefused,
  TRUST_RECIPE_COPY,
} from './trust-recipe';

const FP_A = 'a'.repeat(64);
const FP_B = 'b'.repeat(64);

test('trust requires owner-local verify; unverified cannot grant', () => {
  assert.equal(ownerHasVerified({ verification: { method: 'none', verified_at: null } }), false);
  assert.deepEqual(canGrantTrust({ trusted: false }), { ok: false, reason: 'need-verify' });
});

test('email/QR verification is not the private ritual', () => {
  assert.equal(
    ownerHasVerified({ verification: { method: 'email', verified_at: '2026-01-01T00:00:00.000Z' } }),
    false,
  );
  assert.equal(
    ownerHasVerified({ verification: { method: 'qr', verified_at: '2026-01-01T00:00:00.000Z' } }),
    false,
  );
  // The old `verification` record says nothing about WHICH key was checked, so it no longer counts for a Trust grant.
  assert.equal(
    ownerHasVerified({
      fingerprint: FP_A,
      verification: { method: 'in_person', verified_at: '2026-01-01T00:00:00.000Z' },
    }),
    false,
  );
});

test('owner_verify meta unlocks trust for the key it was written for; already-trusted skips', () => {
  const meta = buildOwnerVerifyMeta({}, 'in_person', FP_A);
  assert.equal(ownerHasVerified({ fingerprint: FP_A, metadata: meta }), true);
  assert.deepEqual(canGrantTrust({ fingerprint: FP_A, metadata: meta, trusted: false }), { ok: true });
  assert.deepEqual(canGrantTrust({ trusted: true }), { ok: true });
});

test('persist patch is owner-local only — no public verification field', () => {
  const patch = ownerVerifyPersistPatch({ notes: 'stay' }, 'other_channel', FP_A);
  assert.equal(patch.owner_verify.method, 'other_channel');
  assert.ok(patch.owner_verify.owner_verified_at);
  assert.equal((patch as { verification?: unknown }).verification, undefined);
  assert.equal((patch.metadata as { notes?: string }).notes, 'stay');
});

test('verified is not a publish field — strip owner_verify / notes / tags', () => {
  const payload = {
    fingerprint: 'aa',
    owner_verify: { owner_verified_at: 'x', method: 'in_person' },
    metadata: { owner_verify: { owner_verified_at: 'x', method: 'in_person' }, notes: 'bro', tags: ['x'] },
  };
  const stripped = stripOwnerLocalForPublish(payload);
  assert.equal('owner_verify' in stripped, false);
  const m = stripped.metadata as Record<string, unknown>;
  assert.equal('owner_verify' in m, false);
  assert.equal('notes' in m, false);
  assert.equal('tags' in m, false);
  assert.equal(stripped.fingerprint, 'aa');
});

test('#255: owner-local share_settings (known_visibility/per_contact_private/open_visibility) NEVER rides the wire', () => {
  const payload = {
    fingerprint: 'bb',
    metadata: {
      share_settings: { open_visibility: true, known_visibility: true, per_contact_private: true },
      notes: 'keep-local',
    },
  };
  const stripped = stripOwnerLocalForPublish(payload);
  const m = stripped.metadata as Record<string, unknown>;
  // fail-closed: the whole owner-local container is dropped, not field-by-field
  assert.equal('share_settings' in m, false);
  // negative control: a crafted known_visibility survives to ZERO bytes outbound (anywhere)
  const wire = JSON.stringify(stripped);
  assert.equal(wire.includes('known_visibility'), false, 'known_visibility must not appear on the wire');
  assert.equal(wire.includes('per_contact_private'), false, 'per_contact_private (owner-local) must not leak either');
  assert.equal(stripped.fingerprint, 'bb');
});

test('fingerprint grouping is for compare-aloud, not a score', () => {
  const fp = formatFingerprintForVerify('aabbccddeeff0011');
  assert.match(fp, /AABB CCDD EEFF 0011/);
  assert.equal(GROW_INVITE_CAP, 7);
});

test('gate doors are Start and Continue', () => {
  assert.equal(TRUST_RECIPE_COPY.gateStart, 'Start');
  assert.equal(TRUST_RECIPE_COPY.gateContinue, 'Continue');
});

test('verify poetry is the name couplet', () => {
  assert.equal(TRUST_RECIPE_COPY.verifyWhy, "Anyone can use my name. They can't forge this key.");
  assert.equal(TRUST_RECIPE_COPY.helpTitle, 'The Formula');
  assert.match(TRUST_RECIPE_COPY.verifyConfirm, /scanned this from their phone/i);
});

test('growHint: in-person can be a star; remote waits at the Gate', () => {
  assert.match(TRUST_RECIPE_COPY.growHint, /In person/);
  assert.match(TRUST_RECIPE_COPY.growHint, /Gate/);
  assert.match(TRUST_RECIPE_COPY.growHint, /later tap/);
});

test('recovery copy: give is present-tense honest, round-trip is Coming, constants kept', () => {
  assert.equal(TRUST_RECIPE_COPY.recoveryTitle, 'Recovery');
  // recoverySelect claims only the LIVE give (Shamir), not the recover round-trip
  assert.match(TRUST_RECIPE_COPY.recoverySelect, /Give someone you Trust a piece/);
  assert.match(TRUST_RECIPE_COPY.recoveryComing, /^Coming:/);
  // Unmounted-half constants kept (for when the UI wires up); just not rendered in beta Help
  assert.match(TRUST_RECIPE_COPY.recoveryRotate, /Rotate Guardians/);
  assert.match(TRUST_RECIPE_COPY.recoverySeed, /Change Seed/);
  assert.match(TRUST_RECIPE_COPY.recoveryPassword, /Change Password/);
  assert.match(TRUST_RECIPE_COPY.recoveryDistress, /silent cry/i);
});

test('bottom manifesto is keep / never give away', () => {
  assert.match(TRUST_RECIPE_COPY.manifestoKeep, /never lose it/i);
  assert.match(TRUST_RECIPE_COPY.manifestoKeep, /never give it away/i);
  assert.equal(TRUST_RECIPE_COPY.manifestoCloser, 'you are not a product');
  assert.match(TRUST_RECIPE_COPY.manifestoAxes, /post-quantum/);
  assert.match(TRUST_RECIPE_COPY.manifestoAxes, /local-first/);
  assert.match(TRUST_RECIPE_COPY.manifestoAxes, /social-recovery/);
});

// ── a stamp is bound to the key it was written for ──────────────────────────────────────────────────────────────────────────────────────

test('a stamp counts only for the fingerprint it was written for: the same key passes, another key, another length or none does not', () => {
  const stamp = ownerVerifyPersistPatch({}, 'in_person', FP_A).owner_verify;
  assert.equal(stamp.fingerprint, FP_A);
  assert.equal(ownerHasVerified({ fingerprint: FP_A, owner_verify: stamp }), true);
  assert.equal(ownerHasVerified({ fingerprint: FP_B, owner_verify: stamp }), false, 'a stamp for another key');
  assert.equal(ownerHasVerified({ fingerprint: FP_A.slice(0, 40), owner_verify: stamp }), false, 'length-strict');
  assert.equal(ownerHasVerified({ owner_verify: stamp }), false, 'no current fingerprint to compare with: fail closed');
  assert.equal(ownerHasVerified({ fingerprint: '', owner_verify: stamp }), false);
  assert.equal(ownerHasVerified({ fingerprint: FP_A.toUpperCase(), owner_verify: stamp }), true, 'compared lowercase');
});

test('a stamp is found the same way on the edge shape (peer_fingerprint) and in metadata', () => {
  const meta = buildOwnerVerifyMeta({}, 'other_channel', FP_A);
  assert.equal(ownerHasVerified({ peer_fingerprint: FP_A, metadata: meta }), true);
  assert.equal(ownerHasVerified({ peer_fingerprint: FP_B, metadata: meta }), false);
});

test('a LEGACY stamp (no fingerprint) never counts for a new grant, whatever key the record holds now', () => {
  const legacyTop = { owner_verified_at: '2026-01-01T00:00:00.000Z', method: 'in_person' as const };
  assert.equal(ownerHasVerified({ fingerprint: FP_A, owner_verify: legacyTop }), false);
  assert.equal(ownerHasVerified({ fingerprint: FP_A, metadata: { owner_verify: legacyTop } }), false);
  assert.deepEqual(canGrantTrust({ fingerprint: FP_A, owner_verify: legacyTop, trusted: false }), { ok: false, reason: 'need-verify' });
});

test('NEG: nothing back-fills a fingerprint into a legacy stamp: the recipe\'s own copies leave it as it was', () => {
  const legacy = { owner_verified_at: '2026-01-01T00:00:00.000Z', method: 'in_person' as const };
  const before = JSON.stringify(legacy);
  // The stamp builder works from the metadata it is given and must not touch an existing legacy stamp of another record.
  buildOwnerVerifyMeta({ other: 1, owner_verify: legacy }, 'in_person', FP_B);
  assert.equal(JSON.stringify(legacy), before, 'the legacy object is not mutated');
  const stripped = stripOwnerLocalForPublish({ fingerprint: FP_A, owner_verify: legacy });
  assert.equal('owner_verify' in stripped, false);
  assert.equal(ownerHasVerified({ fingerprint: FP_A, owner_verify: legacy }), false, 'and it still does not count');
});

test('the writer refuses a stamp without the fingerprint it is for, and stores it lowercase', () => {
  for (const bad of ['', '   ', undefined, null] as unknown[]) {
    assert.throws(() => ownerVerifyPersistPatch({}, 'in_person', bad as string), /fingerprint/);
    assert.throws(() => buildOwnerVerifyMeta({}, 'in_person', bad as string), /fingerprint/);
  }
  const stamp = ownerVerifyPersistPatch({}, 'in_person', FP_A.toUpperCase()).owner_verify;
  assert.equal(stamp.fingerprint, FP_A);
  assert.equal((ownerVerifyPersistPatch({}, 'in_person', FP_A).metadata.owner_verify as { fingerprint: string }).fingerprint, FP_A);
});

test('the stamp, with its fingerprint, is still never a publish field', () => {
  const stamp = ownerVerifyPersistPatch({}, 'in_person', FP_A);
  const stripped = stripOwnerLocalForPublish({ owner_verify: stamp.owner_verify, metadata: stamp.metadata });
  assert.equal('owner_verify' in stripped, false);
  assert.equal(JSON.stringify(stripped).includes(FP_A), false, 'the fingerprint rides inside the stamp and goes with it');
});

// ── the ONE decision both store sinks make ───────────────────────────────────────────────────────────────────────────────────────────────

test('trustGrantRefused: a GRANT needs a stamp for the current key; everything else passes untouched', () => {
  const bound = ownerVerifyPersistPatch({}, 'in_person', FP_A).owner_verify;
  const other = ownerVerifyPersistPatch({}, 'in_person', FP_B).owner_verify;
  const legacy = { owner_verified_at: '2026-01-01T00:00:00.000Z', method: 'in_person' as const };
  const rec = (o: Record<string, unknown>) => ({ fingerprint: FP_A, ...o });
  // promote / create (was not trusted, is now)
  assert.equal(trustGrantRefused(false, true, rec({ owner_verify: bound })), false, 'a stamp for this key');
  assert.equal(trustGrantRefused(false, true, rec({ metadata: { owner_verify: bound } })), false, 'in metadata too');
  assert.equal(trustGrantRefused(false, true, rec({ owner_verify: other })), true, 'a stamp for another key');
  assert.equal(trustGrantRefused(false, true, rec({ owner_verify: legacy })), true, 'a legacy stamp');
  assert.equal(trustGrantRefused(false, true, rec({ verification: { method: 'in_person', verified_at: 'x' } })), true, 'the old verification record');
  assert.equal(trustGrantRefused(false, true, rec({})), true, 'no stamp at all');
  assert.equal(trustGrantRefused(false, true, { owner_verify: bound }), true, 'no current key to compare with');
  // nothing is revoked or re-checked
  assert.equal(trustGrantRefused(true, true, rec({ owner_verify: legacy })), false, 'a legacy-trusted contact stays trusted when it is saved again');
  assert.equal(trustGrantRefused(true, true, rec({})), false, 'even with no stamp at all');
  assert.equal(trustGrantRefused(true, false, rec({})), false, 'un-trusting always passes');
  assert.equal(trustGrantRefused(false, false, rec({})), false, 'a record that is not trusted is not a grant');
});

// ── keyless demo rows: the store drops their fingerprint, the edge projection falls back to a stand-in ──────────────────────────────────

test('the key a contact is checked against: its fingerprint, else the edge\'s, else the demo stand-in; never its id', () => {
  const standIn = '7e51a00000000000000000000000000000000008';
  assert.equal(currentFingerprintOf({ fingerprint: FP_A, peer_fingerprint: FP_B, metadata: { sample_fingerprint: standIn } }), FP_A);
  assert.equal(currentFingerprintOf({ peer_fingerprint: FP_B, metadata: { sample_fingerprint: standIn } }), FP_B);
  assert.equal(currentFingerprintOf({ metadata: { sample_fingerprint: standIn } }), standIn);
  assert.equal(currentFingerprintOf({ id: 'contact-1', metadata: {} } as never), '', 'an id is not a key');
  assert.equal(currentFingerprintOf({ metadata: { sample_fingerprint: 42 } }), '');
});

test('a keyless demo row is verified against its stand-in: the stamp counts for it, and a real fingerprint always wins over the stand-in', () => {
  const standIn = '7e51a00000000000000000000000000000000008';
  const demo = { metadata: { sample_fingerprint: standIn } as Record<string, unknown> };
  const stamp = ownerVerifyPersistPatch(demo.metadata, 'other_channel', currentFingerprintOf(demo)).owner_verify;
  assert.equal(ownerHasVerified({ ...demo, owner_verify: stamp }), true);
  assert.equal(ownerHasVerified({ metadata: {}, owner_verify: stamp }), false, 'no key at all: nothing to check against');
  assert.equal(ownerHasVerified({ fingerprint: FP_B, metadata: { sample_fingerprint: standIn }, owner_verify: stamp }), false, 'a real fingerprint is not replaced by the stand-in');
  assert.equal(trustGrantRefused(false, true, { ...demo, owner_verify: stamp }), false, 'so a demo row can be trusted after Verify');
});
