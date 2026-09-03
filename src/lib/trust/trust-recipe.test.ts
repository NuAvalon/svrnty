import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  buildOwnerVerifyMeta,
  canGrantTrust,
  formatFingerprintForVerify,
  GROW_INVITE_CAP,
  ownerHasVerified,
  ownerVerifyPersistPatch,
  stripOwnerLocalForPublish,
  TRUST_RECIPE_COPY,
} from './trust-recipe';

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
  assert.equal(
    ownerHasVerified({
      verification: { method: 'in_person', verified_at: '2026-01-01T00:00:00.000Z' },
    }),
    true,
  );
});

test('owner_verify meta unlocks trust; already-trusted skips', () => {
  const meta = buildOwnerVerifyMeta({}, 'in_person');
  assert.equal(ownerHasVerified({ metadata: meta }), true);
  assert.deepEqual(canGrantTrust({ metadata: meta, trusted: false }), { ok: true });
  assert.deepEqual(canGrantTrust({ trusted: true }), { ok: true });
});

test('persist patch is owner-local only — no public verification field', () => {
  const patch = ownerVerifyPersistPatch({ notes: 'stay' }, 'other_channel');
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
