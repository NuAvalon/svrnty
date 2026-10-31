// src/lib/trust/discoverable-consent.test.ts
// Run: npx tsx --test src/lib/trust/discoverable-consent.test.ts
//
// Trust-PSI increment #2 (C3) — the subject's own signed "discoverable as trusted" consent.
// Proves: (1) the canonical signing-input is injective (Flint's no-pipe-canon property) + field-
// sensitive; (2) anti-forge — a genuine consent verifies against the subject's key, a forgery by any
// other key does NOT; (3) the edge-store apply is verify-before-set, monotonic-supersede, fail-closed
// (forged / non-contact / unsupported-scope / stale all refuse to write). Real identities via the
// proven headless mint. (Hybrid-suite framing is covered by sign-envelope.test.ts; classical here
// proves the module logic — a wrong key fails regardless of suite.)

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import {
  CONSENT_SCOPE_GLOBAL,
  CONSENT_SCOPE_PER_TRUSTER,
  DISCOVERABLE_FLAG_KEY,
  DISCOVERABLE_EPOCH_KEY,
  discoverableConsentInput,
  signDiscoverableConsent,
  verifyDiscoverableConsent,
  applyDiscoverableConsent,
  type DiscoverableConsent,
  type SignedDiscoverableConsent,
  type DiscoverableConsentContact,
  type DiscoverableConsentStore,
} from './discoverable-consent';

async function signer() {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id: any = a.introduction.card.identity;
  return {
    fp: id.fingerprint as string,
    pub: id.public_key as string,
    priv: a.secret_material.classicalPrivateKey as string,
    kpass: a.secret_material.classicalKpass as string,
  };
}

function consent(subjectFp: string, epoch: number, discoverable: boolean): DiscoverableConsent {
  return { subject_fp: subjectFp, epoch, discoverable, scope_tag: CONSENT_SCOPE_GLOBAL, scope_value: '' };
}

// ── canonical input: injective (no pipe-canon trap) + field-sensitive (pure, no keys) ───────────
test('discoverableConsentInput is injective across field boundaries (LP framing, not raw-concat)', () => {
  // subject_fp='ab'+scope_value='c' vs subject_fp='a'+scope_value='bc' — a raw concat collides; LP must NOT.
  const x = discoverableConsentInput({ subject_fp: 'ab', scope_value: 'c', epoch: 1, discoverable: true, scope_tag: 0 });
  const y = discoverableConsentInput({ subject_fp: 'a', scope_value: 'bc', epoch: 1, discoverable: true, scope_tag: 0 });
  assert.notEqual(x, y);
});

test('discoverableConsentInput is deterministic + sensitive to every field', () => {
  const base = consent('carol', 5, true);
  assert.equal(discoverableConsentInput(base), discoverableConsentInput(consent('carol', 5, true)));
  assert.notEqual(discoverableConsentInput(base), discoverableConsentInput(consent('carol', 5, false))); // discoverable
  assert.notEqual(discoverableConsentInput(base), discoverableConsentInput(consent('carol', 6, true))); // epoch
  assert.notEqual(discoverableConsentInput(base), discoverableConsentInput(consent('carorl', 5, true))); // subject
  assert.notEqual(discoverableConsentInput(base), discoverableConsentInput({ ...base, scope_tag: 1 })); // scope_tag
});

// ── anti-forge: genuine verifies against subject key; forgery by another key does not ────────────
test('valid consent verifies against the subject key; a forgery by another key does NOT (anti-forge)', async () => {
  const carol = await signer();
  const mallory = await signer();
  const signed = await signDiscoverableConsent(consent(carol.fp, 1, true), carol.priv, carol.kpass);
  assert.equal(await verifyDiscoverableConsent(signed, carol.pub), true); // genuine
  assert.equal(await verifyDiscoverableConsent(signed, mallory.pub), false); // wrong key → fail
});

test('tampering any signed field fails verification (injective preimage)', async () => {
  const carol = await signer();
  const signed = await signDiscoverableConsent(consent(carol.fp, 1, true), carol.priv, carol.kpass);
  assert.equal(await verifyDiscoverableConsent({ ...signed, discoverable: false }, carol.pub), false);
  assert.equal(await verifyDiscoverableConsent({ ...signed, epoch: 2 }, carol.pub), false);
  assert.equal(await verifyDiscoverableConsent({ ...signed, subject_fp: 'x' }, carol.pub), false);
});

// ── edge-store apply: verify-before-set, monotonic-supersede, fail-closed ────────────────────────
function fakeStore(initial: DiscoverableConsentContact[]) {
  const byFp = new Map(initial.map((c) => [c.fingerprint, { ...c }]));
  const writes: Array<{ id: string; metadata: Record<string, unknown> | undefined }> = [];
  const store: DiscoverableConsentStore = {
    getContactByFingerprint: async (fp) => byFp.get(fp) ?? null,
    updateContact: async (id, updates) => {
      writes.push({ id, metadata: updates.metadata });
      for (const c of byFp.values()) if (c.id === id) c.metadata = updates.metadata;
    },
  };
  return { store, writes, byFp };
}

test('apply: a genuine consent writes the flag + epoch; monotonic-stale + revoke hold', async () => {
  const carol = await signer();
  const { store, byFp } = fakeStore([{ id: 'c1', fingerprint: carol.fp, public_key: carol.pub }]);
  assert.equal(await applyDiscoverableConsent(await signDiscoverableConsent(consent(carol.fp, 1, true), carol.priv, carol.kpass), store), 'applied');
  assert.equal(byFp.get(carol.fp)!.metadata![DISCOVERABLE_FLAG_KEY], true);
  assert.equal(byFp.get(carol.fp)!.metadata![DISCOVERABLE_EPOCH_KEY], 1);
  // same epoch again → stale (no downgrade/replay)
  assert.equal(await applyDiscoverableConsent(await signDiscoverableConsent(consent(carol.fp, 1, true), carol.priv, carol.kpass), store), 'rejected-stale');
  // revoke at a strictly-greater epoch → applied, flag false
  assert.equal(await applyDiscoverableConsent(await signDiscoverableConsent(consent(carol.fp, 2, false), carol.priv, carol.kpass), store), 'applied');
  assert.equal(byFp.get(carol.fp)!.metadata![DISCOVERABLE_FLAG_KEY], false);
  assert.equal(byFp.get(carol.fp)!.metadata![DISCOVERABLE_EPOCH_KEY], 2);
});

test('apply fail-closed: forged sig / non-contact / unsupported-scope all refuse to write', async () => {
  const carol = await signer();
  const mallory = await signer();
  const { store, writes, byFp } = fakeStore([{ id: 'c1', fingerprint: carol.fp, public_key: carol.pub }]);
  // FORGED: Mallory signs a consent with subject=Carol → verified against Carol's STORED key = FALSE (anti-forge)
  const forged: SignedDiscoverableConsent = await signDiscoverableConsent(consent(carol.fp, 1, true), mallory.priv, mallory.kpass);
  assert.equal(await applyDiscoverableConsent(forged, store), 'rejected-sig');
  // NON-CONTACT: Mallory genuinely self-signs, but the truster doesn't have Mallory → never materialize
  const stranger = await signDiscoverableConsent(consent(mallory.fp, 1, true), mallory.priv, mallory.kpass);
  assert.equal(await applyDiscoverableConsent(stranger, store), 'rejected-no-contact');
  // UNSUPPORTED SCOPE: per-truster is reserved for a future variant → rejected before set
  const perTruster = await signDiscoverableConsent(
    { ...consent(carol.fp, 1, true), scope_tag: CONSENT_SCOPE_PER_TRUSTER, scope_value: 'some-truster' },
    carol.priv,
    carol.kpass,
  );
  assert.equal(await applyDiscoverableConsent(perTruster, store), 'rejected-unsupported-scope');
  // NOTHING written on any fail-closed path
  assert.equal(writes.length, 0);
  assert.equal(byFp.get(carol.fp)!.metadata ?? undefined, undefined);
});
