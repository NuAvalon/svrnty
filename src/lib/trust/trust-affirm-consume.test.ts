// src/lib/trust/trust-affirm-consume.test.ts
// Run: npx tsx --test src/lib/trust/trust-affirm-consume.test.ts
//
// Proves acceptTrustAffirm's four gates in order (authn → bind-to-me → admit → apply), with REAL signed
// affirmations (mintHeadlessAgent) and INJECTED isAdmitted/applyMutual sinks so no IndexedDB is needed.
// These are the increment-2 security bars Flint named (#167514): the FALSE-MUTUAL / stranger-affirm gate,
// break-direction, ack-follows-persist, and reciprocal-only-if-I-independently-trust-them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { signTrustAffirm, TRUST_AFFIRM_WIRE_TYPE, type TrustAffirmWireV0 } from './trust-affirm';
import { acceptTrustAffirm, type MutualApplyResult } from './trust-affirm-consume';

type Signer = { fp: string; pub: string; priv: string; kpass: string; kem: string; sig: string };
async function signerFromMint(): Promise<Signer> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id: any = a.introduction.card.identity;
  return {
    fp: id.fingerprint, pub: id.public_key,
    priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, sig: id.pq_sig_public_key,
  };
}
async function signedAffirm(from: Signer, toFp: string, trusts = true): Promise<TrustAffirmWireV0> {
  return signTrustAffirm(
    { type: TRUST_AFFIRM_WIRE_TYPE, affirm_id: 'af_c_0001', from_fingerprint: from.fp, to_fingerprint: toFp, trusts, sent_at: '2026-10-10T03:20:00.000Z' },
    from.pub, from.priv, from.kpass, from.kem, from.sig,
  );
}

// A spy apply sink. `iTrustThem` emulates the recipient's EXISTING trusted state (edgeTrusted),
// so reciprocal = iTrustThem && trusts — exactly the live wiring's rule.
function spyApply(iTrustThem: boolean) {
  const calls: Array<{ fp: string; trusts: boolean }> = [];
  const applyMutual = async (fp: string, trusts: boolean): Promise<MutualApplyResult> => {
    calls.push({ fp, trusts });
    return { id: 'rec_' + fp.slice(0, 6), reciprocal: iTrustThem && trusts };
  };
  return { calls, applyMutual };
}

test('verified + in-book + I-already-trust-them → flip applied, reciprocal TRUE (mutual)', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const wire = await signedAffirm(A, B.fp, true);
  const apply = spyApply(/* iTrustThem */ true);
  const out = await acceptTrustAffirm({ wire, ownerFingerprint: B.fp, isAdmitted: async () => true, applyMutual: apply.applyMutual });
  assert.ok(out);
  assert.equal(out?.reciprocal, true, 'both sides trust → mutual');
  assert.equal(out?.trusts, true);
  assert.deepEqual(apply.calls, [{ fp: A.fp, trusts: true }], 'applyMutual fired once with the sender fp + trusts');
});

test('verified + in-book + I do NOT trust them back → they_trust_me set, reciprocal FALSE (inbound, no auto-promote)', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const wire = await signedAffirm(A, B.fp, true);
  const apply = spyApply(/* iTrustThem */ false);
  const out = await acceptTrustAffirm({ wire, ownerFingerprint: B.fp, isAdmitted: async () => true, applyMutual: apply.applyMutual });
  assert.ok(out);
  assert.equal(out?.reciprocal, false, 'no wire-driven promotion — mutual requires MY own prior trust');
});

test('a BREAK affirmation (trusts=false) from an in-book sender applies with trusts=false', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const wire = await signedAffirm(A, B.fp, false);
  const apply = spyApply(true);
  const out = await acceptTrustAffirm({ wire, ownerFingerprint: B.fp, isAdmitted: async () => true, applyMutual: apply.applyMutual });
  assert.ok(out);
  assert.equal(out?.trusts, false);
  assert.equal(out?.reciprocal, false, 'break clears reciprocal even if I still trust them');
  assert.deepEqual(apply.calls, [{ fp: A.fp, trusts: false }]);
});

test('FALSE-MUTUAL GATE: a verified STRANGER (not in book) is dropped — NO flip (Flint #167514)', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const wire = await signedAffirm(A, B.fp, true);
  const apply = spyApply(true);
  const out = await acceptTrustAffirm({ wire, ownerFingerprint: B.fp, isAdmitted: async () => false, applyMutual: apply.applyMutual });
  assert.equal(out, null, 'a verified stranger affirmation is dropped terminally');
  assert.deepEqual(apply.calls, [], 'applyMutual NEVER fired — no "X trusts you" off an unknown sender');
});

test('an UNSIGNED / forged affirmation is dropped before admit (authn floor)', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  // Strip the signature → verifyTrustAffirmSender fails.
  const signed = await signedAffirm(A, B.fp, true);
  const unsigned = { ...signed, signature: undefined, public_key: undefined } as TrustAffirmWireV0;
  const apply = spyApply(true);
  let admitChecked = false;
  const out = await acceptTrustAffirm({
    wire: unsigned, ownerFingerprint: B.fp,
    isAdmitted: async () => { admitChecked = true; return true; },
    applyMutual: apply.applyMutual,
  });
  assert.equal(out, null, 'unsigned affirmation dropped');
  assert.equal(admitChecked, false, 'authn runs BEFORE admit — a forged wire never reaches the book lookup');
  assert.deepEqual(apply.calls, []);
});

test('BIND-TO-ME: an affirmation addressed to someone else is dropped (to_fingerprint mismatch)', async () => {
  const [A, B, C] = [await signerFromMint(), await signerFromMint(), await signerFromMint()];
  const wire = await signedAffirm(A, C.fp, true); // addressed to C, signed over to=C
  const apply = spyApply(true);
  const out = await acceptTrustAffirm({ wire, ownerFingerprint: B.fp, isAdmitted: async () => true, applyMutual: apply.applyMutual });
  assert.equal(out, null, 'an affirmation whose to != me cannot drive my state');
  assert.deepEqual(apply.calls, []);
});

test('ACK-FOLLOWS-PERSIST: applyMutual throwing propagates (caller leaves it retryable)', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const wire = await signedAffirm(A, B.fp, true);
  await assert.rejects(
    () => acceptTrustAffirm({
      wire, ownerFingerprint: B.fp, isAdmitted: async () => true,
      applyMutual: async () => { throw new Error('IndexedDB updateContact failed'); },
    }),
    /updateContact failed/,
    'a store failure propagates → the consume loop treats it as retryable, not acked',
  );
});

test('STALE-REPLAY (#3 monotonic): the SIGNED sent_at is forwarded, and a null (superseded) apply → DROPPED terminally', async () => {
  const [A, B] = [await signerFromMint(), await signerFromMint()];
  const wire = await signedAffirm(A, B.fp, true); // sent_at = '2026-10-10T03:20:00.000Z'
  let seenSentAt: string | undefined;
  const out = await acceptTrustAffirm({
    wire, ownerFingerprint: B.fp, isAdmitted: async () => true,
    // The seam's per-sender monotonic cursor returns null when sent_at is not newer than the last applied —
    // acceptTrustAffirm must forward the signed sent_at and treat null as a TERMINAL drop (no flip, acked).
    applyMutual: async (_fp, _trusts, sentAt) => { seenSentAt = sentAt; return null; },
  });
  assert.equal(out, null, 'a stale/superseded affirmation is dropped terminally — not left-for-retry');
  assert.equal(seenSentAt, '2026-10-10T03:20:00.000Z', 'the SIGNED sent_at reaches the monotonic sink');
});
