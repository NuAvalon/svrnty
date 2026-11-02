// src/lib/trust/apply-trust-transition.test.ts
// Run: npx tsx --test src/lib/trust/apply-trust-transition.test.ts
//
// OPERATION-verifies the single trust-transition CHOKEPOINT (apply-trust-transition.ts) — the fn both
// the contact-LIST toggle (ContactManagement) and the trust-MAP toggle (app/page.tsx) route through.
//
// #593 (affirm-wire removal): the chokepoint NO LONGER deposits a signed trust-affirmation. A device-held
// `they_trust_me` is false security (defeated by inspection), so mutual is now discovered via the blind
// PSI intersection (#588), never a received affirm bit. These tests assert the RETAINED behavior AND the
// removal itself:
//   • local trust write (+ trust_history) is EMIT-ONLY — NO reciprocal / they_trust_me / mutual in the patch.
//   • the blind satellite commit/revoke still fires (trust → commit, break → revoke), keyed on owner fp.
//   • ★ REMOVAL PROOF: NOTHING is deposited to the peer's mailbox, and a peer poll flips NOTHING on their seat.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mintHeadlessAgent } from '@/lib/identity/headless-mint';
import { deriveMailboxId } from '@/lib/relay/mailbox-auth';
import { HeadlessStore, type HeadlessContact } from '@/lib/headless/headless-store';
import { type HeadlessOwner, pollHeadlessOnce } from '@/lib/headless/headless-client';
import { applyTrustTransition, type TrustTransitionDeps } from './apply-trust-transition';

const RELAY = 'http://relay.test/api/relay';
const FIXED_NOW = '2026-10-18T03:20:00.000Z';

type Id = { fp: string; pub: string; priv: string; kpass: string; kem: string; sig: string };
async function mint(): Promise<Id> {
  const a = await mintHeadlessAgent({ throwaway: true });
  const id: any = a.introduction.card.identity;
  return {
    fp: id.fingerprint, pub: id.public_key,
    priv: a.secret_material.classicalPrivateKey, kpass: a.secret_material.classicalKpass,
    kem: id.pq_kem_public_key, sig: id.pq_sig_public_key,
  };
}
function headlessOwner(id: Id): HeadlessOwner {
  return {
    fingerprint: id.fp, publicKeyArmored: id.pub, privateKeyArmored: id.priv, passphrase: id.kpass,
    kemPublicKey: id.kem, sigPublicKey: id.sig,
  };
}
function asContact(id: Id, over: Partial<HeadlessContact> = {}): HeadlessContact {
  return {
    id: 'c_' + id.fp.slice(0, 8), fingerprint: id.fp, public_key: id.pub,
    pq_sig_public_key: id.sig, pq_kem_public_key: id.kem, ...over,
  };
}

/** Mock relay: /envelope deposit, /queue, /ack — PLUS records /api/trust/commit|revoke calls. */
function mockRelay() {
  const boxes = new Map<string, Array<{ envelope_id: string; blob: string }>>();
  const trustCalls: Array<{ op: string; body: any }> = [];
  let seq = 0;
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    const u = String(url);
    if (u.includes('/api/trust/commit') || u.includes('/api/trust/revoke')) {
      trustCalls.push({ op: u.includes('/commit') ? 'commit' : 'revoke', body: JSON.parse(String(init?.body ?? '{}')) });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    if (u.includes('/envelope')) {
      const { mailbox_id, blob } = JSON.parse(String(init?.body ?? '{}'));
      if (!boxes.has(mailbox_id)) boxes.set(mailbox_id, []);
      boxes.get(mailbox_id)!.push({ envelope_id: `e${++seq}`, blob });
      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    }
    if (u.includes('/queue')) {
      const mid = new URL(u).searchParams.get('mailbox_id') ?? '';
      return new Response(JSON.stringify(boxes.get(mid) ?? []), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (u.includes('/ack')) {
      const { mailbox_id, envelope_ids } = JSON.parse(String(init?.body ?? '{}'));
      const q = boxes.get(mailbox_id) ?? [];
      boxes.set(mailbox_id, q.filter((e) => !envelope_ids.includes(e.envelope_id)));
      return new Response(JSON.stringify({ deleted: (envelope_ids as string[]).length }), { status: 200 });
    }
    return new Response('nf', { status: 404 });
  }) as unknown as typeof fetch;
  return { fetchImpl, boxes, trustCalls };
}

/** Drive A's trust/break toggle through the CHOKEPOINT, capturing A's own local write patch(es). */
async function toggleViaChokepoint(A: Id, B: Id, nextTrusted: boolean, relay: ReturnType<typeof mockRelay>) {
  const patches: Array<Record<string, unknown>> = [];
  const deps: TrustTransitionDeps = {
    updateContact: async (_id, patch) => { patches.push(patch); },
    reconcile: async () => {}, // reveal-set reconcile is a separate fire-and-forget seam; no-op in this unit
    fetchImpl: relay.fetchImpl,
    satelliteBase: '',
    now: () => FIXED_NOW,
  };
  await applyTrustTransition(
    { fingerprint: A.fp, publicKeyArmored: A.pub, pqKemPublicKey: A.kem, pqSigPublicKey: A.sig },
    { contactId: 'c_' + B.fp.slice(0, 8), fingerprint: B.fp, publicKeyArmored: B.pub },
    nextTrusted,
    deps,
  );
  return { patches };
}

test('CHOKEPOINT: A trusts B → local EMIT-ONLY write + blind satellite COMMIT; ★ NO affirm deposited (removed #593), peer seat untouched', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A, { trusted: true, trust_level: 'trusted' })); // B independently trusts A

  const { patches } = await toggleViaChokepoint(A, B, true, relay);

  // (local) the chokepoint wrote A's trust of B.
  assert.equal(patches.length, 1, 'one local trust write');
  assert.equal(patches[0].trusted, true);
  assert.equal(patches[0].trust_level, 'trusted');
  assert.ok(Array.isArray(patches[0].trust_history), 'trust_history recorded');
  // ★ EMIT-ONLY, OBSERVED: A's own local write assumes NOTHING about mutuality.
  assert.equal('reciprocal' in patches[0], false, 'sender write never sets reciprocal');
  assert.equal('they_trust_me' in patches[0], false, 'sender write never sets they_trust_me');
  assert.equal('mutual' in patches[0], false, 'sender write never sets mutual');

  // (satellite) a blind COMMIT fired (not revoke), keyed on the owner fp.
  assert.deepEqual(relay.trustCalls.map((c) => c.op), ['commit']);
  assert.equal(relay.trustCalls[0].body.fingerprint, A.fp);

  // ★ REMOVAL PROOF (#593): the affirm deposit is GONE — NOTHING landed in B's mailbox.
  assert.equal(relay.boxes.get(deriveMailboxId(B.fp))?.length ?? 0, 0, 'no affirmation deposited to the peer');

  // A peer poll flips NOTHING — there is no affirm to consume (the device-held they_trust_me path is gone).
  const summary = await pollHeadlessOnce(headlessOwner(B), bStore, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
  assert.equal(summary.applied + summary.notes + summary.delivered, 0, 'peer poll consumes nothing');
  const a = bStore.getContactByFingerprint(A.fp)!;
  assert.equal(a.mutual?.they_trust_me ?? false, false, 'peer seat: they_trust_me never flips (no affirm-wire)');
  assert.equal(a.mutual?.reciprocal ?? false, false, 'peer seat: reciprocal never flips (mutual is PSI-only, #588)');
});

test('CHOKEPOINT: break direction — A breaks trust → local unverified write + blind satellite REVOKE; ★ no deposit', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();

  const { patches } = await toggleViaChokepoint(A, B, false, relay);
  assert.equal(patches[0].trusted, false);
  assert.equal(patches[0].trust_level, 'unverified');
  assert.deepEqual(relay.trustCalls.map((c) => c.op), ['revoke'], 'break → satellite revoke');

  // ★ REMOVAL PROOF (#593): break also deposits no affirmation.
  assert.equal(relay.boxes.get(deriveMailboxId(B.fp))?.length ?? 0, 0, 'no break-affirmation deposited to the peer');
});
