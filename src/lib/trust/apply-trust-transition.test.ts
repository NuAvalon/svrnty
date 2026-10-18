// src/lib/trust/apply-trust-transition.test.ts
// Run: npx tsx --test src/lib/trust/apply-trust-transition.test.ts
//
// OPERATION-verifies the single trust-transition CHOKEPOINT (apply-trust-transition.ts) — the fn both
// the contact-LIST toggle (ContactManagement) and the trust-MAP toggle (app/page.tsx) route through,
// so no surface can grant trust without depositing the signed affirmation (Flint floor-verify #173014).
//
// It drives A's toggle THROUGH the chokepoint (not sendTrustAffirmToPeer directly), then B consumes via
// the real headless consume path, asserting the property Flint flagged as the hardest-watch:
//   • EMIT-ONLY, OBSERVED (Flint #173025): A's own local write carries NO reciprocal/they_trust_me —
//     the sender assumes nothing; the flip lands only on B's seat AFTER B consumes.
//   • reciprocal flips IFF the recipient independently trusts the sender (mutual needs both sides).
//   • both directions wire end-to-end (trust → satellite commit + trusts:true; break → revoke + false).

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
    loadKey: async () => ({ privateKey: A.priv, passphrase: A.kpass }),
    reconcile: async () => {}, // reveal-set reconcile is a separate fire-and-forget seam; no-op in this unit
    fetchImpl: relay.fetchImpl,
    satelliteBase: '',
    relayBase: RELAY,
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

test('CHOKEPOINT: A trusts B via the shared fn → B consumes → MUTUAL (B already trusts A); sender write is EMIT-ONLY', async () => {
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

  // (emit) a sealed blob landed in B's fp-derived mailbox.
  assert.equal(relay.boxes.get(deriveMailboxId(B.fp))?.length, 1, "deposited to B's mailbox");

  // ★ BEFORE B consumes: nothing has flipped on B's seat — the sender's act is silent on the peer.
  assert.equal(bStore.getContactByFingerprint(A.fp)!.mutual?.they_trust_me ?? false, false, 'no flip before receive');

  // Only after B's real consume does the flip land — on the RECIPIENT seat, mutual iff B trusts A.
  const summary = await pollHeadlessOnce(headlessOwner(B), bStore, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
  assert.equal(summary.affirmed, 1, 'B consumed the chokepoint-driven affirmation');
  const a = bStore.getContactByFingerprint(A.fp)!;
  assert.equal(a.mutual?.they_trust_me, true, 'flip lands on the recipient seat');
  assert.equal(a.mutual?.reciprocal, true, 'reciprocal → MUTUAL (both trust)');
});

test('CHOKEPOINT: one-way — B does NOT trust A → they_trust_me set, reciprocal FALSE (no wire-driven promotion)', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A, { trusted: false, trust_level: 'known' })); // in book, NOT trusted

  await toggleViaChokepoint(A, B, true, relay);
  await pollHeadlessOnce(headlessOwner(B), bStore, { relayBase: RELAY, fetchImpl: relay.fetchImpl });

  const a = bStore.getContactByFingerprint(A.fp)!;
  assert.equal(a.mutual?.they_trust_me, true);
  assert.equal(a.mutual?.reciprocal, false, "mutual needs the recipient's OWN prior trust — a deposit alone cannot promote");
});

test('CHOKEPOINT: break direction — A breaks trust → satellite REVOKE + trusts:false deposit clears reciprocal on consume', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const bStore = new HeadlessStore();
  bStore.upsertContact(asContact(A, { trusted: true, trust_level: 'trusted' })); // B trusts A (so an affirm could reach mutual)

  const { patches } = await toggleViaChokepoint(A, B, false, relay);
  assert.equal(patches[0].trusted, false);
  assert.equal(patches[0].trust_level, 'unverified');
  assert.deepEqual(relay.trustCalls.map((c) => c.op), ['revoke'], 'break → satellite revoke');

  await pollHeadlessOnce(headlessOwner(B), bStore, { relayBase: RELAY, fetchImpl: relay.fetchImpl });
  const a = bStore.getContactByFingerprint(A.fp)!;
  assert.equal(a.mutual?.they_trust_me, false, 'break clears they_trust_me on the recipient');
  assert.equal(a.mutual?.reciprocal, false, 'break clears reciprocal');
});
