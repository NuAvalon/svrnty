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
import { allowedRowShouldExist, type PeerConsent } from '@/lib/sync/allowed-sync';
import { readFileSync } from 'node:fs';

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
async function toggleViaChokepoint(A: Id, B: Id, nextTrusted: boolean, relay: ReturnType<typeof mockRelay>, held: Record<string, unknown> = {}, peerExtra: Record<string, unknown> = {}, stored: Record<string, unknown> | null | 'throws' = null) {
  const patches: Array<Record<string, unknown>> = [];
  const consents: PeerConsent[] = [];
  const deps: TrustTransitionDeps = {
    // `held` stands for the record the store holds when the write runs: a function updater is applied to it, as updateContact does.
    updateContact: async (_id, patch) => { patches.push(typeof patch === 'function' ? patch(held) : patch); },
    // `stored` stands for the record the store holds AFTER the write: the satellite consent is read back from it.
    getContact: async () => { if (stored === 'throws') throw new Error('store unavailable'); return stored; },
    reconcile: async (a) => { consents.push(a.consent as PeerConsent); }, // the reveal-set reconcile seam: captured here
    fetchImpl: relay.fetchImpl,
    satelliteBase: '',
    now: () => FIXED_NOW,
  };
  await applyTrustTransition(
    { fingerprint: A.fp, publicKeyArmored: A.pub, pqKemPublicKey: A.kem, pqSigPublicKey: A.sig },
    { contactId: 'c_' + B.fp.slice(0, 8), fingerprint: B.fp, publicKeyArmored: B.pub, ...peerExtra },
    nextTrusted,
    deps,
  );
  return { patches, consents };
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

test('the history append and the open_visibility clear are built from the record held when the write runs, not from the copy `peer` carried', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const staleEvent = { timestamp: 't0', action: 'trust', reason: 'older', initiated_by: 'self' };
  const heldEvents = [staleEvent, { timestamp: 't1', action: 'break', reason: 'a write since', initiated_by: 'self' }];
  const held = {
    trust_history: heldEvents,
    metadata: { notes: 'kept', share_settings: { open_visibility: true, per_contact_private: true, share_card: false } },
  };
  // `peer` carries an OLDER copy: one history event and metadata without the setting changed since.
  const { patches } = await toggleViaChokepoint(A, B, false, relay, held, {
    priorTrustHistory: [staleEvent],
    metadata: { notes: 'old copy', share_settings: { open_visibility: true } },
  });
  const history = patches[0].trust_history as unknown[];
  assert.equal(history.length, heldEvents.length + 1, 'the held history plus the new event, not the stale copy plus one');
  const md = patches[0].metadata as { notes: string; share_settings: Record<string, unknown> };
  assert.equal(md.notes, 'kept', 'metadata comes from the held record');
  assert.equal(md.share_settings.open_visibility, false, 'untrust still clears open_visibility');
  assert.equal(md.share_settings.per_contact_private, true, 'a setting changed since the copy was read survives');
  assert.equal(md.share_settings.share_card, false);
});

test('trusting does not touch metadata, and still appends to the held history', async () => {
  const [A, B] = [await mint(), await mint()];
  const relay = mockRelay();
  const { patches } = await toggleViaChokepoint(A, B, true, relay, { trust_history: [{ timestamp: 't0', action: 'break', reason: 'x', initiated_by: 'self' }], metadata: { x: 1 } });
  assert.equal('metadata' in patches[0], false);
  assert.equal((patches[0].trust_history as unknown[]).length, 2);
});

// ── the satellite consent is read back from the stored record, not carried by the caller ───────────────────

test('the satellite consent comes from the stored record read back after the write, not from fields the caller carried', async () => {
  const [A, B] = [await mint(), await mint()];
  const stored = { trust_level: 'trusted', blocked: true, metadata: { share_settings: { open_visibility: true, per_contact_private: false } } };
  // the caller's copy says: not blocked, open, not private (older than the stored record)
  const { consents } = await toggleViaChokepoint(A, B, true, mockRelay(), {}, { blocked: false, openVisibility: true, perContactPrivate: false }, stored);
  assert.equal(consents.length, 1);
  assert.equal(consents[0].blocked, true, 'blocked is the stored value');
  assert.equal(allowedRowShouldExist(consents[0]), false, 'a blocked contact is never added');
});

test('NEG: a trust toggle on a contact blocked AFTER the caller took its copy reconciles as blocked and never adds the row', async () => {
  const [A, B] = [await mint(), await mint()];
  const afterBlock = { trust_level: 'unverified', blocked: true, trusted: false, metadata: { blocked: true, share_settings: { open_visibility: false } } };
  const { consents } = await toggleViaChokepoint(A, B, true, mockRelay(), {}, { blocked: false, openVisibility: true }, afterBlock);
  assert.equal(consents[0].blocked, true);
  assert.equal(allowedRowShouldExist(consents[0]), false);
});

test('an untrust reconciles from the stored, cleared open_visibility, whatever the caller carried', async () => {
  const [A, B] = [await mint(), await mint()];
  const stored = { trust_level: 'unverified', trusted: false, metadata: { share_settings: { open_visibility: false } } };
  const { consents } = await toggleViaChokepoint(A, B, false, mockRelay(), {}, { openVisibility: true }, stored);
  assert.deepEqual(consents[0], { trusted: false, openVisibility: false, blocked: false, perContactPrivate: false });
});

test('a promotion reads the stored open_visibility and per-contact-private setting', async () => {
  const [A, B] = [await mint(), await mint()];
  const stored = { trust_level: 'trusted', metadata: { share_settings: { open_visibility: true, per_contact_private: false } } };
  const { consents } = await toggleViaChokepoint(A, B, true, mockRelay(), {}, {}, stored);
  assert.deepEqual(consents[0], { trusted: true, openVisibility: true, blocked: false, perContactPrivate: false });
  assert.equal(allowedRowShouldExist(consents[0]), true);
});

test('a contact that is gone, or a store that cannot be read, reconciles as NO consent (the row is removed) and does not throw', async () => {
  const [A, B] = [await mint(), await mint()];
  const none = { trusted: false, openVisibility: false, blocked: false, perContactPrivate: false };
  assert.deepEqual((await toggleViaChokepoint(A, B, true, mockRelay(), {}, {}, null)).consents[0], none);
  assert.deepEqual((await toggleViaChokepoint(A, B, true, mockRelay(), {}, {}, 'throws')).consents[0], none);
});

test('GUARD: the transition no longer reads blocked / openVisibility / perContactPrivate from its caller', () => {
  const src = readFileSync(new URL('./apply-trust-transition.ts', import.meta.url), 'utf8').replace(/^\s*\/\/.*$/gm, '');
  assert.doesNotMatch(src, /peer\.(blocked|openVisibility|perContactPrivate|metadata|priorTrustHistory)/);
  assert.match(src, /const stored = await getContact\(peer\.contactId\);\s*if \(stored\) consent = consentFromRecord\(stored\);/);
  // the read-back comes AFTER the local write and the satellite commit, never before (a read before would see the pre-write record)
  const iWrite = src.indexOf('await withSafetyWrite(peer.contactId');
  const iRead = src.indexOf('await getContact(peer.contactId)');
  assert.ok(iWrite > 0 && iRead > iWrite, 'the consent is read back after the write');
});
