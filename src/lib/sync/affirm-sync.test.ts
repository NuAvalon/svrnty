// src/lib/sync/affirm-sync.test.ts
// ADVERSARIAL gate for the piece-2 EMIT/RECEIVE wiring (task #579, §F seal KB#92252). Drives REAL crypto
// end-to-end through an in-memory satellite (peelOnion) with raw noble keys — no IndexedDB, no network.
// Refutes survivor-safety properties:
//   · EMIT §F3 fail-closed: an UNREADABLE suppression record (null) ⇒ emit to NO ONE,
//   · EMIT eligibility: grow-gate / blocked / metadata.blocked / person / group / global are excluded,
//   · EMIT re-filters FRESH each pass (suppress-between-ticks ⇒ next tick emits nothing to that peer),
//   · EMIT under-reveals on a missing seal-target / unresolvable peer signing key (never a bare send),
//   · ROUND-TRIP: A's emit, polled off the satellite by B, verifies + records a fresh affirmative,
//   · RECEIVE rejects EXPIRED / ROLLBACK / a stale-or-wrong peer key (each ⇒ under-reveal),
//   · RECEIVE tolerates the edge window (a near-boundary emit is still found one window later),
//   · COVER is a well-formed 'cover' cell (never a visible-affirm) — a visible-affirm poll filters it out.
// Run: npx tsx --test src/lib/sync/affirm-sync.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';

import {
  isEmitEligible,
  runAffirmEmitTick,
  runAffirmReceiveTick,
  makeAffirmCover,
  AFFIRM_EMIT_TTL_SECONDS,
  PIECE2_ROUTE_ANCHOR_WINDOW,
  type AffirmSyncContext,
} from './affirm-sync.js';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys } from '../crypto/mailbox-keys.js';
import { deriveMailboxFp } from '../crypto/mailbox-envelope.js';
import { mailboxPublicOf } from '../identity/device-mailbox.js';
import { peelOnion, openOnionInner, type StrippedInner } from '../crypto/onion-envelope.js';
import { unframeUniform } from '../crypto/uniform-frame.js';
import type { SuppressionRecord } from '../trust/suppression.js';
import type { ContactRecord } from '../identity/client-store.js';

// A clock well past the fixed anchor so routeIdForPeer never trips nowWindow<anchorWindow.
const T0 = (PIECE2_ROUTE_ANCHOR_WINDOW + 6) * 3600; // seconds, window = anchor+6
const emptySupp = (): SuppressionRecord => ({ global: false, groups: [], persons: [] });

interface Identity {
  fp: string;
  seed: Uint8Array;
  signPub: Uint8Array;
  me: AffirmSyncContext['me'];
  mailboxPublic: ReturnType<typeof mailboxPublicOf>;
}

function mkIdentity(fpSeed: string): Identity {
  const seed = ed25519.utils.randomSecretKey();
  const signPub = ed25519.getPublicKey(seed);
  const mb = generateMailboxKeypair();
  const publicKeys = toPublicKeys(mb);
  const secrets = toSecretKeys(mb);
  const fpHex = deriveMailboxFp(publicKeys.x25519Pub, publicKeys.mlkem1024Pub); // any stable 64-hex works as id
  // Use a distinct deterministic identity fp (NOT the mailbox fp) so recipientBinding is identity-bound.
  const fp = fpSeed.repeat(64).slice(0, 64);
  return { fp, seed, signPub, me: { secrets, publicKeys, fp: fpHex }, mailboxPublic: mailboxPublicOf(publicKeys) };
}

function mkContact(peer: Identity, extra: Partial<ContactRecord> = {}): ContactRecord {
  return {
    id: peer.fp.slice(0, 8),
    fingerprint: peer.fp,
    name: 'peer',
    email: '',
    public_key: '', // resolved via injected resolvePeerSignPub in tests
    device_mailbox: peer.mailboxPublic,
    trust_level: 'trusted',
    added_at: '2026-10-05',
    ...extra,
  } as ContactRecord;
}

function mkContext(self: Identity, satPub: AffirmSyncContext['satelliteKeys']): AffirmSyncContext {
  return { owner: self.fp, ownerSeed: self.seed, me: self.me, satelliteKeys: satPub, anchorWindow: PIECE2_ROUTE_ANCHOR_WINDOW };
}

// In-memory satellite: peels the onion OUTER exactly like the real relay, buffers stripped inners by route.
function mkSatellite() {
  const satMb = generateMailboxKeypair();
  const satPub = toPublicKeys(satMb);
  const satSec = toSecretKeys(satMb);
  const satFp = deriveMailboxFp(satPub.x25519Pub, satPub.mlkem1024Pub);
  const buffer = new Map<string, StrippedInner[]>();
  const relay = {
    async deposit(outer: Parameters<typeof peelOnion>[0]) {
      const peeled = await peelOnion(outer, satSec, satFp);
      if (!peeled) return;
      const arr = buffer.get(peeled.route) ?? [];
      arr.push(peeled.inner);
      buffer.set(peeled.route, arr);
    },
    async poll(routeId: string) {
      return buffer.get(routeId) ?? [];
    },
  };
  return { satPub, satSec, satFp, relay, buffer };
}

// Collect enqueued outers (stand-in for the CadenceEmitter) then deposit them to the satellite.
function mkCadence() {
  const cells: Array<Parameters<ReturnType<typeof mkSatellite>['relay']['deposit']>[0]> = [];
  return { enqueue: (o: any) => cells.push(o), cells };
}

function signPubResolver(...ids: Identity[]) {
  const by = new Map(ids.map((i) => [i.fp, i.signPub]));
  return (c: ContactRecord) => by.get(c.fingerprint) ?? null;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────────────

test('isEmitEligible: eligible contact passes; every exclusion bites', () => {
  const peer = mkIdentity('a');
  const supp = emptySupp();
  assert.equal(isEmitEligible(mkContact(peer), supp), true, 'plain eligible');
  assert.equal(isEmitEligible(mkContact(peer, { metadata: { grow_gate: true } }), supp), false, 'grow-gate excluded');
  assert.equal(isEmitEligible(mkContact(peer, { blocked: true } as any), supp), false, 'blocked excluded');
  assert.equal(isEmitEligible(mkContact(peer, { metadata: { blocked: true } }), supp), false, 'metadata.blocked excluded');
  assert.equal(isEmitEligible(mkContact(peer, { fingerprint: '' }), supp), false, 'no-fingerprint excluded');
  assert.equal(isEmitEligible(mkContact(peer), { ...supp, persons: [peer.fp] }), false, 'person-suppressed excluded');
  assert.equal(isEmitEligible(mkContact(peer, { tags: ['g1'] } as any), { ...supp, groups: ['g1'] }), false, 'group-suppressed excluded');
  assert.equal(isEmitEligible(mkContact(peer), { ...supp, global: true }), false, 'global go-private excludes all');
  assert.equal(isEmitEligible(mkContact(peer), null), false, '★ §F3: null record ⇒ suppress (exclude)');
});

test('EMIT §F3 fail-closed: null suppression record ⇒ emit to NO ONE, nothing enqueued', async () => {
  const self = mkIdentity('a');
  const peer = mkIdentity('b');
  const { satPub } = mkSatellite();
  const cadence = mkCadence();
  const res = await runAffirmEmitTick(mkContext(self, satPub), cadence, {
    getSuppressionRecord: async () => null, // UNREADABLE
    getAllContacts: async () => [mkContact(peer)],
    resolvePeerSignPub: signPubResolver(peer),
    clock: () => T0,
  });
  assert.equal(res.emitted, 0, 'emitted nothing');
  assert.equal(cadence.cells.length, 0, 'enqueued nothing');
});

test('EMIT under-reveals on a missing seal-target and on an unresolvable signing key', async () => {
  const self = mkIdentity('a');
  const peer = mkIdentity('b');
  const { satPub } = mkSatellite();

  // (1) no device_mailbox ⇒ no seal-target ⇒ skip
  let cadence = mkCadence();
  let res = await runAffirmEmitTick(mkContext(self, satPub), cadence, {
    getSuppressionRecord: async () => emptySupp(),
    getAllContacts: async () => [mkContact(peer, { device_mailbox: undefined })],
    resolvePeerSignPub: signPubResolver(peer),
    clock: () => T0,
  });
  assert.equal(res.emitted, 0); assert.equal(res.skipped, 1); assert.equal(cadence.cells.length, 0);

  // (2) resolvePeerSignPub returns null ⇒ can't key the route ⇒ skip
  cadence = mkCadence();
  res = await runAffirmEmitTick(mkContext(self, satPub), cadence, {
    getSuppressionRecord: async () => emptySupp(),
    getAllContacts: async () => [mkContact(peer)],
    resolvePeerSignPub: () => null,
    clock: () => T0,
  });
  assert.equal(res.emitted, 0); assert.equal(res.skipped, 1); assert.equal(cadence.cells.length, 0);
});

test('ROUND-TRIP: A emits → satellite → B receives, records a fresh affirmative (epoch = emit time)', async () => {
  const A = mkIdentity('a');
  const B = mkIdentity('b');
  const { satPub, relay } = mkSatellite();

  // A emits to B
  const cadence = mkCadence();
  const emit = await runAffirmEmitTick(mkContext(A, satPub), cadence, {
    getSuppressionRecord: async () => emptySupp(),
    getAllContacts: async () => [mkContact(B)],
    resolvePeerSignPub: signPubResolver(B),
    clock: () => T0,
  });
  assert.equal(emit.emitted, 1, 'A enqueued one affirmative');
  for (const o of cadence.cells) await relay.deposit(o); // cadence → satellite

  // B receives from A
  let stored: any = null;
  const recv = await runAffirmReceiveTick(mkContext(B, satPub), {
    getAllContacts: async () => [mkContact(A)],
    getHeldAffirmatives: async () => null, // absent ⇒ empty baseline
    setHeldAffirmatives: async (_owner, map) => { stored = map; },
    resolvePeerSignPub: signPubResolver(A),
    relay,
    clock: () => T0,
  });

  assert.equal(recv.accepted, 1, 'B accepted one affirmative');
  assert.ok(stored, 'held store persisted');
  const held = stored[A.fp.toLowerCase()];
  assert.ok(held, 'B holds an affirmative from A');
  assert.equal(held.epoch, T0, 'epoch is the emit time (DECISION-1)');
  assert.equal(held.validUntil, T0 + AFFIRM_EMIT_TTL_SECONDS, 'validUntil = now + emit TTL');
});

test('RECEIVE rejects an EXPIRED affirmative (block bites by absence)', async () => {
  const A = mkIdentity('a');
  const B = mkIdentity('b');
  const { satPub, relay } = mkSatellite();
  const cadence = mkCadence();
  await runAffirmEmitTick(mkContext(A, satPub), cadence, {
    getSuppressionRecord: async () => emptySupp(), getAllContacts: async () => [mkContact(B)],
    resolvePeerSignPub: signPubResolver(B), clock: () => T0,
  });
  for (const o of cadence.cells) await relay.deposit(o);

  let persisted = false;
  const recv = await runAffirmReceiveTick(mkContext(B, satPub), {
    getAllContacts: async () => [mkContact(A)],
    getHeldAffirmatives: async () => null,
    setHeldAffirmatives: async () => { persisted = true; },
    resolvePeerSignPub: signPubResolver(A),
    relay,
    clock: () => T0 + AFFIRM_EMIT_TTL_SECONDS + 5, // past validUntil
  });
  assert.equal(recv.accepted, 0, 'expired affirmative not accepted');
  assert.equal(persisted, false, 'nothing persisted');
});

test('RECEIVE rejects a ROLLBACK (replayed older epoch never overwrites a newer held one)', async () => {
  const A = mkIdentity('a');
  const B = mkIdentity('b');
  const { satPub, relay } = mkSatellite();
  const cadence = mkCadence();
  await runAffirmEmitTick(mkContext(A, satPub), cadence, {
    getSuppressionRecord: async () => emptySupp(), getAllContacts: async () => [mkContact(B)],
    resolvePeerSignPub: signPubResolver(B), clock: () => T0, // epoch = T0
  });
  for (const o of cadence.cells) await relay.deposit(o);

  // B already holds a NEWER affirmative from A (epoch T0+100).
  const prior = { [A.fp.toLowerCase()]: { validUntil: T0 + 100 + AFFIRM_EMIT_TTL_SECONDS, epoch: T0 + 100 } };
  let saved: any = null;
  const recv = await runAffirmReceiveTick(mkContext(B, satPub), {
    getAllContacts: async () => [mkContact(A)],
    getHeldAffirmatives: async () => ({ ...prior }),
    setHeldAffirmatives: async (_o, m) => { saved = m; },
    resolvePeerSignPub: signPubResolver(A),
    relay,
    clock: () => T0 + 100, // still fresh window, but the polled cell's epoch (T0) <= held (T0+100)
  });
  assert.equal(recv.accepted, 0, 'older epoch not accepted over newer');
  assert.equal(saved, null, 'held unchanged');
});

test('RECEIVE under-reveals on a stale/wrong peer signing key', async () => {
  const A = mkIdentity('a');
  const B = mkIdentity('b');
  const Wrong = mkIdentity('c'); // attacker/rotated-away key
  const { satPub, relay } = mkSatellite();
  const cadence = mkCadence();
  await runAffirmEmitTick(mkContext(A, satPub), cadence, {
    getSuppressionRecord: async () => emptySupp(), getAllContacts: async () => [mkContact(B)],
    resolvePeerSignPub: signPubResolver(B), clock: () => T0,
  });
  for (const o of cadence.cells) await relay.deposit(o);

  const recv = await runAffirmReceiveTick(mkContext(B, satPub), {
    getAllContacts: async () => [mkContact(A)],
    getHeldAffirmatives: async () => null,
    setHeldAffirmatives: async () => {},
    resolvePeerSignPub: () => Wrong.signPub, // wrong key for A ⇒ wrong route + wrong verify ⇒ miss
    relay,
    clock: () => T0,
  });
  assert.equal(recv.accepted, 0, 'wrong/stale key ⇒ under-reveal');
});

test('RECEIVE tolerates the edge window: a near-boundary emit is found one window later', async () => {
  const A = mkIdentity('a');
  const B = mkIdentity('b');
  const { satPub, relay } = mkSatellite();
  const boundary = (PIECE2_ROUTE_ANCHOR_WINDOW + 12) * 3600;
  const tEmit = boundary - 20;  // 20s before a window boundary (window anchor+11)
  const tRecv = boundary + 20;  // 20s after  (window anchor+12) — still well within the 1140s TTL

  const cadence = mkCadence();
  await runAffirmEmitTick(mkContext(A, satPub), cadence, {
    getSuppressionRecord: async () => emptySupp(), getAllContacts: async () => [mkContact(B)],
    resolvePeerSignPub: signPubResolver(B), clock: () => tEmit,
  });
  for (const o of cadence.cells) await relay.deposit(o);

  let saved: any = null;
  const recv = await runAffirmReceiveTick(mkContext(B, satPub), {
    getAllContacts: async () => [mkContact(A)],
    getHeldAffirmatives: async () => null,
    setHeldAffirmatives: async (_o, m) => { saved = m; },
    resolvePeerSignPub: signPubResolver(A),
    relay,
    clock: () => tRecv,
  });
  assert.equal(recv.accepted, 1, 'edge-window emit still received');
  assert.ok(saved[A.fp.toLowerCase()], 'held across the boundary');
});

test('EMIT re-filters FRESH each pass (§F3): suppressing a peer between ticks stops emission to them', async () => {
  const A = mkIdentity('a');
  const B = mkIdentity('b');
  const { satPub } = mkSatellite();
  const live = emptySupp(); // mutable record read fresh each tick

  const t1 = mkCadence();
  const r1 = await runAffirmEmitTick(mkContext(A, satPub), t1, {
    getSuppressionRecord: async () => live, getAllContacts: async () => [mkContact(B)],
    resolvePeerSignPub: signPubResolver(B), clock: () => T0,
  });
  assert.equal(r1.emitted, 1, 'tick-1 emits to B');

  live.persons.push(B.fp); // user blocks B between ticks
  const t2 = mkCadence();
  const r2 = await runAffirmEmitTick(mkContext(A, satPub), t2, {
    getSuppressionRecord: async () => live, getAllContacts: async () => [mkContact(B)],
    resolvePeerSignPub: signPubResolver(B), clock: () => T0 + 1,
  });
  assert.equal(r2.emitted, 0, 'tick-2 emits nothing to the now-suppressed B');
  assert.equal(t2.cells.length, 0, 'nothing enqueued');
});

test('makeAffirmCover: peels to a real uniform "cover" frame (never a visible-affirm)', async () => {
  const self = mkIdentity('a');
  const sat = mkSatellite();
  const ctx = mkContext(self, sat.satPub);
  const cover = await makeAffirmCover(ctx);

  // Peel the OUTER with the satellite's secrets (what the real relay does), re-insert the device fp, open the
  // INNER with self's device secrets (the cover is sealed to self), and unframe — the frame type MUST be 'cover'.
  const peeled = await peelOnion(cover, sat.satSec, sat.satFp);
  assert.ok(peeled, 'cover outer peels at the satellite');
  const inner = await openOnionInner(peeled!.inner, self.me.secrets, self.me.fp);
  assert.ok(inner, 'inner opens with self device secrets (cover sealed to self)');
  const framed = unframeUniform(inner!);
  assert.ok(framed, 'inner unframes');
  assert.equal(framed!.type, 'cover', 'frame type is cover, NOT visible-affirm');

  // And a visible-affirm receive over the cover's route recovers nothing (kind filter drops it).
  await sat.relay.deposit(cover);
  const recv = await runAffirmReceiveTick(ctx, {
    getAllContacts: async () => [],
    getHeldAffirmatives: async () => null,
    setHeldAffirmatives: async () => { throw new Error('cover must never record an affirmative'); },
    resolvePeerSignPub: () => null,
    relay: sat.relay,
    clock: () => T0,
  });
  assert.equal(recv.accepted, 0, 'a cover cell never becomes an affirmative');
});
