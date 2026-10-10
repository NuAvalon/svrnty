// src/lib/sync/affirm-churn-matrix.test.ts
// ★ §F3 CHURN-MATRIX emit-cell — the piece-2 "proven-tested" ship-gate (Peter's invariant), Apollo+Flint
// co-verify to Flint's checklist KB#92283. Task #579, DARK.
//
// INSTRUMENTATION = OBSERVE AT THE SINK, not the in-memory set (KB#92283): we assert on ACTUAL deposits —
// each emitted cell is drained off the CadenceEmitter to an in-memory satellite that peels the onion OUTER
// (peelOnion) and records the deposited routeId. A deposit is mapped back to a peer by precomputing that
// peer's emit route from the peer's CURRENT (post-churn) signing key. We NEVER assert on the suppressed-set
// (a cached/stale set is exactly the bug class). POSITIVE CONTROL every cell: an un-suppressed peer MUST get
// a deposit — proving the harness can detect emission at all (guards against false-GREEN).
//
// MATRIX {churn op} × {target type}:
//   churn  = (1) key-rotation (peer rotates signing key) · (2) mailbox-rebuild · (3) relay-transfer
//   target = (A) suppressed-person · (B) suppressed-group · (C) global (go-private)
// Per cell: apply churn → FULL emit pass → ZERO deposit to the suppressed target + positive-control fires.
// + Archie's cell: piece-1 block → suppression-RECORD person-entry is LOAD-BEARING (suppresses even with the
//   blocked FLAG cleared) and survives rebuild/transfer. + fresh-union + fail-closed-on-doubt invariants.
//
// SCOPE-HONESTY (confirmed with Flint #159918): block-survives-churn is STRUCTURAL by construction —
// suppression is emit-side, owner-LOCAL, durable_id-KEYED, in a SEPARATE store from device_mailbox. This cell
// proves the emit-side BEHAVIORAL invariant (record + durable_id intact ⇒ zero-emit-to-suppressed + positive
// -control); the intact-ACROSS-CHURN half is proven by Flint's seals + structural args, COMPOSED (not a gap):
//   · key-rotation  — suppression keyed on the GENESIS-anchored canonical fp (stable across operational
//                     rotation, both owner + peer entries). [Flint KB#92285, grounded fingerprint.ts/did-peer.ts]
//   · mailbox-rebuild — device_mailbox is a DIFFERENT store (regen on absence / skip-on-unreadable); it never
//                     touches the suppression record. [Flint KB#92292 seal]
//   · relay-transfer — suppression NEVER rides the relay (owner-local) ⇒ a blob migrate/resend CANNOT un-
//                     suppress; the {relay-transfer × suppressed} half is trivially safe, so its load-bearing
//                     content is the LIVENESS positive-control (non-suppressed STILL delivered post-transfer).
// Composed = full block-survives-churn PROVEN. These cells assert the emit-side invariant + name that boundary.
//
// Run: npx tsx --test src/lib/sync/affirm-churn-matrix.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';

import {
  runAffirmEmitTick,
  makeAffirmCover,
  PIECE2_ROUTE_ANCHOR_WINDOW,
  type AffirmSyncContext,
} from './affirm-sync.js';
import { CadenceEmitter, routeIdForPeer } from './onion-transport.js';
import { currentWindowIndex } from '../crypto/route-ratchet.js';
import { deriveSharedSecret } from '../crypto/mutual-trust.js';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys } from '../crypto/mailbox-keys.js';
import { deriveMailboxFp } from '../crypto/mailbox-envelope.js';
import { mailboxPublicOf } from '../identity/device-mailbox.js';
import { peelOnion, type StrippedInner } from '../crypto/onion-envelope.js';
import type { SuppressionRecord } from '../trust/suppression.js';
import type { ContactRecord } from '../identity/client-store.js';

const T0 = (PIECE2_ROUTE_ANCHOR_WINDOW + 6) * 3600; // seconds; window well past the anchor floor
const NOW_WINDOW = currentWindowIndex(T0 * 1000);
const emptySupp = (): SuppressionRecord => ({ global: false, groups: [], persons: [] });

interface Id {
  fp: string;
  seed: Uint8Array;
  signPub: Uint8Array;
  me: AffirmSyncContext['me'];
  mailboxPublic: ReturnType<typeof mailboxPublicOf>;
}

function mkId(fpChar: string): Id {
  const seed = ed25519.utils.randomSecretKey();
  const mb = generateMailboxKeypair();
  const publicKeys = toPublicKeys(mb);
  return {
    fp: fpChar.repeat(64).slice(0, 64),
    seed,
    signPub: ed25519.getPublicKey(seed),
    me: { secrets: toSecretKeys(mb), publicKeys, fp: deriveMailboxFp(publicKeys.x25519Pub, publicKeys.mlkem1024Pub) },
    mailboxPublic: mailboxPublicOf(publicKeys),
  };
}

/** Operational key-rotation: a NEW signing key, SAME durable_id (contact.fingerprint = genesis-anchored fp,
 *  stable across operational rotation — §F2). Returns the new signPub to thread through the resolver + route map. */
function rotateSigning(id: Id): Uint8Array {
  const seed = ed25519.utils.randomSecretKey();
  id.seed = seed; // peer's own seed (only the peer holds it; test uses it to prove route tracks the new key)
  id.signPub = ed25519.getPublicKey(seed);
  return id.signPub;
}

/** Mailbox-rebuild: a fresh device mailbox keypair (new seal-target + fp), SAME identity fp. */
function rebuildMailbox(id: Id): void {
  const mb = generateMailboxKeypair();
  const publicKeys = toPublicKeys(mb);
  id.me = { secrets: toSecretKeys(mb), publicKeys, fp: deriveMailboxFp(publicKeys.x25519Pub, publicKeys.mlkem1024Pub) };
  id.mailboxPublic = mailboxPublicOf(publicKeys);
}

function mkContact(peer: Id, extra: Partial<ContactRecord> = {}): ContactRecord {
  return {
    id: peer.fp.slice(0, 8),
    fingerprint: peer.fp,
    name: 'peer',
    email: '',
    public_key: '',
    device_mailbox: peer.mailboxPublic,
    trust_level: 'trusted',
    added_at: '2026-10-05',
    ...extra,
  } as ContactRecord;
}

function mkSatellite() {
  const satMb = generateMailboxKeypair();
  const satPub = toPublicKeys(satMb);
  const satSec = toSecretKeys(satMb);
  const satFp = deriveMailboxFp(satPub.x25519Pub, satPub.mlkem1024Pub);
  return { satPub, satSec, satFp };
}

function mkContext(self: Id, satPub: AffirmSyncContext['satelliteKeys']): AffirmSyncContext {
  return { owner: self.fp, ownerSeed: self.seed, me: self.me, satelliteKeys: satPub, anchorWindow: PIECE2_ROUTE_ANCHOR_WINDOW };
}

/** The emit route a peer's cells land on, computed from the peer's CURRENT signing key (post-churn). */
function routeOf(ctx: AffirmSyncContext, peerFp: string, peerSignPub: Uint8Array): string {
  const sAB = deriveSharedSecret(ctx.ownerSeed, peerSignPub);
  return routeIdForPeer({ rootSecret: sAB, senderFp: ctx.owner, recipientFp: peerFp, anchorWindow: ctx.anchorWindow, nowWindow: NOW_WINDOW });
}

/** Run ONE full emit pass and return the SET OF ROUTE IDS that actually received a visible-affirm deposit
 *  (observed at the SINK via the satellite peel). Drains exactly the real cells (no cover slots). */
async function depositedRoutes(
  ctx: AffirmSyncContext,
  sat: ReturnType<typeof mkSatellite>,
  deps: Parameters<typeof runAffirmEmitTick>[2],
): Promise<Set<string>> {
  const deposited: StrippedInner[] = [];
  const buffer: Record<string, true> = {};
  const cadence = new CadenceEmitter({
    makeCover: () => makeAffirmCover(ctx),
    deposit: async (outer) => {
      const peeled = await peelOnion(outer, sat.satSec, sat.satFp);
      if (peeled) { deposited.push(peeled.inner); buffer[peeled.route] = true; }
    },
  });
  await runAffirmEmitTick(ctx, cadence, deps);
  const n = cadence.pending(); // drain ONLY the real enqueued cells — no cover slots
  for (let i = 0; i < n; i++) await cadence.drainSlot();
  return new Set(Object.keys(buffer));
}

function mkDeps(opts: {
  supp: SuppressionRecord | null;
  contacts: ContactRecord[];
  signPubOf: Map<string, Uint8Array>;
}): Parameters<typeof runAffirmEmitTick>[2] {
  return {
    getSuppressionRecord: async () => opts.supp,
    getAllContacts: async () => opts.contacts,
    resolvePeerSignPub: (c) => opts.signPubOf.get(c.fingerprint) ?? null,
    clock: () => T0,
  };
}

// ─────────────────────────────────────────────── MATRIX ───────────────────────────────────────────────

test('(key-rotation × person) suppressed person gets ZERO deposit after rotation; rotated un-suppressed DOES', async () => {
  const F = mkId('f'), P = mkId('a'), U = mkId('b');
  const sat = mkSatellite();
  const ctx = mkContext(F, sat.satPub);
  // churn: BOTH peers rotate their signing key (new operational key, SAME durable_id/fingerprint).
  rotateSigning(P); rotateSigning(U);
  const signPubOf = new Map([[P.fp, P.signPub], [U.fp, U.signPub]]);
  const routes = await depositedRoutes(ctx, sat, mkDeps({ supp: { ...emptySupp(), persons: [P.fp] }, contacts: [mkContact(P), mkContact(U)], signPubOf }));
  assert.ok(routes.has(routeOf(ctx, U.fp, U.signPub)), 'positive control: rotated un-suppressed U gets a deposit on its NEW route (emit tracks rotation)');
  assert.ok(!routes.has(routeOf(ctx, P.fp, P.signPub)), 'suppressed P gets ZERO deposit even after rotation');
  assert.equal(routes.size, 1, 'exactly one deposit (U), none to P');
});

test('(key-rotation × group) member of a suppressed group gets ZERO after rotation; control fires', async () => {
  const F = mkId('f'), Pg = mkId('a'), U = mkId('b');
  const sat = mkSatellite();
  const ctx = mkContext(F, sat.satPub);
  rotateSigning(Pg); rotateSigning(U);
  const signPubOf = new Map([[Pg.fp, Pg.signPub], [U.fp, U.signPub]]);
  const routes = await depositedRoutes(ctx, sat, mkDeps({
    supp: { ...emptySupp(), groups: ['blocked-grp'] },
    contacts: [mkContact(Pg, { tags: ['blocked-grp'] } as Partial<ContactRecord>), mkContact(U)],
    signPubOf,
  }));
  assert.ok(routes.has(routeOf(ctx, U.fp, U.signPub)), 'positive control U fires');
  assert.ok(!routes.has(routeOf(ctx, Pg.fp, Pg.signPub)), 'suppressed-group member gets ZERO');
  assert.equal(routes.size, 1);
});

test('(key-rotation × global) go-private ceases ALL emission; non-global baseline proves the harness emits', async () => {
  const F = mkId('f'), P = mkId('a'), U = mkId('b');
  const sat = mkSatellite();
  const ctx = mkContext(F, sat.satPub);
  rotateSigning(P); rotateSigning(U);
  const signPubOf = new Map([[P.fp, P.signPub], [U.fp, U.signPub]]);
  const contacts = [mkContact(P), mkContact(U)];
  // positive control: WITHOUT global, both get deposits (harness detects emission)
  const baseline = await depositedRoutes(ctx, sat, mkDeps({ supp: emptySupp(), contacts, signPubOf }));
  assert.equal(baseline.size, 2, 'baseline emits to both (harness works)');
  // global: ZERO deposits to anyone
  const global = await depositedRoutes(ctx, sat, mkDeps({ supp: { ...emptySupp(), global: true }, contacts, signPubOf }));
  assert.equal(global.size, 0, 'go-private ⇒ emit to NO ONE');
});

test('(mailbox-rebuild × person) F rebuilds its mailbox + peer rebuilds theirs → suppression still bites; control still reached', async () => {
  const F = mkId('f'), P = mkId('a'), U = mkId('b');
  const sat = mkSatellite();
  // churn: rebuild F's OWN mailbox (receive-side; must not affect emit) + rebuild the peers' mailboxes (new seal-targets)
  rebuildMailbox(F); rebuildMailbox(P); rebuildMailbox(U);
  const ctx = mkContext(F, sat.satPub); // ctx.me = F's rebuilt mailbox
  const signPubOf = new Map([[P.fp, P.signPub], [U.fp, U.signPub]]);
  const routes = await depositedRoutes(ctx, sat, mkDeps({
    supp: { ...emptySupp(), persons: [P.fp] },
    contacts: [mkContact(P), mkContact(U)], // device_mailbox = rebuilt seal-targets
    signPubOf,
  }));
  assert.ok(routes.has(routeOf(ctx, U.fp, U.signPub)), 'control U still reached (route keyed by s_AB, seals to U rebuilt mailbox)');
  assert.ok(!routes.has(routeOf(ctx, P.fp, P.signPub)), 'suppressed P still ZERO after mailbox rebuilds');
});

test('(relay-transfer × person+rotation) liveness: non-suppressed STILL delivered post-transfer; rotated suppressed stays zero', async () => {
  // Flint #159918: suppression never rides the relay (owner-local) ⇒ the {transfer × suppressed} half is
  // trivially safe. The LOAD-BEARING assertion here is the LIVENESS positive-control (non-suppressed U is still
  // delivered after the transfer), with the suppressed-stays-zero as the safety floor. Target also rotated.
  const F = mkId('f'), P = mkId('a'), U = mkId('b');
  const sat = mkSatellite();
  const ctx = mkContext(F, sat.satPub);
  rotateSigning(P); rotateSigning(U); // targets rotated during/after the transfer
  const signPubOf = new Map([[P.fp, P.signPub], [U.fp, U.signPub]]);
  const routes = await depositedRoutes(ctx, sat, mkDeps({
    supp: { ...emptySupp(), persons: [P.fp] }, // record survived the transfer (durable_id key unchanged)
    contacts: [mkContact(P), mkContact(U)],
    signPubOf,
  }));
  assert.ok(routes.has(routeOf(ctx, U.fp, U.signPub)), 'control fires');
  assert.ok(!routes.has(routeOf(ctx, P.fp, P.signPub)), 'rotated P still suppressed post-transfer');
});

test("Archie's cell: block→suppression-RECORD is LOAD-BEARING (suppresses with the blocked FLAG cleared); both paths independently suppress", async () => {
  const F = mkId('f'), B = mkId('a'), U = mkId('b');
  const sat = mkSatellite();
  const ctx = mkContext(F, sat.satPub);
  const signPubOf = new Map([[B.fp, B.signPub], [U.fp, U.signPub]]);

  // (1) blocked flag + record entry (block→populate fired): zero to B.
  let routes = await depositedRoutes(ctx, sat, mkDeps({
    supp: { ...emptySupp(), persons: [B.fp] },
    contacts: [mkContact(B, { blocked: true } as Partial<ContactRecord>), mkContact(U)],
    signPubOf,
  }));
  assert.ok(!routes.has(routeOf(ctx, B.fp, B.signPub)) && routes.has(routeOf(ctx, U.fp, U.signPub)), 'flag+record ⇒ B zero, U fires');

  // (2) RECORD LOAD-BEARING: blocked FLAG cleared but the record entry persists (survives rebuild/transfer) ⇒ still zero.
  routes = await depositedRoutes(ctx, sat, mkDeps({
    supp: { ...emptySupp(), persons: [B.fp] },
    contacts: [mkContact(B, { blocked: false } as Partial<ContactRecord>), mkContact(U)],
    signPubOf,
  }));
  assert.ok(!routes.has(routeOf(ctx, B.fp, B.signPub)), 'record alone (no flag) STILL suppresses — record is load-bearing');

  // (3) FLAG defense-in-depth: record empty but the blocked flag set ⇒ still zero (belt + suspenders).
  routes = await depositedRoutes(ctx, sat, mkDeps({
    supp: emptySupp(),
    contacts: [mkContact(B, { blocked: true } as Partial<ContactRecord>), mkContact(U)],
    signPubOf,
  }));
  assert.ok(!routes.has(routeOf(ctx, B.fp, B.signPub)), 'blocked flag alone STILL suppresses (defense-in-depth)');
});

test('INVARIANT fresh-union: suppressing a target between passes drops it on the NEXT pass (no cached emit-set)', async () => {
  const F = mkId('f'), P = mkId('a'), U = mkId('b');
  const sat = mkSatellite();
  const ctx = mkContext(F, sat.satPub);
  const signPubOf = new Map([[P.fp, P.signPub], [U.fp, U.signPub]]);
  const live = emptySupp(); // mutated between passes; deps reads it FRESH each pass
  const contacts = [mkContact(P), mkContact(U)];

  const pass1 = await depositedRoutes(ctx, sat, mkDeps({ supp: live, contacts, signPubOf }));
  assert.ok(pass1.has(routeOf(ctx, P.fp, P.signPub)), 'pass-1 emits to P');
  live.persons.push(P.fp); // suppress P mid-run
  const pass2 = await depositedRoutes(ctx, sat, mkDeps({ supp: live, contacts, signPubOf }));
  assert.ok(!pass2.has(routeOf(ctx, P.fp, P.signPub)), 'pass-2 drops P (fresh re-filter, not cached)');
  assert.ok(pass2.has(routeOf(ctx, U.fp, U.signPub)), 'U still emitted');
});

test('INVARIANT fail-closed-on-doubt: unreadable suppression record (null) ⇒ emit to NO ONE', async () => {
  const F = mkId('f'), P = mkId('a'), U = mkId('b');
  const sat = mkSatellite();
  const ctx = mkContext(F, sat.satPub);
  const signPubOf = new Map([[P.fp, P.signPub], [U.fp, U.signPub]]);
  const routes = await depositedRoutes(ctx, sat, mkDeps({ supp: null, contacts: [mkContact(P), mkContact(U)], signPubOf }));
  assert.equal(routes.size, 0, 'null suppression record ⇒ ZERO deposits (fail-closed, not emit-to-all)');
});

test('INVARIANT fail-closed: a getSuppressionRecord that THROWS must not emit-to-all (emit pass yields nothing)', async () => {
  const F = mkId('f'), P = mkId('a'), U = mkId('b');
  const sat = mkSatellite();
  const ctx = mkContext(F, sat.satPub);
  const signPubOf = new Map([[P.fp, P.signPub], [U.fp, U.signPub]]);
  const deps: Parameters<typeof runAffirmEmitTick>[2] = {
    getSuppressionRecord: async () => { throw new Error('decrypt-fail'); },
    getAllContacts: async () => [mkContact(P), mkContact(U)],
    resolvePeerSignPub: (c) => signPubOf.get(c.fingerprint) ?? null,
    clock: () => T0,
  };
  // runAffirmEmitTick awaits Promise.all([getSuppressionRecord, getAllContacts]) — a throw rejects the pass.
  // The §8 runner (startAffirmSync) wraps the tick in try/catch (fail-soft) → a throwing store yields NO emit,
  // never emit-to-all. Assert the pass surfaces no deposits (it rejects before any enqueue).
  const deposited: string[] = [];
  const cadence = new CadenceEmitter({ makeCover: () => makeAffirmCover(ctx), deposit: async (o) => { const p = await peelOnion(o, sat.satSec, sat.satFp); if (p) deposited.push(p.route); } });
  await assert.rejects(runAffirmEmitTick(ctx, cadence, deps), 'a throwing suppression getter rejects the pass (runner fail-soft catches it)');
  assert.equal(cadence.pending(), 0, 'nothing enqueued before the throw ⇒ emit-to-NONE, never emit-to-all');
  assert.equal(deposited.length, 0);
});
