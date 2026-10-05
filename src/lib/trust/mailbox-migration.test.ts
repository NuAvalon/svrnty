// src/lib/trust/mailbox-migration.test.ts
// Same-relay mailbox rekey orchestrator (W4 day-1, KB#92332/#92342/#92346). DI'd + DARK: real crypto
// round-trips over an in-memory rendezvous, zero IndexedDB. Pins the 3 Flint-ruled fail-safe constants.
//   node --import tsx --test src/lib/trust/mailbox-migration.test.ts
import test from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { type TrustRelay } from './trust-rendezvous.js';
import { sealToMailbox, openMailboxEnvelope } from '../crypto/mailbox-envelope.js';
import {
  generateMailboxKeypair,
  mailboxFpOf,
  toPublicKeys,
  toSecretKeys,
  deserializeMailboxKeypair,
  type MailboxKeypair,
} from '../crypto/mailbox-keys.js';
import {
  publishMailboxPointer,
  resolveMailboxPointer,
  type PointerOpenCandidate,
} from './mailbox-pointer-transport.js';
import {
  migrateMailbox,
  nextMailboxEpoch,
  shouldRetireOverlap,
  type MigrateMailboxDeps,
  type MigrationFanoutTarget,
  type MailboxOverlapRecord,
} from './mailbox-migration.js';

// ── in-memory rendezvous relay (blobs keyed by R tag) — same shape as the transport test ──
function memRelay(): TrustRelay {
  const store = new Map<string, string[]>();
  return {
    async deposit(r, blob) {
      const a = store.get(r) ?? [];
      a.push(blob);
      store.set(r, a);
      return true;
    },
    async poll(r) {
      return store.get(r) ?? [];
    },
  };
}

// ── my identity (publisher) ──
const seedA = new Uint8Array(32).fill(0x41);
const pubA = ed25519.getPublicKey(seedA);
const DID_A = 'did:svrnty:aaaa';
const OWNER_A = 'owner-fp-aaaa';
const EPOCH_WK = 2900; // fixed rendezvous week epoch (pin determinism; avoid Date.now in currentEpochWeek)
const WINDOW_MS = 7 * 24 * 3600 * 1000;
const NOW_MS = 1_000_000;

// ── a peer: identity seed + Ed25519 pubkey + current mailbox (the rotation seal target) ──
function makePeer(fill: number, didSuffix: string) {
  const seed = new Uint8Array(32).fill(fill);
  const edPub = ed25519.getPublicKey(seed);
  const did = `did:svrnty:${didSuffix}`;
  const mailbox = generateMailboxKeypair();
  const target: MigrationFanoutTarget = {
    peerDid: did,
    peerEdPub: edPub,
    sealTarget: toPublicKeys(mailbox),
    sealTargetFp: mailboxFpOf(mailbox),
    contactFp: `fp-${didSuffix}`,
  };
  const candidates: PointerOpenCandidate[] = [{ secrets: toSecretKeys(mailbox), fp: mailboxFpOf(mailbox) }];
  // what this peer does to learn MY current mailbox from the relay
  const resolveMine = (relay: TrustRelay) =>
    resolveMailboxPointer({ relay, myEdPriv: seed, myDid: did, peerEdPub: pubA, peerDid: DID_A, openWith: candidates, now: EPOCH_WK });
  return { seed, edPub, did, mailbox, target, resolveMine };
}

// ── a fake, in-memory client-store for the injected deps (no IndexedDB) ──
function fakeStore(initialKp: MailboxKeypair | null, initialEpoch: number | null) {
  const s = {
    mailbox: initialKp,
    epoch: initialEpoch,
    overlap: null as MailboxOverlapRecord | null,
  };
  return {
    loadCurrentMailbox: async () => s.mailbox,
    storeNewMailbox: async (kp: MailboxKeypair) => { s.mailbox = kp; },
    loadEpoch: async () => s.epoch,
    saveEpoch: async (e: number) => { s.epoch = e; },
    saveOverlap: async (rec: MailboxOverlapRecord) => { s.overlap = rec; },
    _state: s,
  };
}

// pin the rendezvous week epoch so publish + resolve meet deterministically (real seal/sign still run)
const pinnedPublish: typeof publishMailboxPointer = (args) =>
  publishMailboxPointer({ ...args, rendezvousEpoch: EPOCH_WK });

function baseDeps(store: ReturnType<typeof fakeStore>, relay: TrustRelay, targets: MigrationFanoutTarget[], extra: Partial<MigrateMailboxDeps> = {}): MigrateMailboxDeps {
  return {
    relay,
    ownerFp: OWNER_A,
    myDid: DID_A,
    myEdPriv: seedA,
    loadCurrentMailbox: store.loadCurrentMailbox,
    storeNewMailbox: store.storeNewMailbox,
    loadEpoch: store.loadEpoch,
    saveEpoch: store.saveEpoch,
    saveOverlap: store.saveOverlap,
    listFanoutTargets: async () => targets,
    now: () => NOW_MS,
    windowMs: WINDOW_MS,
    publishPointer: pinnedPublish,
    ...extra,
  };
}

// ───────────────────────────────────────────────────────────────────────────────────────────────
// 1. END-TO-END: rekey fans the NEW mailbox to holders; a holder resolves it at the new epoch.
test('end-to-end: rekey → non-blocked holder resolves MY new mailbox at the bumped epoch', async () => {
  const relay = memRelay();
  const oldKp = generateMailboxKeypair();
  const store = fakeStore(oldKp, 4); // current epoch 4
  const B = makePeer(0x42, 'bbbb');
  const C = makePeer(0x43, 'cccc');

  const result = await migrateMailbox(baseDeps(store, relay, [B.target, C.target]));

  // epoch bumped monotonically; device_mailbox flipped to the new keypair
  assert.equal(result.epoch, 5);
  assert.equal(store._state.epoch, 5);
  assert.equal(result.oldMailboxFp, mailboxFpOf(oldKp));
  assert.notEqual(result.newMailboxFp, result.oldMailboxFp); // unlinkable: fresh keypair
  assert.equal(result.newMailboxFp, mailboxFpOf(store._state.mailbox!)); // store now holds the new kp
  assert.equal(result.blockedTripwireHits, 0);
  assert.equal(result.skippedNoSealTarget, 0);
  assert.deepEqual(result.fanned.map((f) => f.peerDid).sort(), [B.did, C.did].sort());
  assert.ok(result.fanned.every((f) => f.deposited));

  // the real proof: B resolves MY new mailbox over the blind rendezvous
  const gotB = await B.resolveMine(relay);
  assert.ok(gotB, 'B must resolve a pointer');
  assert.equal(gotB!.mailboxFp, result.newMailboxFp);
  assert.equal(gotB!.epoch, 5);
  assert.equal(bytesToHex(gotB!.x25519Pub), bytesToHex(store._state.mailbox!.x25519Pub));
  assert.equal(bytesToHex(gotB!.mlkem1024Ek), bytesToHex(store._state.mailbox!.mlkem1024Pub));

  // C resolves it independently (per-pair isolation; each learns only its own rendezvous blob)
  const gotC = await C.resolveMine(relay);
  assert.equal(gotC!.mailboxFp, result.newMailboxFp);
});

// 2a. FAIL-SAFE #1 — blocked-minus BY CONSTRUCTION: a correctly pre-filtered set never trips the guard.
test('fail-safe #1: blocked-minus by construction → tripwire reads 0', async () => {
  const relay = memRelay();
  const store = fakeStore(generateMailboxKeypair(), 0);
  const B = makePeer(0x42, 'bbbb');
  // isBlockedTripwire present but the set already excludes blocked → must never fire
  const result = await migrateMailbox(
    baseDeps(store, relay, [B.target], { isBlockedTripwire: () => false }),
  );
  assert.equal(result.blockedTripwireHits, 0);
  assert.equal(result.fanned.length, 1);
});

// 2b. FAIL-SAFE #1 — defense-in-depth: if upstream regresses and a BLOCKED peer slips into the set,
//     the new location is NEVER sealed to them (skip + count), and they cannot resolve it.
test('fail-safe #1: blocked peer in the set is SKIPPED — never sealed, cannot resolve the new mailbox', async () => {
  const relay = memRelay();
  const store = fakeStore(generateMailboxKeypair(), 7);
  const B = makePeer(0x42, 'bbbb'); // legit
  const D = makePeer(0x44, 'dddd'); // blocked (a survivor blocked them)
  const blocked = new Set([D.did]);

  const result = await migrateMailbox(
    baseDeps(store, relay, [B.target, D.target], {
      isBlockedTripwire: (t) => blocked.has(t.peerDid),
    }),
  );

  assert.equal(result.blockedTripwireHits, 1);
  assert.deepEqual(result.fanned.map((f) => f.peerDid), [B.did]); // only B got a pointer
  // D MUST NOT be able to learn the new location — nothing was sealed to D.
  const gotD = await D.resolveMine(relay);
  assert.equal(gotD, null, 'blocked peer must not resolve the new mailbox (anti-safety to leak it)');
  // B still works (no silent loss for the legit holder)
  const gotB = await B.resolveMine(relay);
  assert.equal(gotB!.mailboxFp, result.newMailboxFp);
});

// 3. FAIL-SAFE #2 — epoch monotonic + floor-on-recovery (pure predicate).
test('fail-safe #2: nextMailboxEpoch — monotonic bump, floor-on-recovery, fail-closed on wiped state', () => {
  assert.equal(nextMailboxEpoch(4), 5);
  assert.equal(nextMailboxEpoch(0), 1);
  assert.equal(nextMailboxEpoch(null, 10), 11); // recovery: floor above previously published
  assert.throws(() => nextMailboxEpoch(null), /wiped state/); // recovery w/o floor → refuse (silent-loss guard)
  assert.throws(() => nextMailboxEpoch(-1), /corrupt persisted epoch/);
  assert.throws(() => nextMailboxEpoch(3.5), /corrupt persisted epoch/);
  assert.throws(() => nextMailboxEpoch(null, -1), /invalid recoveryFloorEpoch/);
});

// 3b. FAIL-SAFE #2 — the orchestrator refuses to rekey from a wiped epoch state without a floor.
test('fail-safe #2: migrate on null epoch without recovery floor throws; with floor it publishes above it', async () => {
  const relay = memRelay();
  const B = makePeer(0x42, 'bbbb');

  const wiped = fakeStore(generateMailboxKeypair(), null);
  await assert.rejects(migrateMailbox(baseDeps(wiped, relay, [B.target])), /wiped state/);

  const recovered = fakeStore(generateMailboxKeypair(), null);
  const result = await migrateMailbox(baseDeps(recovered, relay, [B.target], { recoveryFloorEpoch: 42 }));
  assert.equal(result.epoch, 43);
  assert.equal((await B.resolveMine(relay))!.epoch, 43);
});

// 3c. FAIL-SAFE #2 — two sequential migrations bump strictly monotonically.
test('fail-safe #2: sequential rekeys bump the epoch strictly', async () => {
  const relay = memRelay();
  const store = fakeStore(generateMailboxKeypair(), 0);
  const B = makePeer(0x42, 'bbbb');
  const r1 = await migrateMailbox(baseDeps(store, relay, [B.target]));
  const r2 = await migrateMailbox(baseDeps(store, relay, [B.target]));
  assert.equal(r1.epoch, 1);
  assert.equal(r2.epoch, 2);
  assert.notEqual(r1.newMailboxFp, r2.newMailboxFp);
  // B resolves the LATEST (highest-epoch-wins across the two collided pointers)
  assert.equal((await B.resolveMine(relay))!.epoch, 2);
});

// 4. FAIL-SAFE #3 — overlap: old keypair is stashed BEFORE the flip, so in-flight mail to the OLD
//    mailbox still drains during the window.
test('fail-safe #3: old mailbox keypair survives the flip and in-flight mail to it still opens', async () => {
  const relay = memRelay();
  const oldKp = generateMailboxKeypair();
  const store = fakeStore(oldKp, 1);
  const B = makePeer(0x42, 'bbbb');

  const result = await migrateMailbox(baseDeps(store, relay, [B.target]));
  const overlap = store._state.overlap;
  assert.ok(overlap, 'overlap record must be persisted');
  assert.equal(overlap.oldMailboxFp, result.oldMailboxFp);
  assert.equal(overlap.newMailboxFp, result.newMailboxFp);
  assert.equal(overlap.openedAt, NOW_MS);
  assert.equal(overlap.expiresAt, NOW_MS + WINDOW_MS);
  assert.equal(result.overlapExpiresAt, NOW_MS + WINDOW_MS);

  // reconstruct the OLD secrets from the overlap record and prove a blob sealed to the old mailbox drains
  const recoveredOld = deserializeMailboxKeypair(overlap.oldKeypair);
  assert.equal(mailboxFpOf(recoveredOld), result.oldMailboxFp);
  const inflight = new Uint8Array([9, 8, 7, 6]);
  const sealed = await sealToMailbox(inflight, toPublicKeys(recoveredOld), result.oldMailboxFp);
  const opened = await openMailboxEnvelope(sealed, toSecretKeys(recoveredOld), result.oldMailboxFp);
  assert.ok(opened, 'in-flight mail to the old mailbox must still open during overlap');
  assert.equal(bytesToHex(opened!), bytesToHex(inflight));
});

// 4b. FAIL-SAFE #3 — retirement predicate: time-bounded MAX + confirm-based early-close, never early on time.
test('fail-safe #3: shouldRetireOverlap — time MAX, early-close on full ack, never early otherwise', () => {
  const holders = ['did:svrnty:bbbb', 'did:svrnty:cccc'];
  const expiresAt = NOW_MS + WINDOW_MS;
  // before expiry, no acks → hold (do NOT drop in-flight)
  assert.equal(shouldRetireOverlap({ expiresAt, ackedPeerDids: [] }, holders, NOW_MS), false);
  // partial ack before expiry → hold
  assert.equal(shouldRetireOverlap({ expiresAt, ackedPeerDids: ['did:svrnty:bbbb'] }, holders, NOW_MS), false);
  // time MAX reached → retire
  assert.equal(shouldRetireOverlap({ expiresAt, ackedPeerDids: [] }, holders, expiresAt), true);
  assert.equal(shouldRetireOverlap({ expiresAt, ackedPeerDids: [] }, holders, expiresAt + 1), true);
  // full ack before expiry → early-close (DORMANT path, but logic pinned)
  assert.equal(shouldRetireOverlap({ expiresAt, ackedPeerDids: holders.slice() }, holders, NOW_MS), true);
  // zero holders, before expiry → conservatively hold for time (no early-close on an empty set)
  assert.equal(shouldRetireOverlap({ expiresAt, ackedPeerDids: [] }, [], NOW_MS), false);
});

// 5. FAIL-CLOSED — no current mailbox to rotate.
test('fail-closed: migrate with no current device mailbox throws', async () => {
  const relay = memRelay();
  const store = fakeStore(null, 0);
  const B = makePeer(0x42, 'bbbb');
  await assert.rejects(migrateMailbox(baseDeps(store, relay, [B.target])), /no current device mailbox/);
});

// 6. FAIL-CLOSED — a holder with no current seal target is skipped (under-reveal), never sealed to nothing.
test('fail-closed: holder missing a seal target is skipped, not sealed', async () => {
  const relay = memRelay();
  const store = fakeStore(generateMailboxKeypair(), 2);
  const B = makePeer(0x42, 'bbbb');
  const noTarget: MigrationFanoutTarget = { ...makePeer(0x45, 'eeee').target, sealTargetFp: '' };

  const result = await migrateMailbox(baseDeps(store, relay, [B.target, noTarget]));
  assert.equal(result.skippedNoSealTarget, 1);
  assert.deepEqual(result.fanned.map((f) => f.peerDid), [B.did]);
});
