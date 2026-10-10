// src/lib/trust/relay-migration.test.ts
// Proves migrateRelay against Flint's 5 security-review criteria (#169327). Run:
//   npx tsx --test src/lib/trust/relay-migration.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  migrateRelay,
  type MigratePeer,
  type MigrateProgress,
  type MigrateRelayDeps,
  type PeerSealTarget,
  type NewMailboxAdvert,
} from './relay-migration.js';

const NEW_MAILBOX: NewMailboxAdvert = { x25519Pub: new Uint8Array(32).fill(7), mlkemEk: new Uint8Array(1568).fill(9) };

function peer(fp: string): MigratePeer {
  return { fingerprint: fp, edPub: new Uint8Array(32).fill(fp.charCodeAt(0)), did: `did:key:${fp}` };
}
// per-peer seal target (distinct by fp so we can assert each pointer is sealed to ITS OWN peer [F2])
function sealFor(p: MigratePeer): PeerSealTarget {
  return {
    sealTarget: { x25519Pub: new Uint8Array(32).fill(p.fingerprint.charCodeAt(0)), mlkemEk: new Uint8Array(1568).fill(1) } as any,
    sealTargetFp: `mbx-${p.fingerprint}`,
  };
}

/** A mock deps harness with spies + an injectable "this peer fails to resolve/deposit". */
function harness(peers: MigratePeer[], opts: { unresolvable?: Set<string>; depositFails?: Set<string> } = {}) {
  const published: Array<{ fp: string; sealTargetFp: string; epoch: number }> = [];
  const progressMap = new Map<number, MigrateProgress>(); // epoch -> persisted progress (the durable sink)
  const deps: MigrateRelayDeps = {
    enumerateTrustedPeers: async () => peers,
    registerNewMailbox: async () => NEW_MAILBOX,
    resolvePeerSealTarget: async (p) => (opts.unresolvable?.has(p.fingerprint) ? null : sealFor(p)),
    publishPointer: async ({ peer, sealTarget, newMailbox, pointerEpoch }) => {
      if (opts.depositFails?.has(peer.fingerprint)) return false;
      assert.equal(newMailbox, NEW_MAILBOX, 'pointer advertises MY new mailbox');
      // [F2] the pointer MUST be sealed to THIS peer's own mailbox
      assert.equal(sealTarget.sealTargetFp, `mbx-${peer.fingerprint}`, `[F2] sealed to ${peer.fingerprint}'s own mailbox`);
      published.push({ fp: peer.fingerprint, sealTargetFp: sealTarget.sealTargetFp, epoch: pointerEpoch });
      return true;
    },
    // durable sink: loadProgress returns a prior-persisted copy; saveProgress deep-copies (so the live
    // array in the orchestrator isn't what's "persisted" — a real crash would only have the saved copy).
    loadProgress: async (epoch) => {
      const p = progressMap.get(epoch);
      return p ? { ...p, pointeredFps: [...p.pointeredFps] } : null;
    },
    saveProgress: async (p) => {
      progressMap.set(p.pointerEpoch, { ...p, pointeredFps: [...p.pointeredFps] });
    },
  };
  return { deps, published, progressMap };
}

test('[F1][F2][F4] all peers enumerated, each sealed to its own mailbox, at epoch+1', async () => {
  const peers = [peer('alice'), peer('bob'), peer('carol')];
  const { deps, published } = harness(peers);
  const r = await migrateRelay(deps, { pointerEpoch: 3, overlapWindowMs: 1000, now: () => 1_000_000 });
  assert.equal(r.totalPeers, 3);
  assert.deepEqual([...r.pointeredFps].sort(), ['alice', 'bob', 'carol']); // [F1] no peer left behind
  assert.equal(r.failedFps.length, 0);
  assert.equal(r.complete, true);
  assert.equal(published.length, 3);
  assert.ok(published.every((p) => p.epoch === 3), '[F4] every pointer at the given epoch');
  assert.ok(published.every((p) => p.sealTargetFp === `mbx-${p.fp}`), '[F2] each sealed to its own peer');
});

test('[F1] an unresolvable peer is RECORDED as failed, never silently skipped → migration incomplete', async () => {
  const peers = [peer('alice'), peer('bob'), peer('carol')];
  const { deps } = harness(peers, { unresolvable: new Set(['bob']) });
  const r = await migrateRelay(deps, { pointerEpoch: 1, overlapWindowMs: 0, now: () => 5 });
  assert.deepEqual(r.failedFps, ['bob']); // recorded
  assert.deepEqual([...r.pointeredFps].sort(), ['alice', 'carol']);
  assert.equal(r.complete, false, '[F1] incomplete while any peer is un-pointered');
  assert.equal(r.safeToRetire, false, '[F5] never retire the old mailbox while incomplete');
});

test('[F3] idempotent + RESUMABLE: crash mid-migrate → re-run completes, no dup, no epoch reuse', async () => {
  const peers = [peer('alice'), peer('bob'), peer('carol')];
  // Run 1: carol's deposit FAILS (simulated crash/transient before carol is recorded).
  const h = harness(peers, { depositFails: new Set(['carol']) });
  const r1 = await migrateRelay(h.deps, { pointerEpoch: 2, overlapWindowMs: 10, now: () => 100 });
  assert.deepEqual([...r1.pointeredFps].sort(), ['alice', 'bob']);
  assert.deepEqual(r1.failedFps, ['carol']);
  assert.equal(r1.complete, false);
  assert.equal(h.published.length, 2); // alice, bob published once

  // Run 2: SAME epoch, carol now deposits fine. loadProgress returns alice/bob → they are NOT re-published.
  const depositFails = new Set<string>(); // carol recovers
  h.deps.publishPointer = (async ({ peer: p, sealTarget, newMailbox, pointerEpoch }) => {
    if (depositFails.has(p.fingerprint)) return false;
    assert.equal(sealTarget.sealTargetFp, `mbx-${p.fingerprint}`);
    h.published.push({ fp: p.fingerprint, sealTargetFp: sealTarget.sealTargetFp, epoch: pointerEpoch });
    return true;
  }) as MigrateRelayDeps['publishPointer'];
  const r2 = await migrateRelay(h.deps, { pointerEpoch: 2, overlapWindowMs: 10, now: () => 200 });
  assert.equal(r2.complete, true, 'resume completes');
  assert.deepEqual([...r2.pointeredFps].sort(), ['alice', 'bob', 'carol']);
  // [F3] alice/bob NOT re-published in run 2 (idempotent); only carol published → total 3, not 5.
  const published2 = h.published.filter((p) => p.epoch === 2);
  assert.equal(published2.length, 3, 'alice+bob (run1) + carol (run2) = 3; no re-publish of done peers');
  assert.equal(published2.filter((p) => p.fp === 'alice').length, 1, '[F3] alice published exactly once');
  assert.equal(published2.filter((p) => p.fp === 'carol').length, 1);
});

test('[F4] a non-advancing epoch (< 1) is rejected — no rollback via a stale epoch', async () => {
  const { deps } = harness([peer('alice')]);
  await assert.rejects(() => migrateRelay(deps, { pointerEpoch: 0, now: () => 1 }), /pointerEpoch must be an integer >= 1/);
  await assert.rejects(() => migrateRelay(deps, { pointerEpoch: -2, now: () => 1 }), /pointerEpoch must be/);
});

test('[F5] overlap: safeToRetire only when complete AND past the window; clamped to <= 30d', async () => {
  const peers = [peer('alice'), peer('bob')];
  // window-start run: now < overlapUntil → not safe to retire yet (old mailbox keeps decapsulating)
  const h1 = harness(peers);
  const start = await migrateRelay(h1.deps, { pointerEpoch: 1, overlapWindowMs: 7 * 24 * 3600 * 1000, now: () => 1000 });
  assert.equal(start.complete, true);
  assert.equal(start.overlapUntil, 1000 + 7 * 24 * 3600 * 1000);
  assert.equal(start.safeToRetire, false, '[F5] in-window → old mailbox stays live (no in-flight loss)');

  // started earlier (@100 → overlapUntil=110), then a later re-run past the window → safe to retire.
  // Also proves [F3]/[F5] the window is ANCHORED to the persisted start, not recomputed from now().
  const h2 = harness(peers);
  await migrateRelay(h2.deps, { pointerEpoch: 1, overlapWindowMs: 10, now: () => 100 });
  const late = await migrateRelay(h2.deps, { pointerEpoch: 1, overlapWindowMs: 10, now: () => 999_999 });
  assert.equal(late.overlapUntil, 110, 'overlap anchored to the persisted start (100+10), not now()');
  assert.equal(late.safeToRetire, true, 'complete + past-window → retire the old mailbox');

  // over-long overlap is clamped to the 30d msg-TTL (beyond it old mail is GC'd → no benefit)
  const h3 = harness(peers);
  const clamped = await migrateRelay(h3.deps, { pointerEpoch: 1, overlapWindowMs: 999 * 24 * 3600 * 1000, now: () => 0 });
  assert.equal(clamped.overlapUntil, 30 * 24 * 3600 * 1000, 'overlap clamped to 30d');
});
