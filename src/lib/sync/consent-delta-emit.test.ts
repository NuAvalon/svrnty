// src/lib/sync/consent-delta-emit.test.ts
// ADVERSARIAL refutation gate for the consent-delta EMIT-PATH (the wiring consent-delta.ts §6 /
// uniform-frame.ts explicitly deferred: "C's toggle → fan-out → the peer's owner-local apply").
// Each security-relevant test refutes a PROTECT-THE-PERSON property — "an adversary/caller who [X]
// CANNOT [Y]" — WITH a positive control alongside it (a path that DOES succeed), so a test that silently
// stopped testing anything would be caught by its own sibling failing to pass.
// Run: npx tsx --test src/lib/sync/consent-delta-emit.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ed25519 } from '@noble/curves/ed25519.js';
import { generateMailboxKeypair, toPublicKeys, toSecretKeys, mailboxFpOf } from '../crypto/mailbox-keys.js';
import { peelOnion, openOnionInner } from '../crypto/onion-envelope.js';
import { unframeUniform } from '../crypto/uniform-frame.js';
import {
  buildConsentDelta,
  CONSENT_GO_PRIVATE,
  CONSENT_SCOPE_CHANGE,
} from '../crypto/consent-delta.js';
import {
  emitConsentDelta,
  applyInboundConsentDelta,
  nudgeResyncNow,
  type ApplyConsentDeltaDeps,
  type EmitPeerTarget,
} from './consent-delta-emit.js';

const enc = new TextEncoder();
const fill = (byte: number, n: number) => new Uint8Array(n).fill(byte);

// C = the consent-changer (signer/emitter). P = the recipient peer (device applying the inbound delta).
const cSeed = fill(0xc0, 32);
const cSignPub = ed25519.getPublicKey(cSeed);
const pFingerprintHex = 'ab'.repeat(32); // P's own stable identity fp (hex) — becomes recipientBinding
const cFingerprintInPBook = 'cd'.repeat(32); // how P's LOCAL BOOK identifies C — a different axis entirely

/** A fresh {applyMutualResult} stub that records every call — the ONLY side-effect surface this module
 *  is allowed to touch (invariant 4: no durable state introduced in this module itself). */
function recordingDeps(): ApplyConsentDeltaDeps & { calls: Array<[string, 'know' | 'trust', string[]]> } {
  const calls: Array<[string, 'know' | 'trust', string[]]> = [];
  return {
    calls,
    applyMutualResult: async (peerFingerprint, layer, disclosed) => {
      calls.push([peerFingerprint, layer, disclosed]);
    },
  };
}

function onePeer(overrides: Partial<EmitPeerTarget> = {}) {
  const device = generateMailboxKeypair();
  const target: EmitPeerTarget = {
    fingerprint: pFingerprintHex,
    deviceMailbox: toPublicKeys(device),
    epoch: 1,
    ...overrides,
  };
  return { device, target };
}

// ── sanity: emit → deposit shape ────────────────────────────────────────────────────────────────────
test('sanity: emitConsentDelta produces one sealed deposit per peer, no skips on good input', async () => {
  const satellite = generateMailboxKeypair();
  const { target } = onePeer();
  const result = await emitConsentDelta({
    withdrawal: { kind: 'go-private' },
    peers: [target],
    signerSeed: cSeed,
    satellite: toPublicKeys(satellite),
  });
  assert.equal(result.skipped.length, 0);
  assert.equal(result.deposits.length, 1);
  assert.equal(result.deposits[0].fingerprint, pFingerprintHex);
  assert.equal(result.deposits[0].cell.v, 1, 'a well-formed MailboxEnvelopePackage was returned');
});

// ════════════════════════════════════════════════════════════════════════
// (BLOCK MUST NEVER EMIT) — a caller who passes a BLOCK withdrawal CANNOT get a consent-delta out: the
// disappearance itself would be a signal to the blocked party (silence leak). Positive control: the
// SAME peer/args with 'unfriend' DOES emit — proving the guard is BLOCK-specific, not a general failure.
// ════════════════════════════════════════════════════════════════════════
test('(HARD GUARD) a BLOCK withdrawal refuses to emit; the identical input with unfriend DOES emit', async () => {
  const satellite = generateMailboxKeypair();
  const { target } = onePeer();

  await assert.rejects(
    () =>
      emitConsentDelta({
        withdrawal: { kind: 'block' },
        peers: [target],
        signerSeed: cSeed,
        satellite: toPublicKeys(satellite),
      }),
    /refus/i,
    'BLOCK must throw, never silently return an empty result',
  );

  // Positive control — same peer, same satellite, only the kind differs.
  const control = await emitConsentDelta({
    withdrawal: { kind: 'unfriend' },
    peers: [target],
    signerSeed: cSeed,
    satellite: toPublicKeys(satellite),
  });
  assert.equal(control.deposits.length, 1, 'unfriend (not block) legitimately emits — the guard is targeted');
});

// ── fail-closed per-recipient: one bad peer is skipped + reported, the batch is not aborted ───────────
test('robustness: a bad fingerprint / bad epoch is skipped+reported; a good peer in the same batch still gets a deposit', async () => {
  const satellite = generateMailboxKeypair();
  const { target: goodPeer } = onePeer({ fingerprint: pFingerprintHex });
  const badFpPeer = onePeer({ fingerprint: '' }).target;
  const badEpochPeer = onePeer({ fingerprint: 'ef'.repeat(32), epoch: -1 }).target;

  const result = await emitConsentDelta({
    withdrawal: { kind: 'unfriend' },
    peers: [goodPeer, badFpPeer, badEpochPeer],
    signerSeed: cSeed,
    satellite: toPublicKeys(satellite),
  });

  assert.equal(result.deposits.length, 1, 'only the good peer produced a deposit');
  assert.equal(result.deposits[0].fingerprint, pFingerprintHex);
  assert.equal(result.skipped.length, 2);
  assert.ok(result.skipped.some((s) => s.reason === 'bad-fingerprint'));
  assert.ok(result.skipped.some((s) => s.reason === 'bad-epoch'));
});

// ════════════════════════════════════════════════════════════════════════
// (ANTI-ROLLBACK through the wrapper) — a replayed/stale-epoch inbound delta CANNOT re-trigger apply once
// a later epoch has been accepted; a genuine LATER epoch (positive control) DOES apply. This exercises the
// §6a monotonic check THROUGH applyInboundConsentDelta, not just the raw primitive (already proven in
// consent-delta.test.ts) — so a regression in the wrapper's plumbing would be caught here too.
// ════════════════════════════════════════════════════════════════════════
test('(ANTI-ROLLBACK) a stale-epoch delta does not re-apply after a later epoch was accepted; a newer one does', async () => {
  const deps = recordingDeps();
  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));

  const epoch5 = buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: 5, scope: enc.encode('all') }, cSeed, recipientBinding);
  const first = await applyInboundConsentDelta(
    epoch5,
    cSignPub,
    { recipientBinding, lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook },
    deps,
  );
  assert.deepEqual(first, { kind: 'applied', typ: CONSENT_GO_PRIVATE, epoch: 5 });
  assert.equal(deps.calls.length, 1);
  assert.deepEqual(deps.calls[0], [cFingerprintInPBook, 'know', []]);

  // A replay of an OLDER epoch, verified against lastSeenEpoch now at 5 — must be rejected, no 2nd apply.
  const staleEpoch3 = buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: 3, scope: enc.encode('all') }, cSeed, recipientBinding);
  const replay = await applyInboundConsentDelta(
    staleEpoch3,
    cSignPub,
    { recipientBinding, lastSeenEpoch: 5, peerFingerprint: cFingerprintInPBook },
    deps,
  );
  assert.equal(replay, null, 'a stale/replayed epoch must not re-trigger removal');
  assert.equal(deps.calls.length, 1, 'no second sink call from the replay');

  // Positive control: a genuine LATER epoch is accepted (liveness preserved).
  const epoch8 = buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: 8, scope: enc.encode('all') }, cSeed, recipientBinding);
  const later = await applyInboundConsentDelta(
    epoch8,
    cSignPub,
    { recipientBinding, lastSeenEpoch: 5, peerFingerprint: cFingerprintInPBook },
    deps,
  );
  assert.deepEqual(later, { kind: 'applied', typ: CONSENT_GO_PRIVATE, epoch: 8 });
  assert.equal(deps.calls.length, 2);
});

// ════════════════════════════════════════════════════════════════════════
// (UNFORGEABILITY through the wrapper) — a delta NOT signed by the claimed C CANNOT trigger removal.
// Positive control: the genuine signer's delta DOES trigger it.
// ════════════════════════════════════════════════════════════════════════
test('(UNFORGEABILITY) a delta verified against the WRONG signer key never reaches the sink', async () => {
  const deps = recordingDeps();
  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const payload = buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: 1, scope: enc.encode('all') }, cSeed, recipientBinding);
  const wrongPub = ed25519.getPublicKey(fill(0xee, 32));

  const forged = await applyInboundConsentDelta(
    payload,
    wrongPub,
    { recipientBinding, lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook },
    deps,
  );
  assert.equal(forged, null);
  assert.equal(deps.calls.length, 0, 'an unforgeable signature check means the sink is never invoked');

  const genuine = await applyInboundConsentDelta(
    payload,
    cSignPub,
    { recipientBinding, lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook },
    deps,
  );
  assert.equal(genuine?.kind, 'applied');
  assert.equal(deps.calls.length, 1);
});

// ── null-not-throw: hostile/malformed wire bytes never throw, always resolve to null ───────────────────
test('robustness: applyInboundConsentDelta returns null (never throws) on malformed/hostile input', async () => {
  const deps = recordingDeps();
  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const wellFormed = buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: 1, scope: enc.encode('all') }, cSeed, recipientBinding);

  const cases: Array<[string, () => Promise<unknown>]> = [
    ['empty payload', () => applyInboundConsentDelta(new Uint8Array(0), cSignPub, { recipientBinding, lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook }, deps)],
    ['truncated payload', () => applyInboundConsentDelta(wellFormed.subarray(0, 5), cSignPub, { recipientBinding, lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook }, deps)],
    ['garbage bytes', () => applyInboundConsentDelta(crypto.getRandomValues(new Uint8Array(140)), cSignPub, { recipientBinding, lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook }, deps)],
    ['bad signer pubkey length', () => applyInboundConsentDelta(wellFormed, new Uint8Array(3), { recipientBinding, lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook }, deps)],
    ['empty recipientBinding', () => applyInboundConsentDelta(wellFormed, cSignPub, { recipientBinding: new Uint8Array(0), lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook }, deps)],
    ['garbage opts object', () => applyInboundConsentDelta(wellFormed, cSignPub, {} as never, deps)],
  ];

  for (const [label, run] of cases) {
    await assert.doesNotReject(run, `${label} must resolve, not throw`);
    const outcome = await run();
    assert.equal(outcome, null, `${label} → null`);
  }
  assert.equal(deps.calls.length, 0, 'none of the hostile inputs ever reached the sink');

  // Positive control: the function CAN return non-null for well-formed input (the nulls above are real).
  const ok = await applyInboundConsentDelta(wellFormed, cSignPub, { recipientBinding, lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook }, deps);
  assert.equal(ok?.kind, 'applied');
});

// ── policy scope: a verified-but-unimplemented typ is surfaced distinctly, and never touches the sink ──
test('a verified CONSENT_SCOPE_CHANGE is reported verified-unhandled and does NOT call the sink (policy deferred)', async () => {
  const deps = recordingDeps();
  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const scopeChange = buildConsentDelta({ typ: CONSENT_SCOPE_CHANGE, epoch: 1, scope: enc.encode('circle-x') }, cSeed, recipientBinding);

  const outcome = await applyInboundConsentDelta(
    scopeChange,
    cSignPub,
    { recipientBinding, lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook },
    deps,
  );
  assert.deepEqual(outcome, { kind: 'verified-unhandled', typ: CONSENT_SCOPE_CHANGE, epoch: 1 });
  assert.equal(deps.calls.length, 0, 'an unimplemented-policy typ must never silently trigger removal');
});

// ── sink rejection surfaces as apply-failed, never an uncaught throw (mutual-trust-sync.ts:469-471 contract) ──
test('a sink that rejects an unknown peer surfaces as apply-failed, not a thrown error', async () => {
  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const payload = buildConsentDelta({ typ: CONSENT_GO_PRIVATE, epoch: 1, scope: enc.encode('all') }, cSeed, recipientBinding);
  const deps: ApplyConsentDeltaDeps = {
    applyMutualResult: async () => {
      throw new Error('applyMutualResult: peer not in book — fail-closed');
    },
  };

  const outcome = await applyInboundConsentDelta(
    payload,
    cSignPub,
    { recipientBinding, lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook },
    deps,
  );
  assert.deepEqual(outcome, { kind: 'apply-failed', typ: CONSENT_GO_PRIVATE, epoch: 1 });
});

// ── content-free nudge: fires the EXISTING burst() shape; null-safe when nothing is wired ──────────────
test('nudgeResyncNow fires burst() when wired, and is a safe no-op (false) when absent/malformed', () => {
  let firedWith: number | undefined = -1;
  const nudge = { burst: (ms?: number) => { firedWith = ms; } };
  assert.equal(nudgeResyncNow(nudge, 500), true);
  assert.equal(firedWith, 500);

  assert.equal(nudgeResyncNow(undefined), false);
  assert.equal(nudgeResyncNow(null), false);
  assert.equal(nudgeResyncNow({} as never), false, 'a malformed nudge (no burst fn) must not throw');
});

// ════════════════════════════════════════════════════════════════════════
// (DELIVERY / relay-blind, end-to-end through THIS module's wiring) — emitConsentDelta's own sealed cell
// survives peel→open→unframe→apply, and the satellite peel reveals no consent semantics. This is the
// SAME property consent-delta.test.ts proves for the raw primitive, re-proven here for the actual
// emit-path output (a regression in frameUniform/sealToMailbox/sealOnion wiring order would be caught).
// ════════════════════════════════════════════════════════════════════════
test('(DELIVERY) emitConsentDelta → satellite peel (blind) → device open → applyInboundConsentDelta clears disclosed_circle', async () => {
  const device = generateMailboxKeypair();
  const satellite = generateMailboxKeypair();
  const deps = recordingDeps();

  const emitResult = await emitConsentDelta({
    withdrawal: { kind: 'go-private' },
    peers: [{ fingerprint: pFingerprintHex, deviceMailbox: toPublicKeys(device), epoch: 2, route: 'r-test' }],
    signerSeed: cSeed,
    satellite: toPublicKeys(satellite),
  });
  assert.equal(emitResult.deposits.length, 1);
  const outer = emitResult.deposits[0].cell;

  // Satellite peels routing but must not learn a stable recipient id (K0-1) nor the consent semantics.
  const peeled = await peelOnion(outer, toSecretKeys(satellite), mailboxFpOf(satellite));
  assert.ok(peeled, 'satellite peels the outer');
  assert.equal(peeled.route, 'r-test');
  assert.ok(!('mailbox_fp' in peeled.inner), 'no stable recipient id rides the peel (K0-1 blinding holds)');

  // Only the device opens + unframes + verifies + applies.
  const openedCell = await openOnionInner(peeled.inner, toSecretKeys(device), mailboxFpOf(device));
  assert.ok(openedCell, 'device opens the inner cell');
  const un = unframeUniform(openedCell);
  assert.ok(un && un.type === 'consent-delta', 'device unframes a consent-delta cell (type hidden from the satellite)');

  const recipientBinding = Uint8Array.from(Buffer.from(pFingerprintHex, 'hex'));
  const outcome = await applyInboundConsentDelta(
    un!.payload,
    cSignPub,
    { recipientBinding, lastSeenEpoch: -1, peerFingerprint: cFingerprintInPBook },
    deps,
  );
  assert.deepEqual(outcome, { kind: 'applied', typ: CONSENT_GO_PRIVATE, epoch: 2 });
  assert.deepEqual(deps.calls, [[cFingerprintInPBook, 'know', []]], 'disclosed_circle clear reaches the sink exactly once');
});
